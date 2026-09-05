// Package fuzz implements the "jwtop crack --fuzz" claim-mutation check: it
// complements the fixed exploit checks in jwt/crack/checks/ by mutating
// every claim in the token (type confusion, oversized strings, special
// characters, null) and comparing each response against a captured
// reference response, flagging any that diverge (5xx status, a leaked
// stack trace, or a body length far from the reference).
package fuzz

import (
	"context"
	_ "embed"
	"fmt"
	"strings"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/checkdef"
	"github.com/cerberauth/harnessx/probe"
	jwtop "github.com/cerberauth/jwtop/jwt"
	"github.com/cerberauth/jwtop/jwt/crack/checkbase"
	jwtfuzz "github.com/cerberauth/jwtop/jwt/fuzz"
)

//go:embed check.yaml
var checkYAML []byte

var Def = checkdef.MustParseCheckDefYAML("fuzz", checkYAML)

// maxFindings caps how many divergent mutations are listed in Extra, so a
// badly broken target doesn't blow up the report with hundreds of lines.
const maxFindings = 10

// send builds and sends the probe request for token, returning its status
// code and body.
func send(ctx context.Context, pctx *checkbase.ProbeCtx, target harnessx.Target, token string) (status int, body []byte, err error) {
	req, err := checkbase.NewTokenRequest(ctx, target.URL, token, pctx.TokenLocation)
	if err != nil {
		return 0, nil, err
	}
	status, _, body, _, err = probe.Do(ctx, pctx.Probe.Client(), req)
	return status, body, err
}

var Check = checkdef.NewCheck(Def,
	func(ctx context.Context, target harnessx.Target, _ harnessx.ResultStore) (harnessx.Result, error) {
		pctx := target.Data.(*checkbase.ProbeCtx)

		decoded, err := jwtop.Decode(pctx.TokenString)
		if err != nil {
			r := harnessx.DataResult(checkbase.ProbeResult{Err: err})
			r.Err = err
			return r, nil
		}

		// Reference response: the original, unmutated token. Every
		// mutation's response is compared against this rather than the
		// global invalid-token baseline, since fuzzing is looking for
		// deviations from normal behavior, not from a rejected token.
		_, refBody, err := send(ctx, pctx, target, pctx.TokenString)
		if err != nil {
			return harnessx.Result{}, err
		}

		mutations := jwtfuzz.GenerateClaimMutations(decoded.Claims, pctx.FuzzMaxStringLen)

		// When the HMAC secret was cracked by the weak_secret check (which
		// this check depends on), mutated tokens are re-signed with it
		// instead of just dropping the signature: servers that verify the
		// signature correctly — as real APIs generally do — never reach
		// the vulnerable claim-handling code otherwise.
		signWithSecret := pctx.IsHMAC && pctx.CrackedHMACSecret != ""

		var findings []string
		attempted := 0
		for _, cm := range mutations {
			if err := ctx.Err(); err != nil {
				return harnessx.Result{}, err
			}

			var token string
			var err error
			if signWithSecret {
				token, err = jwtfuzz.MutateAndSignToken(pctx.TokenString, cm.Claim, cm.Mutation.Value, []byte(pctx.CrackedHMACSecret))
			} else {
				token, err = jwtfuzz.MutateToken(pctx.TokenString, cm.Claim, cm.Mutation.Value)
			}
			if err != nil {
				continue
			}
			status, body, err := send(ctx, pctx, target, token)
			if err != nil {
				continue
			}
			attempted++

			div := jwtfuzz.Detect(status, body, len(refBody))
			if div.Any() && len(findings) < maxFindings {
				findings = append(findings, fmt.Sprintf("%s=%s/%s (status %d: %s)", cm.Claim, cm.Mutation.Category, cm.Mutation.Name, status, div.String()))
			}
		}

		if len(findings) == 0 {
			return harnessx.DataResult(checkbase.ProbeResult{
				Payload: fmt.Sprintf("%d mutations tried", attempted),
			}), nil
		}

		return harnessx.DataResult(checkbase.ProbeResult{
			Vulnerable: true,
			Payload:    fmt.Sprintf("%d mutations tried", attempted),
			Extra:      fmt.Sprintf("%d/%d mutations diverged from baseline: %s", len(findings), attempted, strings.Join(findings, "; ")),
		}), nil
	},
	checkdef.WithSkip(harnessx.SkipWhen(func(_ context.Context, target harnessx.Target, _ harnessx.ResultStore) string {
		pctx := target.Data.(*checkbase.ProbeCtx)
		if pctx.Offline {
			return "requires live server"
		}
		if !pctx.FuzzEnabled {
			return "use --fuzz to enable claim mutation fuzzing"
		}
		return ""
	})),
)
