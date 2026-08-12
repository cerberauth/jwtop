package baseline

import (
	"context"
	_ "embed"
	"strings"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/checkdef"
	"github.com/cerberauth/jwtop/jwt/crack/checkbase"
	"github.com/cerberauth/jwtop/jwt/editor"
	"github.com/cerberauth/jwtop/jwt/exploit"
)

//go:embed check.yaml
var checkYAML []byte

var Def = checkdef.MustParseCheckDefYAML("baseline", checkYAML)

func isAsymmetricAlg(alg string) bool {
	switch alg {
	case "RS256", "RS384", "RS512",
		"ES256", "ES384", "ES512",
		"PS256", "PS384", "PS512":
		return true
	}
	return false
}

// capture is the baseline check's GlobalCapture: it sends the invalid-token
// probe (or returns the fixed ExpectedStatus / a zero Snapshot offline).
func capture(ctx context.Context, target harnessx.Target, _ harnessx.ResultStore) (harnessx.Snapshot, error) {
	pctx := target.Data.(*checkbase.ProbeCtx)
	if pctx.Offline {
		return harnessx.Snapshot{}, nil
	}

	status := pctx.ExpectedStatus
	if status == 0 {
		req, err := checkbase.NewTokenRequest(ctx, target.URL, pctx.InvalidToken, pctx.TokenLocation)
		if err != nil {
			return harnessx.Snapshot{}, err
		}
		resp, err := pctx.Probe.Client().Do(req)
		if err != nil {
			return harnessx.Snapshot{}, err
		}
		resp.Body.Close()
		status = resp.StatusCode
	}
	return harnessx.Snapshot{StatusCode: status}, nil
}

var Check = func() harnessx.Check {
	baselineCapture := harnessx.CaptureGlobalBaselineCheck(harnessx.CheckID(Def.ID), Def.Name, capture)

	return checkdef.NewCheck(Def, func(ctx context.Context, target harnessx.Target, store harnessx.ResultStore) (harnessx.Result, error) {
		pctx := target.Data.(*checkbase.ProbeCtx)
		pctx.TokenLocation = pctx.TokenLocation.WithDefaults()

		te, err := editor.NewTokenEditor(pctx.TokenString)
		if err != nil {
			return harnessx.Result{}, err
		}
		alg := te.GetToken().Method.Alg()
		pctx.Alg = alg
		pctx.IsHMAC = te.IsHMACAlg()
		pctx.IsAsymmetric = isAsymmetricAlg(alg)

		parts := strings.SplitN(pctx.TokenString, ".", 3)
		if len(parts) == 3 {
			pctx.InvalidToken = parts[0] + "." + parts[1] + ".invalidsignature"
		} else {
			pctx.InvalidToken = "invalid.token.here"
		}

		algNoneTokens, algNoneErr := exploit.AlgNoneAll(pctx.TokenString)
		pctx.AlgNoneTokens = algNoneTokens
		pctx.AlgNoneErr = algNoneErr

		return baselineCapture.Run(ctx, target, store)
	})
}()
