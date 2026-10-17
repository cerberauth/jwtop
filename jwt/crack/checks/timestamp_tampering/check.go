// Package timestamptampering implements the "jwtop crack" check for the
// exp/iat/nbf timestamp-tampering exploits in jwt/exploit: using the HMAC
// secret recovered by the secret (weak_secret) check, it re-signs the
// token with its exp claim pushed into the past and sends it. A signature
// check alone doesn't prove a token is still supposed to be usable now, so
// a correct verifier must reject this regardless of what the original exp
// was. A server that accepts it has claims validation (exp, and usually
// nbf/iat along with it) turned off entirely once the signature checks
// out — a real misconfiguration in several JWT libraries, not merely a
// missing defense-in-depth control.
package timestamptampering

import (
	"context"
	_ "embed"
	"time"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/checkdef"
	"github.com/cerberauth/jwtop/jwt/crack/checkbase"
	"github.com/cerberauth/jwtop/jwt/exploit"
)

//go:embed check.yaml
var checkYAML []byte

var Def = checkdef.MustParseCheckDefYAML("timestamp_tampering", checkYAML)

// expiredOffset pushes exp an hour into the past. Any value already in the
// past works; an hour keeps this well clear of clock-skew tolerances some
// verifiers apply.
const expiredOffset = -time.Hour

var Check = checkbase.NewTokenCheck(Def,
	harnessx.SkipWhen(func(_ context.Context, target harnessx.Target, _ harnessx.ResultStore) string {
		pctx := target.Data.(*checkbase.ProbeCtx)
		if pctx.Offline {
			return "requires live server"
		}
		if !pctx.IsHMAC {
			return "HMAC-only exploit (token uses " + pctx.Alg + ")"
		}
		if pctx.CrackedHMACSecret == "" {
			return "HMAC secret not cracked (requires the secret check to succeed first)"
		}
		return ""
	}),
	func(pctx *checkbase.ProbeCtx) (string, error) {
		return exploit.ExtendExpiration(pctx.TokenString, []byte(pctx.CrackedHMACSecret), expiredOffset)
	},
)
