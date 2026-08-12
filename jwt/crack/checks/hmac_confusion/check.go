package hmacconfusion

import (
	"context"
	_ "embed"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/checkdef"
	"github.com/cerberauth/jwtop/jwt/crack/checkbase"
	"github.com/cerberauth/jwtop/jwt/exploit"
)

//go:embed check.yaml
var checkYAML []byte

var Def = checkdef.MustParseCheckDefYAML("hmac_confusion", checkYAML)

var Check = checkbase.NewTokenCheck(Def,
	harnessx.SkipWhen(func(_ context.Context, target harnessx.Target, _ harnessx.ResultStore) string {
		pctx := target.Data.(*checkbase.ProbeCtx)
		if pctx.Offline {
			return "requires live server"
		}
		if !pctx.IsAsymmetric {
			return "asymmetric-to-HMAC exploit not applicable for " + pctx.Alg
		}
		if len(pctx.PublicKeyPEM) == 0 {
			return "no public key provided"
		}
		return ""
	}),
	func(pctx *checkbase.ProbeCtx) (string, error) {
		return exploit.HMACConfusion(pctx.TokenString, pctx.PublicKeyPEM)
	},
)
