package jwkinjection

import (
	"context"
	_ "embed"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/checkdef"
	jwtpkg "github.com/cerberauth/jwtop/jwt"
	"github.com/cerberauth/jwtop/jwt/crack/checkbase"
	"github.com/cerberauth/jwtop/jwt/exploit"
)

//go:embed check.yaml
var checkYAML []byte

var Def = checkdef.MustParseCheckDefYAML("jwk_injection", checkYAML)

var Check = checkbase.NewTokenCheck(Def,
	harnessx.SkipWhen(func(_ context.Context, target harnessx.Target, _ harnessx.ResultStore) string {
		pctx := target.Data.(*checkbase.ProbeCtx)
		if pctx.Offline {
			return "requires live server (server-side key trust)"
		}
		if !pctx.IsAsymmetric {
			return "jwk injection not applicable for " + pctx.Alg
		}
		return ""
	}),
	func(pctx *checkbase.ProbeCtx) (string, error) {
		method, err := jwtpkg.ParseSigningMethod(pctx.Alg)
		if err != nil {
			return "", err
		}
		return exploit.JWKInjection(pctx.TokenString, method)
	},
)
