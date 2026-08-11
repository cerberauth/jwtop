package psychicsignature

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

var Def = checkdef.MustParseCheckDefYAML("psychic_signature", checkYAML)

var Check = checkbase.NewTokenCheck(Def,
	harnessx.SkipWhen(func(_ context.Context, target harnessx.Target, _ harnessx.ResultStore) string {
		pctx := target.Data.(*checkbase.ProbeCtx)
		if pctx.Offline {
			return "requires live server"
		}
		if !exploit.IsPsychicSignatureAlg(pctx.Alg) {
			return "ECDSA-only exploit (token uses " + pctx.Alg + ")"
		}
		return ""
	}),
	func(pctx *checkbase.ProbeCtx) (string, error) {
		return exploit.PsychicSignature(pctx.TokenString, pctx.Alg)
	},
)
