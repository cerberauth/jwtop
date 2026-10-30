package blanksecret

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

var Def = checkdef.MustParseCheckDefYAML("blank_secret", checkYAML)

var Check = checkdef.NewCheck(Def,
	func(ctx context.Context, target harnessx.Target, store harnessx.ResultStore) (harnessx.Result, error) {
		pctx := target.Data.(*checkbase.ProbeCtx)
		if pctx.Offline {
			vulnerable, err := exploit.IsSignedWithBlankSecret(pctx.TokenString)
			if err != nil {
				r := harnessx.DataResult(checkbase.ProbeResult{Err: err})
				r.Err = err
				return r, nil
			}
			return harnessx.DataResult(checkbase.ProbeResult{Vulnerable: vulnerable}), nil
		}
		token, err := exploit.BlankSecret(pctx.TokenString)
		return checkbase.SendToken(ctx, target, store, token, err)
	},
	checkdef.WithSkip(harnessx.SkipWhen(func(_ context.Context, target harnessx.Target, _ harnessx.ResultStore) string {
		pctx := target.Data.(*checkbase.ProbeCtx)
		if !pctx.IsHMAC {
			return "HMAC-only exploit (token uses " + pctx.Alg + ")"
		}
		return ""
	})),
)
