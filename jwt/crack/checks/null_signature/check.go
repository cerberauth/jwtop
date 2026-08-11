package nullsignature

import (
	"context"
	_ "embed"
	"strings"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/checkdef"
	"github.com/cerberauth/jwtop/jwt/crack/checkbase"
	"github.com/cerberauth/jwtop/jwt/exploit"
)

//go:embed check.yaml
var checkYAML []byte

var Def = checkdef.MustParseCheckDefYAML("null_signature", checkYAML)

var Check = checkdef.NewCheck(Def,
	func(ctx context.Context, target harnessx.Target, store harnessx.ResultStore) (harnessx.Result, error) {
		pctx := target.Data.(*checkbase.ProbeCtx)
		if pctx.Offline {
			parts := strings.SplitN(pctx.TokenString, ".", 3)
			return harnessx.DataResult(checkbase.ProbeResult{
				Vulnerable: len(parts) == 3 && parts[2] == "",
			}), nil
		}
		token, err := exploit.NullSignature(pctx.TokenString)
		return checkbase.SendToken(ctx, target, store, token, err)
	},
	checkdef.WithSkip(harnessx.SkipWhen(func(_ context.Context, target harnessx.Target, _ harnessx.ResultStore) string {
		pctx := target.Data.(*checkbase.ProbeCtx)
		if strings.EqualFold(pctx.Alg, "none") {
			return "token already uses alg=none — see Algorithm None finding"
		}
		return ""
	})),
)
