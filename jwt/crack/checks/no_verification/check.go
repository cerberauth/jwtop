package noverification

import (
	"context"
	_ "embed"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/checkdef"
	"github.com/cerberauth/jwtop/jwt/crack/checkbase"
)

//go:embed check.yaml
var checkYAML []byte

var Def = checkdef.MustParseCheckDefYAML("no_verification", checkYAML)

var Check = checkdef.NewCheck(Def,
	func(ctx context.Context, target harnessx.Target, store harnessx.ResultStore) (harnessx.Result, error) {
		pctx := target.Data.(*checkbase.ProbeCtx)
		baseline, _ := harnessx.BaselineFromGlobalCheck(checkbase.CheckIDBaseline)(ctx, target, store)
		pr := checkbase.ProbeResult{
			Payload:    pctx.InvalidToken,
			Status:     baseline.StatusCode,
			Vulnerable: baseline.StatusCode < 400,
		}
		return harnessx.DataResult(pr), nil
	},
	checkdef.WithSkip(harnessx.SkipWhen(func(_ context.Context, target harnessx.Target, _ harnessx.ResultStore) string {
		if target.Data.(*checkbase.ProbeCtx).Offline {
			return "requires live server"
		}
		return ""
	})),
)
