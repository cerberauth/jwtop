package algnone

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

var Def = checkdef.MustParseCheckDefYAML("alg_none", checkYAML)

// variantIndex maps a variant string (an entry of exploit.AlgNoneVariants)
// to its position, so a variant attempt can look up its matching
// pre-forged token in ProbeCtx.AlgNoneTokens (built in the same order by
// exploit.AlgNoneAll).
var variantIndex = func() map[string]int {
	m := make(map[string]int, len(exploit.AlgNoneVariants))
	for i, v := range exploit.AlgNoneVariants {
		m[v] = i
	}
	return m
}()

var Check = checkdef.NewVariantCheck(Def,
	func(ctx context.Context, target harnessx.Target, variant string, store harnessx.ResultStore) (harnessx.Result, error) {
		pctx := target.Data.(*checkbase.ProbeCtx)
		if pctx.AlgNoneErr != nil {
			return checkbase.SendToken(ctx, target, store, "", pctx.AlgNoneErr)
		}
		// Only the canonical "none" variant checks for a token that
		// already uses alg=none — matches the old idx==0 behavior, and
		// avoids reporting the same "already vulnerable" finding once per
		// casing variant.
		if variantIndex[variant] == 0 && strings.EqualFold(pctx.Alg, "none") {
			return harnessx.DataResult(checkbase.ProbeResult{
				Vulnerable: true,
				Extra:      "token already uses alg=none",
			}), nil
		}
		if pctx.Offline {
			return harnessx.Result{}, nil
		}
		return checkbase.SendToken(ctx, target, store, pctx.AlgNoneTokens[variantIndex[variant]], nil)
	},
	checkdef.WithVariants(exploit.AlgNoneVariants...),
	checkdef.WithSkip(harnessx.SkipWhen(func(_ context.Context, target harnessx.Target, _ harnessx.ResultStore) string {
		pctx := target.Data.(*checkbase.ProbeCtx)
		if strings.EqualFold(pctx.Alg, "none") {
			return ""
		}
		if pctx.Offline {
			return "requires live server"
		}
		return ""
	})),
)
