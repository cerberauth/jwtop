package kidsqlinjection

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

var Def = checkdef.MustParseCheckDefYAML("kid_sql_injection", checkYAML)

// kidSQLTables returns the table-name candidates to try, in order of
// precedence: pctx.KidSQLTables when set, else the deprecated single-value
// pctx.KidSQLTable, else exploit.DefaultKidSQLTable.
func kidSQLTables(pctx *checkbase.ProbeCtx) []string {
	if len(pctx.KidSQLTables) > 0 {
		return pctx.KidSQLTables
	}
	if pctx.KidSQLTable != "" {
		return []string{pctx.KidSQLTable}
	}
	return []string{exploit.DefaultKidSQLTable}
}

var Check = checkdef.NewCheck(Def,
	func(ctx context.Context, target harnessx.Target, store harnessx.ResultStore) (harnessx.Result, error) {
		pctx := target.Data.(*checkbase.ProbeCtx)

		var last harnessx.Result
		for _, table := range kidSQLTables(pctx) {
			token, err := exploit.KidSQLInjection(pctx.TokenString, exploit.BuildKidSQLPayload(table), []byte("secret"))
			if err != nil {
				r := harnessx.DataResult(checkbase.ProbeResult{Err: err})
				r.Err = err
				return r, nil
			}

			result, err := checkbase.SendProbe(ctx, pctx.Probe, target.URL, token, pctx.TokenLocation, store)
			if err != nil {
				return harnessx.Result{}, err
			}

			if pr, ok := harnessx.DataAs[checkbase.ProbeResult](result); ok && pr.Vulnerable {
				pr.Extra = "table: " + table
				return harnessx.DataResult(pr), nil
			}
			last = result
		}
		// None of the candidates proved vulnerable; report the last probe's
		// (non-vulnerable) result rather than swallowing it.
		return last, nil
	},
	checkdef.WithSkip(harnessx.SkipWhen(func(_ context.Context, target harnessx.Target, store harnessx.ResultStore) string {
		if target.Data.(*checkbase.ProbeCtx).Offline {
			return "requires live server (server-side key lookup)"
		}
		if pr, ok := harnessx.GetData[checkbase.ProbeResult](store, "secret"); ok && pr.Vulnerable {
			return "server accepts a weak/known HMAC secret regardless of kid — see Weak Secret finding"
		}
		return ""
	})),
)
