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

var Check = checkbase.NewTokenCheck(Def,
	harnessx.SkipWhen(func(_ context.Context, target harnessx.Target, store harnessx.ResultStore) string {
		if target.Data.(*checkbase.ProbeCtx).Offline {
			return "requires live server (server-side key lookup)"
		}
		if pr, ok := harnessx.GetData[checkbase.ProbeResult](store, "secret"); ok && pr.Vulnerable {
			return "server accepts a weak/known HMAC secret regardless of kid — see Weak Secret finding"
		}
		return ""
	}),
	func(pctx *checkbase.ProbeCtx) (string, error) {
		payload := exploit.DefaultKidSQLPayload
		if pctx.KidSQLTable != "" {
			payload = exploit.BuildKidSQLPayload(pctx.KidSQLTable)
		}
		return exploit.KidSQLInjection(pctx.TokenString, payload, []byte("secret"))
	},
)
