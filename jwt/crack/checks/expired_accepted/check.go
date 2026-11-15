package expiredaccepted

import (
	"context"
	_ "embed"
	"time"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/checkdef"
	"github.com/cerberauth/jwtop/jwt/crack/checkbase"
)

//go:embed check.yaml
var checkYAML []byte

var Def = checkdef.MustParseCheckDefYAML("expired_accepted", checkYAML)

var Check = checkbase.NewTokenCheck(Def,
	harnessx.SkipWhen(func(_ context.Context, target harnessx.Target, _ harnessx.ResultStore) string {
		pctx := target.Data.(*checkbase.ProbeCtx)
		if pctx.Offline {
			return "requires live server"
		}
		claims, err := pctx.Claims()
		if err != nil {
			return err.Error()
		}
		exp, err := claims.GetExpirationTime()
		if err != nil || exp == nil {
			return "token has no exp claim"
		}
		if exp.After(time.Now()) {
			return "token is not expired (timestamp_tampering re-signs it expired when the secret is known)"
		}
		return ""
	}),
	func(pctx *checkbase.ProbeCtx) (string, error) {
		return pctx.TokenString, nil
	},
)
