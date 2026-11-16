package scopenotvalidated

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

var Def = checkdef.MustParseCheckDefYAML("scope_not_validated", checkYAML)

var ScopeClaims = []string{"scope", "scp", "roles", "role", "groups", "permissions", "authorities"}

var Check = checkbase.NewTokenCheck(Def,
	harnessx.SkipWhen(func(ctx context.Context, target harnessx.Target, store harnessx.ResultStore) string {
		if reason := checkbase.SkipUnlessResignable().Eval(ctx, target, store); reason != "" {
			return reason
		}
		claims, err := target.Data.(*checkbase.ProbeCtx).Claims()
		if err != nil {
			return err.Error()
		}
		if len(checkbase.PresentClaims(claims, ScopeClaims...)) == 0 {
			return "token has no scope or role claim"
		}
		return ""
	}),
	func(pctx *checkbase.ProbeCtx) (string, error) {
		claims, err := pctx.Claims()
		if err != nil {
			return "", err
		}
		return exploit.RemoveClaims(pctx.TokenString, pctx.ResigningKey(), checkbase.PresentClaims(claims, ScopeClaims...)...)
	},
)
