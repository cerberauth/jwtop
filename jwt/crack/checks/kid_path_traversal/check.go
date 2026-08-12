package kidpathtraversal

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

var Def = checkdef.MustParseCheckDefYAML("kid_path_traversal", checkYAML)

var Check = checkbase.NewTokenCheck(Def,
	harnessx.SkipWhen(func(_ context.Context, target harnessx.Target, store harnessx.ResultStore) string {
		if target.Data.(*checkbase.ProbeCtx).Offline {
			return "requires live server (server-side key lookup)"
		}
		if pr, ok := harnessx.GetData[checkbase.ProbeResult](store, "blanksecret"); ok && pr.Vulnerable {
			return "server accepts a blank HMAC secret regardless of kid — see Blank Secret finding"
		}
		return ""
	}),
	func(pctx *checkbase.ProbeCtx) (string, error) {
		path := exploit.DefaultKidPathTraversalPayload
		if pctx.KidPath != "" {
			path = pctx.KidPath
		}
		return exploit.KidPathTraversal(pctx.TokenString, path, []byte(""))
	},
)
