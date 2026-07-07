package kidpathtraversal

import (
	"context"
	_ "embed"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/jwtop/jwt/crack/checkbase"
	"github.com/cerberauth/jwtop/jwt/exploit"
	"gopkg.in/yaml.v3"
)

//go:embed check.yaml
var checkYAML []byte

var Def checkbase.CheckDef

var Check = func() harnessx.Check {
	if err := yaml.Unmarshal(checkYAML, &Def); err != nil {
		panic("kid_path_traversal: failed to parse check.yaml: " + err.Error())
	}
	return harnessx.Check{
		ID:          harnessx.CheckID(Def.ID),
		Name:        Def.Name,
		Description: Def.Description,
		Link:        Def.Link,
		Tags:        Def.Tags,
		DependsOn:   Def.DependsOnIDs(),
		Skip: harnessx.SkipWhen(func(_ context.Context, target harnessx.Target, store harnessx.ResultStore) string {
			if target.Data.(*checkbase.ProbeCtx).Offline {
				return "requires live server (server-side key lookup)"
			}
			if pr, ok := harnessx.GetData[checkbase.ProbeResult](store, "blanksecret"); ok && pr.Vulnerable {
				return "server accepts a blank HMAC secret regardless of kid — see Blank Secret finding"
			}
			return ""
		}),
		Run: func(ctx context.Context, target harnessx.Target, store harnessx.ResultStore) (harnessx.Result, error) {
			pctx := target.Data.(*checkbase.ProbeCtx)
			path := exploit.DefaultKidPathTraversalPayload
			if pctx.KidPath != "" {
				path = pctx.KidPath
			}
			token, err := exploit.KidPathTraversal(pctx.TokenString, path, []byte(""))
			if err != nil {
				r := harnessx.DataResult(checkbase.ProbeResult{Err: err})
				r.Err = err
				return r, nil
			}
			return checkbase.SendProbe(ctx, pctx.Probe, target.URL, token, store)
		},
	}
}()
