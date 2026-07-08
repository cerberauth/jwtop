package nullsignature

import (
	"context"
	_ "embed"
	"strings"

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
		panic("null_signature: failed to parse check.yaml: " + err.Error())
	}
	return harnessx.Check{
		ID:          harnessx.CheckID(Def.ID),
		Name:        Def.Name,
		Description: Def.Description,
		Link:        Def.Link,
		Tags:        Def.Tags,
		DependsOn:   Def.DependsOnIDs(),
		Skip: harnessx.SkipWhen(func(_ context.Context, target harnessx.Target, _ harnessx.ResultStore) string {
			pctx := target.Data.(*checkbase.ProbeCtx)
			if strings.EqualFold(pctx.Alg, "none") {
				return "token already uses alg=none — see Algorithm None finding"
			}
			return ""
		}),
		Run: func(ctx context.Context, target harnessx.Target, store harnessx.ResultStore) (harnessx.Result, error) {
			pctx := target.Data.(*checkbase.ProbeCtx)
			if pctx.Offline {
				parts := strings.SplitN(pctx.TokenString, ".", 3)
				return harnessx.DataResult(checkbase.ProbeResult{
					Vulnerable: len(parts) == 3 && parts[2] == "",
				}), nil
			}
			token, err := exploit.NullSignature(pctx.TokenString)
			if err != nil {
				r := harnessx.DataResult(checkbase.ProbeResult{Err: err})
				r.Err = err
				return r, nil
			}
			return checkbase.SendProbe(ctx, pctx.Probe, target.URL, token, pctx.TokenLocation, store)
		},
	}
}()
