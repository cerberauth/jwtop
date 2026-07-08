package algnone

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

var Checks []harnessx.Check

func init() {
	if err := yaml.Unmarshal(checkYAML, &Def); err != nil {
		panic("alg_none: failed to parse check.yaml: " + err.Error())
	}
	for i, v := range exploit.AlgNoneVariants {
		idx := i
		Checks = append(Checks, harnessx.Check{
			ID:          harnessx.CheckID(Def.ID + " (" + v + ")"),
			Name:        Def.Name + " (" + v + ")",
			Description: Def.Description,
			Link:        Def.Link,
			Tags:        Def.Tags,
			DependsOn:   Def.DependsOnIDs(),
			Skip: harnessx.SkipWhen(func(_ context.Context, target harnessx.Target, _ harnessx.ResultStore) string {
				pctx := target.Data.(*checkbase.ProbeCtx)
				if idx == 0 && strings.EqualFold(pctx.Alg, "none") {
					return ""
				}
				if pctx.Offline {
					return "requires live server"
				}
				return ""
			}),
			Run: func(ctx context.Context, target harnessx.Target, store harnessx.ResultStore) (harnessx.Result, error) {
				pctx := target.Data.(*checkbase.ProbeCtx)
				if idx == 0 && strings.EqualFold(pctx.Alg, "none") {
					return harnessx.DataResult(checkbase.ProbeResult{
						Vulnerable: true,
						Extra:      "token already uses alg=none",
					}), nil
				}
				if pctx.AlgNoneErr != nil {
					r := harnessx.DataResult(checkbase.ProbeResult{Err: pctx.AlgNoneErr})
					r.Err = pctx.AlgNoneErr
					return r, nil
				}
				return checkbase.SendProbe(ctx, pctx.Probe, target.URL, pctx.AlgNoneTokens[idx], pctx.TokenLocation, store)
			},
		})
	}
}
