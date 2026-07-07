package noverification

import (
	"context"
	_ "embed"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/jwtop/jwt/crack/checkbase"
	"gopkg.in/yaml.v3"
)

//go:embed check.yaml
var checkYAML []byte

var Def checkbase.CheckDef

var Check = func() harnessx.Check {
	if err := yaml.Unmarshal(checkYAML, &Def); err != nil {
		panic("no_verification: failed to parse check.yaml: " + err.Error())
	}
	return harnessx.Check{
		ID:          harnessx.CheckID(Def.ID),
		Name:        Def.Name,
		Description: Def.Description,
		Link:        Def.Link,
		Tags:        Def.Tags,
		DependsOn:   Def.DependsOnIDs(),
		Skip: harnessx.SkipWhen(func(_ context.Context, target harnessx.Target, _ harnessx.ResultStore) string {
			if target.Data.(*checkbase.ProbeCtx).Offline {
				return "requires live server"
			}
			return ""
		}),
		Run: func(_ context.Context, target harnessx.Target, store harnessx.ResultStore) (harnessx.Result, error) {
			pctx := target.Data.(*checkbase.ProbeCtx)
			baseline, _ := harnessx.GetData[int](store, checkbase.CheckIDBaseline)
			pr := checkbase.ProbeResult{
				Payload:    pctx.InvalidToken,
				Status:     baseline,
				Vulnerable: baseline < 400,
			}
			return harnessx.DataResult(pr), nil
		},
	}
}()
