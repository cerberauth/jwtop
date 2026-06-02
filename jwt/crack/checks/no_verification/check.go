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

var Check = func() harnessx.Check {
	var def checkbase.CheckDef
	if err := yaml.Unmarshal(checkYAML, &def); err != nil {
		panic("no_verification: failed to parse check.yaml: " + err.Error())
	}
	return harnessx.Check{
		ID:          harnessx.CheckID(def.ID),
		Name:        def.Name,
		Description: def.Description,
		Link:        def.Link,
		Tags:        def.Tags,
		DependsOn:   def.DependsOnIDs(),
		Run: func(_ context.Context, target harnessx.Target, store harnessx.ResultStore) (harnessx.Result, error) {
			pctx := target.Data.(*checkbase.ProbeCtx)
			baseline, _ := harnessx.GetData[int](store, checkbase.CheckIDBaseline)
			pr := checkbase.ProbeResult{
				Token:      pctx.InvalidToken,
				Status:     baseline,
				Vulnerable: baseline < 400,
			}
			return harnessx.DataResult(pr), nil
		},
	}
}()
