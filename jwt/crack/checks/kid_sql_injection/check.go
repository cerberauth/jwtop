package kidsqlinjection

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

var Check = func() harnessx.Check {
	var def checkbase.CheckDef
	if err := yaml.Unmarshal(checkYAML, &def); err != nil {
		panic("kid_sql_injection: failed to parse check.yaml: " + err.Error())
	}
	return harnessx.Check{
		ID:          harnessx.CheckID(def.ID),
		Name:        def.Name,
		Description: def.Description,
		Link:        def.Link,
		Tags:        def.Tags,
		DependsOn:   def.DependsOnIDs(),
		Run: func(ctx context.Context, target harnessx.Target, store harnessx.ResultStore) (harnessx.Result, error) {
			pctx := target.Data.(*checkbase.ProbeCtx)
			token, err := exploit.KidSQLInjection(pctx.TokenString, exploit.DefaultKidSQLPayload, []byte("secret"))
			if err != nil {
				r := harnessx.DataResult(checkbase.ProbeResult{Err: err})
				r.Err = err
				return r, nil
			}
			return checkbase.SendProbe(ctx, pctx.Probe, target.URL, token, store)
		},
	}
}()
