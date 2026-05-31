package hmacconfusion

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
		panic("hmac_confusion: failed to parse check.yaml: " + err.Error())
	}
	return harnessx.Check{
		ID:          harnessx.CheckID(def.ID),
		Name:        def.Name,
		Description: def.Description,
		Link:        def.Link,
		Tags:        def.Tags,
		DependsOn:   def.DependsOnIDs(),
		Skip: harnessx.SkipWhen(func(_ context.Context, target harnessx.Target, _ harnessx.ResultStore) string {
			pctx := target.Data.(*checkbase.ProbeCtx)
			if !pctx.IsAsymmetric {
				return "asymmetric-to-HMAC exploit not applicable for " + pctx.Alg
			}
			if len(pctx.PublicKeyPEM) == 0 {
				return "no public key provided"
			}
			return ""
		}),
		Run: func(ctx context.Context, target harnessx.Target, store harnessx.ResultStore) (harnessx.Result, error) {
			pctx := target.Data.(*checkbase.ProbeCtx)
			token, err := exploit.HMACConfusion(pctx.TokenString, pctx.PublicKeyPEM)
			if err != nil {
				r := harnessx.DataResult(checkbase.ProbeResult{Err: err})
				r.Err = err
				return r, nil
			}
			return checkbase.SendProbe(ctx, pctx.Probe, target.URL, token, store)
		},
	}
}()
