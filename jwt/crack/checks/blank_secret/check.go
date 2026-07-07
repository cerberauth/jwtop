package blanksecret

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
		panic("blank_secret: failed to parse check.yaml: " + err.Error())
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
			if !pctx.IsHMAC {
				return "HMAC-only exploit (token uses " + pctx.Alg + ")"
			}
			return ""
		}),
		Run: func(ctx context.Context, target harnessx.Target, store harnessx.ResultStore) (harnessx.Result, error) {
			pctx := target.Data.(*checkbase.ProbeCtx)
			if pctx.Offline {
				vulnerable, err := exploit.IsSignedWithBlankSecret(pctx.TokenString)
				if err != nil {
					r := harnessx.DataResult(checkbase.ProbeResult{Err: err})
					r.Err = err
					return r, nil
				}
				return harnessx.DataResult(checkbase.ProbeResult{Vulnerable: vulnerable}), nil
			}
			token, err := exploit.BlankSecret(pctx.TokenString)
			if err != nil {
				r := harnessx.DataResult(checkbase.ProbeResult{Err: err})
				r.Err = err
				return r, nil
			}
			return checkbase.SendProbe(ctx, pctx.Probe, target.URL, token, pctx.TokenLocation, store)
		},
	}
}()
