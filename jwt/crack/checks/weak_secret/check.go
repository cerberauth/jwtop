package weaksecret

import (
	"context"
	_ "embed"
	"net/http"

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
		panic("weak_secret: failed to parse check.yaml: " + err.Error())
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
			if !pctx.IsHMAC {
				return "HMAC-only exploit (token uses " + pctx.Alg + ")"
			}
			return ""
		}),
		Run: func(ctx context.Context, target harnessx.Target, store harnessx.ResultStore) (harnessx.Result, error) {
			pctx := target.Data.(*checkbase.ProbeCtx)
			result, err := exploit.CrackSecret(pctx.TokenString, pctx.Candidates, pctx.Workers)
			if err != nil {
				return harnessx.Result{}, err
			}
			if !result.Found {
				return checkbase.SkippedProbeResult("not found in dictionary"), nil
			}
			if pctx.Offline {
				return harnessx.DataResult(checkbase.ProbeResult{
					Vulnerable: true,
					Extra:      "secret: " + result.Secret,
				}), nil
			}
			baseline, _ := harnessx.GetData[int](store, checkbase.CheckIDBaseline)
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.URL, nil)
			if err != nil {
				return harnessx.Result{}, err
			}
			req.Header.Set("Authorization", "Bearer "+pctx.TokenString)
			resp, err := pctx.Probe.Client().Do(req)
			if err != nil {
				return harnessx.Result{}, err
			}
			resp.Body.Close()
			pr := checkbase.ProbeResult{
				Token:      pctx.TokenString,
				Status:     resp.StatusCode,
				Vulnerable: resp.StatusCode != baseline,
				Extra:      "secret: " + result.Secret,
			}
			return harnessx.DataResult(pr), nil
		},
	}
}()
