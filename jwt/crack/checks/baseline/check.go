package baseline

import (
	"context"
	_ "embed"
	"net/http"
	"strings"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/jwtop/jwt/crack/checkbase"
	"github.com/cerberauth/jwtop/jwt/editor"
	"github.com/cerberauth/jwtop/jwt/exploit"
	"gopkg.in/yaml.v3"
)

//go:embed check.yaml
var checkYAML []byte

func isAsymmetricAlg(alg string) bool {
	switch alg {
	case "RS256", "RS384", "RS512",
		"ES256", "ES384", "ES512",
		"PS256", "PS384", "PS512":
		return true
	}
	return false
}

var Check = func() harnessx.Check {
	var def checkbase.CheckDef
	if err := yaml.Unmarshal(checkYAML, &def); err != nil {
		panic("baseline: failed to parse check.yaml: " + err.Error())
	}
	return harnessx.Check{
		ID:          harnessx.CheckID(def.ID),
		Name:        def.Name,
		Description: def.Description,
		Link:        def.Link,
		Tags:        def.Tags,
		DependsOn:   def.DependsOnIDs(),
		Run: func(ctx context.Context, target harnessx.Target, _ harnessx.ResultStore) (harnessx.Result, error) {
			pctx := target.Data.(*checkbase.ProbeCtx)

			te, err := editor.NewTokenEditor(pctx.TokenString)
			if err != nil {
				return harnessx.Result{}, err
			}
			alg := te.GetToken().Method.Alg()
			pctx.Alg = alg
			pctx.IsHMAC = te.IsHMACAlg()
			pctx.IsAsymmetric = isAsymmetricAlg(alg)

			parts := strings.SplitN(pctx.TokenString, ".", 3)
			if len(parts) == 3 {
				pctx.InvalidToken = parts[0] + "." + parts[1] + ".invalidsignature"
			} else {
				pctx.InvalidToken = "invalid.token.here"
			}

			algNoneTokens, algNoneErr := exploit.AlgNoneAll(pctx.TokenString)
			pctx.AlgNoneTokens = algNoneTokens
			pctx.AlgNoneErr = algNoneErr

			status := pctx.ExpectedStatus
			if status == 0 {
				req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.URL, nil)
				if err != nil {
					return harnessx.Result{}, err
				}
				req.Header.Set("Authorization", "Bearer "+pctx.InvalidToken)
				resp, err := pctx.Probe.Client().Do(req)
				if err != nil {
					return harnessx.Result{}, err
				}
				resp.Body.Close()
				status = resp.StatusCode
			}
			return harnessx.DataResult(status), nil
		},
	}
}()
