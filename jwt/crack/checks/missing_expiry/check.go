package missingexpiry

import (
	"context"
	_ "embed"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/checkdef"
	"github.com/cerberauth/jwtop/jwt/crack/checkbase"
)

//go:embed check.yaml
var checkYAML []byte

var Def = checkdef.MustParseCheckDefYAML("missing_expiry", checkYAML)

var Check = checkdef.NewCheck(Def, func(_ context.Context, target harnessx.Target, _ harnessx.ResultStore) (harnessx.Result, error) {
	pctx := target.Data.(*checkbase.ProbeCtx)
	claims, err := pctx.Claims()
	if err != nil {
		return harnessx.Result{}, err
	}
	if _, ok := claims["exp"]; ok {
		return harnessx.DataResult(checkbase.ProbeResult{}), nil
	}
	return harnessx.DataResult(checkbase.ProbeResult{
		Payload:    pctx.TokenString,
		Vulnerable: true,
		Extra:      "token has no exp claim",
	}), nil
})
