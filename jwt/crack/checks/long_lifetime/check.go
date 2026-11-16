package longlifetime

import (
	"context"
	_ "embed"
	"fmt"
	"time"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/checkdef"
	"github.com/cerberauth/jwtop/jwt/crack/checkbase"
)

//go:embed check.yaml
var checkYAML []byte

var Def = checkdef.MustParseCheckDefYAML("long_lifetime", checkYAML)

var Check = checkdef.NewCheck(Def, func(_ context.Context, target harnessx.Target, _ harnessx.ResultStore) (harnessx.Result, error) {
	pctx := target.Data.(*checkbase.ProbeCtx)
	claims, err := pctx.Claims()
	if err != nil {
		return harnessx.Result{}, err
	}
	exp, err := claims.GetExpirationTime()
	if err != nil || exp == nil {
		return harnessx.DataResult(checkbase.ProbeResult{}), err
	}
	start := time.Now()
	if iat, err := claims.GetIssuedAt(); err == nil && iat != nil {
		start = iat.Time
	}
	lifetime := exp.Sub(start)
	if lifetime <= pctx.MaxLifetime() {
		return harnessx.DataResult(checkbase.ProbeResult{}), nil
	}
	return harnessx.DataResult(checkbase.ProbeResult{
		Payload:    pctx.TokenString,
		Vulnerable: true,
		Extra:      fmt.Sprintf("lifetime %s above %s", lifetime.Round(time.Second), pctx.MaxLifetime()),
	}), nil
}, checkdef.WithSkip(harnessx.SkipWhen(func(_ context.Context, target harnessx.Target, _ harnessx.ResultStore) string {
	claims, err := target.Data.(*checkbase.ProbeCtx).Claims()
	if err != nil {
		return err.Error()
	}
	if exp, err := claims.GetExpirationTime(); err != nil || exp == nil {
		return "token has no exp claim"
	}
	return ""
})))
