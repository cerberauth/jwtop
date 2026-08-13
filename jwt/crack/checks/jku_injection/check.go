package jkuinjection

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

var Def = checkdef.MustParseCheckDefYAML("jku_injection", checkYAML)

var Check = checkdef.NewCheck(Def, run, checkdef.WithSkip(harnessx.SkipWhen(skip)))

func skip(_ context.Context, target harnessx.Target, _ harnessx.ResultStore) string {
	pctx := target.Data.(*checkbase.ProbeCtx)
	if pctx.Offline {
		return "requires live server (server-side jku fetch)"
	}
	if !pctx.IsAsymmetric {
		return "jku injection not applicable for " + pctx.Alg
	}
	if pctx.JKUServerAddr == "" {
		return "no JKU callback address configured (set JKUServerAddr)"
	}
	return ""
}

// run generates a self-signed key, spins up a local JWKS server advertising
// it, points the token's jku header at that server, and probes the target.
// The server is closed once the probe request has completed.
func run(ctx context.Context, target harnessx.Target, store harnessx.ResultStore) (harnessx.Result, error) {
	pctx := target.Data.(*checkbase.ProbeCtx)

	method, err := jwtpkg.ParseSigningMethod(pctx.Alg)
	if err != nil {
		return checkbase.SendToken(ctx, target, store, "", err)
	}

	token, srv, err := exploit.JKUInjectionWithLocalServer(pctx.TokenString, method, pctx.JKUServerAddr)
	if err != nil {
		return checkbase.SendToken(ctx, target, store, "", err)
	}
	defer srv.Close() //nolint:errcheck

	return checkbase.SendToken(ctx, target, store, token, nil)
}
