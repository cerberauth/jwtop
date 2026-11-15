package claimtest

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/probe"
	"github.com/cerberauth/jwtop/jwt/crack/checkbase"
	jwtlib "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

var Secret = []byte("secret")

func Sign(t *testing.T, claims jwtlib.MapClaims) string {
	t.Helper()
	token, err := jwtlib.NewWithClaims(jwtlib.SigningMethodHS256, claims).SignedString(Secret)
	require.NoError(t, err)
	return token
}

func Server(t *testing.T, accept func(claims jwtlib.MapClaims) bool) string {
	t.Helper()
	return ServerRejecting(t, accept, http.StatusUnauthorized, http.StatusUnauthorized)
}

func ServerRejecting(t *testing.T, accept func(claims jwtlib.MapClaims) bool, invalidStatus int, rejectedStatus int) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := jwtlib.MapClaims{}
		_, err := jwtlib.ParseWithClaims(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "), claims, func(*jwtlib.Token) (interface{}, error) {
			return Secret, nil
		}, jwtlib.WithoutClaimsValidation())
		if err != nil {
			w.WriteHeader(invalidStatus)
			return
		}
		if !accept(claims) {
			w.WriteHeader(rejectedStatus)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func Run(t *testing.T, check harnessx.Check, url string, pctx *checkbase.ProbeCtx) (checkbase.ProbeResult, string) {
	t.Helper()
	ctx := context.Background()
	pctx.Probe = probe.New()
	pctx.TokenLocation = checkbase.DefaultTokenLocation()
	pctx.IsHMAC = true
	pctx.Alg = "HS256"
	pctx.Offline = url == ""
	store := harnessx.NewStaticResultStore(harnessx.ResultData(checkbase.CheckIDBaseline, harnessx.Snapshot{StatusCode: http.StatusUnauthorized}))
	target := harnessx.Target{URL: url, Data: pctx}

	if reason := check.Skip.Eval(ctx, target, store); reason != "" {
		return checkbase.ProbeResult{}, reason
	}

	if len(check.Variants) == 0 {
		result, err := check.Run(ctx, target, store)
		require.NoError(t, err)
		require.NoError(t, result.Err)
		pr, _ := harnessx.DataAs[checkbase.ProbeResult](result)
		return pr, ""
	}

	var attempts []harnessx.Attempt
	for _, variant := range check.Variants {
		result, err := check.RunVariant(ctx, target, variant, store)
		require.NoError(t, err)
		require.NoError(t, result.Err)
		attempts = append(attempts, harnessx.Attempt{Variant: variant, Data: result.Data})
	}
	pr, _ := checkbase.ResolveVariantResult(attempts)
	return pr, ""
}
