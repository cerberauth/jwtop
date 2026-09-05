package fuzz_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/probe"
	"github.com/cerberauth/jwtop/jwt/crack/checkbase"
	claimfuzz "github.com/cerberauth/jwtop/jwt/crack/checks/fuzz"
	jwtlib "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

func TestCheck_Skip_Offline(t *testing.T) {
	store := harnessx.NewStaticResultStore()
	target := harnessx.Target{Data: &checkbase.ProbeCtx{Offline: true, FuzzEnabled: true}}

	reason := claimfuzz.Check.Skip.Eval(context.Background(), target, store)
	assert.NotEmpty(t, reason)
}

func TestCheck_Skip_NotEnabled(t *testing.T) {
	store := harnessx.NewStaticResultStore()
	target := harnessx.Target{Data: &checkbase.ProbeCtx{Offline: false, FuzzEnabled: false}}

	reason := claimfuzz.Check.Skip.Eval(context.Background(), target, store)
	assert.NotEmpty(t, reason)
}

func TestCheck_Skip_RunsWhenEnabledAndOnline(t *testing.T) {
	store := harnessx.NewStaticResultStore()
	target := harnessx.Target{Data: &checkbase.ProbeCtx{Offline: false, FuzzEnabled: true}}

	reason := claimfuzz.Check.Skip.Eval(context.Background(), target, store)
	assert.Empty(t, reason)
}

func TestCheck_Run_NotVulnerableWhenResponsesStable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	pctx := &checkbase.ProbeCtx{
		TokenString:      testToken,
		Probe:            probe.New(),
		TokenLocation:    checkbase.DefaultTokenLocation(),
		FuzzEnabled:      true,
		FuzzMaxStringLen: 16,
	}
	store := harnessx.NewStaticResultStore()
	target := harnessx.Target{URL: srv.URL, Data: pctx}

	result, err := claimfuzz.Check.Run(context.Background(), target, store)
	require.NoError(t, err)
	pr, ok := harnessx.DataAs[checkbase.ProbeResult](result)
	require.True(t, ok)
	assert.False(t, pr.Vulnerable)
}

func TestCheck_Run_VulnerableWhenServerErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		if token != "Bearer "+testToken {
			w.WriteHeader(500)
			_, _ = w.Write([]byte("panic: runtime error\n\ngoroutine 1 [running]:"))
			return
		}
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	pctx := &checkbase.ProbeCtx{
		TokenString:      testToken,
		Probe:            probe.New(),
		TokenLocation:    checkbase.DefaultTokenLocation(),
		FuzzEnabled:      true,
		FuzzMaxStringLen: 16,
	}
	store := harnessx.NewStaticResultStore()
	target := harnessx.Target{URL: srv.URL, Data: pctx}

	result, err := claimfuzz.Check.Run(context.Background(), target, store)
	require.NoError(t, err)
	pr, ok := harnessx.DataAs[checkbase.ProbeResult](result)
	require.True(t, ok)
	assert.True(t, pr.Vulnerable)
	assert.Contains(t, pr.Extra, "diverged from baseline")
}

func TestCheck_Run_SignsMutationsWithCrackedSecret(t *testing.T) {
	secret := []byte("s3cr3t-dev-key")
	token, err := jwtlib.NewWithClaims(jwtlib.SigningMethodHS256, jwtlib.MapClaims{
		"sub": "1234567890", "name": "John Doe",
	}).SignedString(secret)
	require.NoError(t, err)

	// Mirrors the jwt-claim-* challenges: the server verifies the
	// signature correctly and only crashes once a mutated claim reaches
	// the handler — which requires a genuinely valid signature, not just
	// a token with the signature stripped.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bearer := r.Header.Get("Authorization")
		reqToken := bearer[len("Bearer "):]
		parsed, err := jwtlib.Parse(reqToken, func(*jwtlib.Token) (interface{}, error) { return secret, nil })
		if err != nil || !parsed.Valid {
			w.WriteHeader(401)
			return
		}
		claims := parsed.Claims.(jwtlib.MapClaims)
		if _, ok := claims["sub"].(string); !ok {
			w.WriteHeader(500)
			_, _ = w.Write([]byte("panic: interface conversion\n\ngoroutine 1 [running]:"))
			return
		}
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	pctx := &checkbase.ProbeCtx{
		TokenString:       token,
		Probe:             probe.New(),
		TokenLocation:     checkbase.DefaultTokenLocation(),
		FuzzEnabled:       true,
		FuzzMaxStringLen:  16,
		IsHMAC:            true,
		CrackedHMACSecret: "s3cr3t-dev-key",
	}
	store := harnessx.NewStaticResultStore()
	target := harnessx.Target{URL: srv.URL, Data: pctx}

	result, err := claimfuzz.Check.Run(context.Background(), target, store)
	require.NoError(t, err)
	pr, ok := harnessx.DataAs[checkbase.ProbeResult](result)
	require.True(t, ok)
	assert.True(t, pr.Vulnerable)
}

func TestCheck_Run_ErrorOnMalformedToken(t *testing.T) {
	pctx := &checkbase.ProbeCtx{
		TokenString:   "not-a-jwt",
		Probe:         probe.New(),
		TokenLocation: checkbase.DefaultTokenLocation(),
		FuzzEnabled:   true,
	}
	store := harnessx.NewStaticResultStore()
	target := harnessx.Target{URL: "http://example.com", Data: pctx}

	result, err := claimfuzz.Check.Run(context.Background(), target, store)
	require.NoError(t, err)
	assert.Error(t, result.Err)
}
