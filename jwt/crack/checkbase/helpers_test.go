package checkbase_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/probe"
	"github.com/cerberauth/jwtop/jwt/crack/checkbase"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func assertHandler(status int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
	}
}

func TestNewTokenRequest_HeaderPlacement(t *testing.T) {
	req, err := checkbase.NewTokenRequest(context.Background(), "http://example.com", "tok", checkbase.TokenLocation{
		In: checkbase.TokenLocationHeader, Name: "Authorization", Prefix: "Bearer ",
	})
	require.NoError(t, err)
	assert.Equal(t, "GET", req.Method)
	assert.Equal(t, "Bearer tok", req.Header.Get("Authorization"))
}

func TestNewTokenRequest_CookiePlacement(t *testing.T) {
	req, err := checkbase.NewTokenRequest(context.Background(), "http://example.com", "tok", checkbase.TokenLocation{
		In: checkbase.TokenLocationCookie, Name: "session",
	})
	require.NoError(t, err)
	cookie, err := req.Cookie("session")
	require.NoError(t, err)
	assert.Equal(t, "tok", cookie.Value)
}

func TestNewTokenRequest_QueryPlacement(t *testing.T) {
	req, err := checkbase.NewTokenRequest(context.Background(), "http://example.com", "tok", checkbase.TokenLocation{
		In: checkbase.TokenLocationQuery, Name: "access_token",
	})
	require.NoError(t, err)
	assert.Equal(t, "tok", req.URL.Query().Get("access_token"))
}

func TestNewTokenRequest_BodyPlacement(t *testing.T) {
	req, err := checkbase.NewTokenRequest(context.Background(), "http://example.com", "tok", checkbase.TokenLocation{
		In: checkbase.TokenLocationBody, Name: "token",
	})
	require.NoError(t, err)
	assert.Equal(t, "POST", req.Method)
	require.NoError(t, req.ParseForm())
	assert.Equal(t, "tok", req.PostForm.Get("token"))
	assert.Equal(t, "application/x-www-form-urlencoded", req.Header.Get("Content-Type"))
}

func TestNewTokenRequest_InvalidTarget_ReturnsError(t *testing.T) {
	_, err := checkbase.NewTokenRequest(context.Background(), "://bad-url", "tok", checkbase.TokenLocation{})
	assert.Error(t, err)
}

func TestSendProbe_VulnerableWhenStatusDiffersFromBaseline(t *testing.T) {
	srv200 := httptest.NewServer(assertHandler(200))
	defer srv200.Close()

	store := harnessx.NewStaticResultStore(harnessx.ResultData(checkbase.CheckIDBaseline, 401))
	res, err := checkbase.SendProbe(context.Background(), probe.New(), srv200.URL, "tok", checkbase.DefaultTokenLocation(), store)
	require.NoError(t, err)
	pr, ok := harnessx.DataAs[checkbase.ProbeResult](res)
	require.True(t, ok)
	assert.True(t, pr.Vulnerable)
	assert.Equal(t, 200, pr.Status)
	assert.Equal(t, "tok", pr.Payload)
}

func TestSendProbe_NotVulnerableWhenStatusMatchesBaselineExact(t *testing.T) {
	srv := httptest.NewServer(assertHandler(401))
	defer srv.Close()

	store := harnessx.NewStaticResultStore(harnessx.ResultData(checkbase.CheckIDBaseline, 401))
	res, err := checkbase.SendProbe(context.Background(), probe.New(), srv.URL, "tok", checkbase.DefaultTokenLocation(), store)
	require.NoError(t, err)
	pr, ok := harnessx.DataAs[checkbase.ProbeResult](res)
	require.True(t, ok)
	assert.False(t, pr.Vulnerable)
}

func TestSendProbe_InvalidTarget_ReturnsError(t *testing.T) {
	store := harnessx.NewStaticResultStore()
	_, err := checkbase.SendProbe(context.Background(), probe.New(), "://bad-url", "tok", checkbase.DefaultTokenLocation(), store)
	assert.Error(t, err)
}

func TestSendProbe_ClientDoError_ReturnsError(t *testing.T) {
	srv := httptest.NewServer(assertHandler(200))
	srv.Close() // closed server: connection refused

	store := harnessx.NewStaticResultStore(harnessx.ResultData(checkbase.CheckIDBaseline, 200))
	_, err := checkbase.SendProbe(context.Background(), probe.New(), srv.URL, "tok", checkbase.DefaultTokenLocation(), store)
	assert.Error(t, err)
}

func TestSkippedProbeResult(t *testing.T) {
	r := checkbase.SkippedProbeResult("not applicable")
	assert.True(t, r.Skipped)
	assert.Equal(t, "not applicable", r.SkipReason)
	pr, ok := harnessx.DataAs[checkbase.ProbeResult](r)
	require.True(t, ok)
	assert.True(t, pr.Skipped)
	assert.Equal(t, "not applicable", pr.SkipReason)
}
