package checkbase_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
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

func TestNewTokenRequest_NewRequestUnset_UnchangedPlainGET(t *testing.T) {
	// Byte-for-byte the same as calling with no builder at all: the
	// variadic slot can carry a nil without changing behavior.
	req, err := checkbase.NewTokenRequest(context.Background(), "http://example.com", "tok", checkbase.DefaultTokenLocation(), nil)
	require.NoError(t, err)
	assert.Equal(t, "GET", req.Method)
	assert.Equal(t, "Bearer tok", req.Header.Get("Authorization"))
}

func TestNewTokenRequest_NewRequestSet_UsesBuilderAndAppliesCredential(t *testing.T) {
	build := func(ctx context.Context, token string) (*http.Request, error) {
		body := strings.NewReader(`{"token":"` + token + `"}`)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://example.com/login", body)
		if err != nil {
			return nil, err
		}
		req.Header.Set("X-Custom", "yes")
		req.Header.Set("Content-Type", "application/json")
		return req, nil
	}

	req, err := checkbase.NewTokenRequest(context.Background(), "http://example.com", "tok", checkbase.TokenLocation{
		In: checkbase.TokenLocationHeader, Name: "Authorization", Prefix: "Bearer ",
	}, build)
	require.NoError(t, err)

	assert.Equal(t, http.MethodPost, req.Method)
	assert.Equal(t, "yes", req.Header.Get("X-Custom"))
	assert.Equal(t, "Bearer tok", req.Header.Get("Authorization"))
	bodyBytes, err := io.ReadAll(req.Body)
	require.NoError(t, err)
	assert.Contains(t, string(bodyBytes), `"token":"tok"`)
}

func TestNewTokenRequest_NewRequestError_IsPropagated(t *testing.T) {
	wantErr := assert.AnError
	build := func(context.Context, string) (*http.Request, error) {
		return nil, wantErr
	}

	_, err := checkbase.NewTokenRequest(context.Background(), "http://example.com", "tok", checkbase.DefaultTokenLocation(), build)
	assert.ErrorIs(t, err, wantErr)
}

func TestSendProbe_VulnerableWhenStatusDiffersFromBaseline(t *testing.T) {
	srv200 := httptest.NewServer(assertHandler(200))
	defer srv200.Close()

	store := harnessx.NewStaticResultStore(harnessx.ResultData(checkbase.CheckIDBaseline, harnessx.Snapshot{StatusCode: 401}))
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

	store := harnessx.NewStaticResultStore(harnessx.ResultData(checkbase.CheckIDBaseline, harnessx.Snapshot{StatusCode: 401}))
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

func TestSendProbe_NewRequestSet_SendsPOSTWithBodyAndToken(t *testing.T) {
	type captured struct {
		method      string
		body        string
		contentType string
		authHeader  string
	}
	var got captured
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, _ := io.ReadAll(r.Body)
		got = captured{
			method:      r.Method,
			body:        string(bodyBytes),
			contentType: r.Header.Get("Content-Type"),
			authHeader:  r.Header.Get("Authorization"),
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()

	build := func(ctx context.Context, token string) (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, srv.URL+"/login", strings.NewReader(`{"token":"`+token+`"}`))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		return req, nil
	}

	store := harnessx.NewStaticResultStore(harnessx.ResultData(checkbase.CheckIDBaseline, harnessx.Snapshot{StatusCode: 401}))
	res, err := checkbase.SendProbe(context.Background(), probe.New(), srv.URL, "tok", checkbase.DefaultTokenLocation(), store, build)
	require.NoError(t, err)

	assert.Equal(t, http.MethodPost, got.method)
	assert.Equal(t, "application/json", got.contentType)
	assert.Contains(t, got.body, `"token":"tok"`)
	assert.Equal(t, "Bearer tok", got.authHeader)

	pr, ok := harnessx.DataAs[checkbase.ProbeResult](res)
	require.True(t, ok)
	assert.True(t, pr.Vulnerable)
}

func TestSendProbe_ClientDoError_ReturnsError(t *testing.T) {
	srv := httptest.NewServer(assertHandler(200))
	srv.Close() // closed server: connection refused

	store := harnessx.NewStaticResultStore(harnessx.ResultData(checkbase.CheckIDBaseline, harnessx.Snapshot{StatusCode: 200}))
	_, err := checkbase.SendProbe(context.Background(), probe.New(), srv.URL, "tok", checkbase.DefaultTokenLocation(), store)
	assert.Error(t, err)
}

func TestSendToken_ErrSet_ReturnsErrResultWithoutProbing(t *testing.T) {
	pctx := &checkbase.ProbeCtx{}
	target := harnessx.Target{Data: pctx}
	wantErr := assert.AnError

	res, err := checkbase.SendToken(context.Background(), target, harnessx.NewStaticResultStore(), "", wantErr)
	require.NoError(t, err)
	assert.ErrorIs(t, res.Err, wantErr)
}

func TestSendToken_UsesProbeCtxNewRequest(t *testing.T) {
	var gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		w.WriteHeader(200)
	}))
	defer srv.Close()

	build := func(ctx context.Context, token string) (*http.Request, error) {
		return http.NewRequestWithContext(ctx, http.MethodPost, srv.URL+"/x", strings.NewReader("tok="+token))
	}
	pctx := &checkbase.ProbeCtx{
		Probe:         probe.New(),
		TokenLocation: checkbase.DefaultTokenLocation(),
		NewRequest:    build,
	}
	store := harnessx.NewStaticResultStore(harnessx.ResultData(checkbase.CheckIDBaseline, harnessx.Snapshot{StatusCode: 401}))
	target := harnessx.Target{URL: srv.URL, Data: pctx}

	res, err := checkbase.SendToken(context.Background(), target, store, "tok", nil)
	require.NoError(t, err)
	assert.Equal(t, http.MethodPost, gotMethod)
	pr, ok := harnessx.DataAs[checkbase.ProbeResult](res)
	require.True(t, ok)
	assert.True(t, pr.Vulnerable)
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
