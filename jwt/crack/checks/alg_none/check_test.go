package algnone_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/probe"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	algnone "github.com/cerberauth/jwtop/jwt/crack/checks/alg_none"
	"github.com/cerberauth/jwtop/jwt/crack/checkbase"
	"github.com/cerberauth/jwtop/jwt/exploit"
)

func TestCheck_HasOneVariantPerAlgNoneVariant(t *testing.T) {
	assert.Equal(t, exploit.AlgNoneVariants, algnone.Check.Variants)
}

func TestCheck_Skip_EmptyWhenTokenAlreadyAlgNone(t *testing.T) {
	store := harnessx.NewStaticResultStore()
	target := harnessx.Target{Data: &checkbase.ProbeCtx{Alg: "none"}}

	reason := algnone.Check.Skip.Eval(context.Background(), target, store)
	assert.Empty(t, reason)
}

func TestCheck_Skip_OfflineWhenTokenNotAlgNone(t *testing.T) {
	store := harnessx.NewStaticResultStore()
	target := harnessx.Target{Data: &checkbase.ProbeCtx{Alg: "HS256", Offline: true}}

	reason := algnone.Check.Skip.Eval(context.Background(), target, store)
	assert.NotEmpty(t, reason)
}

func TestCheck_Skip_RunsOnlineWhenTokenNotAlgNone(t *testing.T) {
	store := harnessx.NewStaticResultStore()
	target := harnessx.Target{Data: &checkbase.ProbeCtx{Alg: "HS256", Offline: false}}

	reason := algnone.Check.Skip.Eval(context.Background(), target, store)
	assert.Empty(t, reason)
}

func TestCheck_RunVariant_VulnerableWhenTokenAlreadyAlgNone(t *testing.T) {
	store := harnessx.NewStaticResultStore()
	target := harnessx.Target{Data: &checkbase.ProbeCtx{Alg: "none"}}

	result, err := algnone.Check.RunVariant(context.Background(), target, "none", store)
	assert.NoError(t, err)
	pr, ok := harnessx.DataAs[checkbase.ProbeResult](result)
	assert.True(t, ok)
	assert.True(t, pr.Vulnerable)
}

func TestCheck_RunVariant_NotVulnerableForOtherVariantsWhenTokenAlreadyAlgNone(t *testing.T) {
	store := harnessx.NewStaticResultStore()
	target := harnessx.Target{Data: &checkbase.ProbeCtx{Alg: "none", Offline: true}}

	result, err := algnone.Check.RunVariant(context.Background(), target, "NONE", store)
	assert.NoError(t, err)
	_, ok := harnessx.DataAs[checkbase.ProbeResult](result)
	assert.False(t, ok, "only the canonical 'none' variant reports the already-alg-none finding")
}

func TestCheck_RunVariant_ReturnsErrorFromAlgNoneGeneration(t *testing.T) {
	store := harnessx.NewStaticResultStore()
	wantErr := assert.AnError
	target := harnessx.Target{Data: &checkbase.ProbeCtx{Alg: "HS256", AlgNoneErr: wantErr}}

	result, err := algnone.Check.RunVariant(context.Background(), target, "none", store)
	assert.NoError(t, err)
	assert.Equal(t, wantErr, result.Err)
}

func TestCheck_RunVariant_OfflineNonMatchingVariant_ReturnsEmptyResult(t *testing.T) {
	store := harnessx.NewStaticResultStore()
	target := harnessx.Target{Data: &checkbase.ProbeCtx{Alg: "HS256", Offline: true}}

	result, err := algnone.Check.RunVariant(context.Background(), target, "NONE", store)
	assert.NoError(t, err)
	_, ok := harnessx.DataAs[checkbase.ProbeResult](result)
	assert.False(t, ok)
}

func TestCheck_RunVariant_Online_SendsForgedTokenForVariant(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	pctx := &checkbase.ProbeCtx{
		Alg:           "HS256",
		Probe:         probe.New(),
		TokenLocation: checkbase.DefaultTokenLocation(),
		AlgNoneTokens: []string{"tok-none", "tok-NONE", "tok-None", "tok-nOnE"},
	}
	store := harnessx.NewStaticResultStore(harnessx.ResultData(checkbase.CheckIDBaseline, harnessx.Snapshot{StatusCode: 401}))
	target := harnessx.Target{URL: srv.URL, Data: pctx}

	result, err := algnone.Check.RunVariant(context.Background(), target, "NONE", store)
	require.NoError(t, err)
	pr, ok := harnessx.DataAs[checkbase.ProbeResult](result)
	require.True(t, ok)
	assert.Equal(t, "tok-NONE", pr.Payload)
	assert.True(t, pr.Vulnerable)
}
