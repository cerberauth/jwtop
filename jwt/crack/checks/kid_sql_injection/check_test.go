package kidsqlinjection_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/probe"
	jwtlib "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cerberauth/jwtop/jwt/crack/checkbase"
	kidsqlinjection "github.com/cerberauth/jwtop/jwt/crack/checks/kid_sql_injection"
	"github.com/cerberauth/jwtop/jwt/exploit"
)

func makeHS256Token(t *testing.T, secret string) string {
	t.Helper()
	tok := jwtlib.NewWithClaims(jwtlib.SigningMethodHS256, jwtlib.MapClaims{"sub": "user1"})
	s, err := tok.SignedString([]byte(secret))
	require.NoError(t, err)
	return s
}

// baselineStore seeds a static result store with the given baseline status,
// as SendProbe/ProbeAndCompareBaseline require one to be present.
func baselineStore(status int) harnessx.ResultStore {
	return harnessx.NewStaticResultStore(harnessx.ResultData(checkbase.CheckIDBaseline, harnessx.Snapshot{StatusCode: status}))
}

func TestCheck_Skip_Offline(t *testing.T) {
	store := harnessx.NewStaticResultStore()
	target := harnessx.Target{Data: &checkbase.ProbeCtx{Offline: true}}

	reason := kidsqlinjection.Check.Skip.Eval(context.Background(), target, store)
	assert.NotEmpty(t, reason)
}

func TestCheck_Skip_WeakSecretAlreadyVulnerable(t *testing.T) {
	store := harnessx.NewStaticResultStore(
		harnessx.ResultData("secret", checkbase.ProbeResult{Vulnerable: true}),
	)
	target := harnessx.Target{Data: &checkbase.ProbeCtx{Offline: false}}

	reason := kidsqlinjection.Check.Skip.Eval(context.Background(), target, store)
	assert.NotEmpty(t, reason)
}

func TestCheck_Skip_RunsWhenOnlineAndNoWeakSecret(t *testing.T) {
	store := harnessx.NewStaticResultStore(
		harnessx.ResultData("secret", checkbase.ProbeResult{Vulnerable: false}),
	)
	target := harnessx.Target{Data: &checkbase.ProbeCtx{Offline: false}}

	reason := kidsqlinjection.Check.Skip.Eval(context.Background(), target, store)
	assert.Empty(t, reason)
}

func TestCheck_Run_StopsAtFirstVulnerableTable_ReportsItInExtra(t *testing.T) {
	token := makeHS256Token(t, "secret")
	const workingTable = "right_table"
	workingToken, err := exploit.KidSQLInjection(token, exploit.BuildKidSQLPayload(workingTable), []byte("secret"))
	require.NoError(t, err)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "Bearer "+workingToken {
			w.WriteHeader(200)
		} else {
			w.WriteHeader(401)
		}
	}))
	defer srv.Close()

	pctx := &checkbase.ProbeCtx{
		TokenString:   token,
		Probe:         probe.New(),
		TokenLocation: checkbase.DefaultTokenLocation(),
		KidSQLTables:  []string{"wrong_table", workingTable, "unreached_table"},
	}
	target := harnessx.Target{URL: srv.URL, Data: pctx}

	result, err := kidsqlinjection.Check.Run(context.Background(), target, baselineStore(401))
	require.NoError(t, err)
	pr, ok := harnessx.DataAs[checkbase.ProbeResult](result)
	require.True(t, ok)
	assert.True(t, pr.Vulnerable)
	assert.Contains(t, pr.Extra, workingTable)
}

func TestCheck_Run_NoTableWorks_ReturnsNotVulnerableNoError(t *testing.T) {
	token := makeHS256Token(t, "secret")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(401)
	}))
	defer srv.Close()

	pctx := &checkbase.ProbeCtx{
		TokenString:   token,
		Probe:         probe.New(),
		TokenLocation: checkbase.DefaultTokenLocation(),
		KidSQLTables:  []string{"table_a", "table_b"},
	}
	target := harnessx.Target{URL: srv.URL, Data: pctx}

	result, err := kidsqlinjection.Check.Run(context.Background(), target, baselineStore(401))
	require.NoError(t, err)
	pr, ok := harnessx.DataAs[checkbase.ProbeResult](result)
	require.True(t, ok)
	assert.False(t, pr.Vulnerable)
}

func TestCheck_Run_DeprecatedKidSQLTable_SeedsSingleCandidate(t *testing.T) {
	token := makeHS256Token(t, "secret")
	legacyToken, err := exploit.KidSQLInjection(token, exploit.BuildKidSQLPayload("legacy_table"), []byte("secret"))
	require.NoError(t, err)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "Bearer "+legacyToken {
			w.WriteHeader(200)
		} else {
			w.WriteHeader(401)
		}
	}))
	defer srv.Close()

	pctx := &checkbase.ProbeCtx{
		TokenString:   token,
		Probe:         probe.New(),
		TokenLocation: checkbase.DefaultTokenLocation(),
		KidSQLTable:   "legacy_table",
	}
	target := harnessx.Target{URL: srv.URL, Data: pctx}

	result, err := kidsqlinjection.Check.Run(context.Background(), target, baselineStore(401))
	require.NoError(t, err)
	pr, ok := harnessx.DataAs[checkbase.ProbeResult](result)
	require.True(t, ok)
	assert.True(t, pr.Vulnerable)
	assert.Contains(t, pr.Extra, "legacy_table")
}

func TestCheck_Run_NeitherTableFieldSet_DefaultsToDefaultKidSQLTable(t *testing.T) {
	token := makeHS256Token(t, "secret")
	defaultToken, err := exploit.KidSQLInjection(token, exploit.DefaultKidSQLPayload, []byte("secret"))
	require.NoError(t, err)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "Bearer "+defaultToken {
			w.WriteHeader(200)
		} else {
			w.WriteHeader(401)
		}
	}))
	defer srv.Close()

	pctx := &checkbase.ProbeCtx{
		TokenString:   token,
		Probe:         probe.New(),
		TokenLocation: checkbase.DefaultTokenLocation(),
	}
	target := harnessx.Target{URL: srv.URL, Data: pctx}

	result, err := kidsqlinjection.Check.Run(context.Background(), target, baselineStore(401))
	require.NoError(t, err)
	pr, ok := harnessx.DataAs[checkbase.ProbeResult](result)
	require.True(t, ok)
	assert.True(t, pr.Vulnerable)
}

func TestCheck_Run_InvalidTokenString_ReturnsErrInResult(t *testing.T) {
	pctx := &checkbase.ProbeCtx{
		TokenString:   "not-a-valid-jwt",
		Probe:         probe.New(),
		TokenLocation: checkbase.DefaultTokenLocation(),
	}
	target := harnessx.Target{URL: "http://127.0.0.1:0", Data: pctx}

	result, err := kidsqlinjection.Check.Run(context.Background(), target, baselineStore(401))
	require.NoError(t, err)
	assert.Error(t, result.Err)
}

func TestCheck_Run_ProbeTransportError_ReturnsError(t *testing.T) {
	// Port 0 on an address nothing listens on: the probe's HTTP request
	// fails at the transport level rather than getting any response.
	pctx := &checkbase.ProbeCtx{
		TokenString:   makeHS256Token(t, "secret"),
		Probe:         probe.New(),
		TokenLocation: checkbase.DefaultTokenLocation(),
	}
	target := harnessx.Target{URL: "http://127.0.0.1:0", Data: pctx}

	_, err := kidsqlinjection.Check.Run(context.Background(), target, baselineStore(401))
	assert.Error(t, err)
}
