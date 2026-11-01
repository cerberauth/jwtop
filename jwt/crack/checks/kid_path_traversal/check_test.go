package kidpathtraversal_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/probe"
	jwtlib "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cerberauth/jwtop/jwt/crack/checkbase"
	kidpathtraversal "github.com/cerberauth/jwtop/jwt/crack/checks/kid_path_traversal"
	"github.com/cerberauth/jwtop/jwt/exploit"
)

func makeHS256Token(t *testing.T, secret string) string {
	t.Helper()
	tok := jwtlib.NewWithClaims(jwtlib.SigningMethodHS256, jwtlib.MapClaims{"sub": "user1"})
	s, err := tok.SignedString([]byte(secret))
	require.NoError(t, err)
	return s
}

// decodedKid returns the kid header claim of a forged token, for asserting
// which payload a check actually signed.
func decodedKid(t *testing.T, token string) string {
	t.Helper()
	parts := strings.SplitN(token, ".", 3)
	require.Len(t, parts, 3)
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	require.NoError(t, err)
	var header struct {
		Kid string `json:"kid"`
	}
	require.NoError(t, json.Unmarshal(raw, &header))
	return header.Kid
}

func TestCheck_HasOneVariantPerKidPathTraversalVariant(t *testing.T) {
	assert.Equal(t, exploit.KidPathTraversalVariants, kidpathtraversal.Check.Variants)
}

func TestCheck_Skip_Offline(t *testing.T) {
	store := harnessx.NewStaticResultStore()
	target := harnessx.Target{Data: &checkbase.ProbeCtx{Offline: true}}

	reason := kidpathtraversal.Check.Skip.Eval(context.Background(), target, store)
	assert.NotEmpty(t, reason)
}

func TestCheck_Skip_BlankSecretAlreadyVulnerable(t *testing.T) {
	store := harnessx.NewStaticResultStore(
		harnessx.ResultData("blanksecret", checkbase.ProbeResult{Vulnerable: true}),
	)
	target := harnessx.Target{Data: &checkbase.ProbeCtx{Offline: false}}

	reason := kidpathtraversal.Check.Skip.Eval(context.Background(), target, store)
	assert.NotEmpty(t, reason)
}

func TestCheck_Skip_RunsWhenOnlineAndNoBlankSecret(t *testing.T) {
	store := harnessx.NewStaticResultStore(
		harnessx.ResultData("blanksecret", checkbase.ProbeResult{Vulnerable: false}),
	)
	target := harnessx.Target{Data: &checkbase.ProbeCtx{Offline: false}}

	reason := kidpathtraversal.Check.Skip.Eval(context.Background(), target, store)
	assert.Empty(t, reason)
}

func TestCheck_RunVariant_OfflineReturnsEmptyResult(t *testing.T) {
	store := harnessx.NewStaticResultStore()
	target := harnessx.Target{Data: &checkbase.ProbeCtx{Offline: true}}

	result, err := kidpathtraversal.Check.RunVariant(context.Background(), target, exploit.DefaultKidPathTraversalPayload, store)
	assert.NoError(t, err)
	_, ok := harnessx.DataAs[checkbase.ProbeResult](result)
	assert.False(t, ok)
}

func TestCheck_RunVariant_Online_SendsForgedTokenPerVariant(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	pctx := &checkbase.ProbeCtx{
		TokenString:   makeHS256Token(t, "secret"),
		Probe:         probe.New(),
		TokenLocation: checkbase.DefaultTokenLocation(),
	}
	store := harnessx.NewStaticResultStore(harnessx.ResultData(checkbase.CheckIDBaseline, harnessx.Snapshot{StatusCode: 401}))
	target := harnessx.Target{URL: srv.URL, Data: pctx}

	result, err := kidpathtraversal.Check.RunVariant(context.Background(), target, "../../dev/null", store)
	require.NoError(t, err)
	pr, ok := harnessx.DataAs[checkbase.ProbeResult](result)
	require.True(t, ok)
	assert.True(t, pr.Vulnerable)
}

func TestCheck_RunVariant_CustomKidPathOverride_OnlyRunsOnFirstVariantSlot(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	pctx := &checkbase.ProbeCtx{
		TokenString:   makeHS256Token(t, "secret"),
		Probe:         probe.New(),
		TokenLocation: checkbase.DefaultTokenLocation(),
		KidPath:       "/etc/passwd",
	}
	store := harnessx.NewStaticResultStore(harnessx.ResultData(checkbase.CheckIDBaseline, harnessx.Snapshot{StatusCode: 401}))
	target := harnessx.Target{URL: srv.URL, Data: pctx}

	// Non-first variant slots are skipped so the custom override isn't
	// probed once per default variant.
	result, err := kidpathtraversal.Check.RunVariant(context.Background(), target, exploit.KidPathTraversalVariants[1], store)
	require.NoError(t, err)
	_, ok := harnessx.DataAs[checkbase.ProbeResult](result)
	assert.False(t, ok)

	// The first variant slot carries the custom path.
	result, err = kidpathtraversal.Check.RunVariant(context.Background(), target, exploit.KidPathTraversalVariants[0], store)
	require.NoError(t, err)
	pr, ok := harnessx.DataAs[checkbase.ProbeResult](result)
	require.True(t, ok)
	assert.Equal(t, "/etc/passwd", decodedKid(t, pr.Payload))
}
