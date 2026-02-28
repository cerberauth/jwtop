package crack_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	jwtlib "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cerberauth/jwtop/jwt/crack"
	"github.com/cerberauth/jwtop/jwt/exploit"
)

func makeHS256Token(t *testing.T, secret string) string {
	t.Helper()
	tok := jwtlib.NewWithClaims(jwtlib.SigningMethodHS256, jwtlib.MapClaims{"sub": "user1"})
	s, err := tok.SignedString([]byte(secret))
	require.NoError(t, err)
	return s
}

func makeRS256Token(t *testing.T) (string, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	tok := jwtlib.NewWithClaims(jwtlib.SigningMethodRS256, jwtlib.MapClaims{"sub": "user1"})
	s, err := tok.SignedString(key)
	require.NoError(t, err)
	return s, key
}

func makeES256Token(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tok := jwtlib.NewWithClaims(jwtlib.SigningMethodES256, jwtlib.MapClaims{"sub": "user1"})
	s, err := tok.SignedString(key)
	require.NoError(t, err)
	return s
}

func rsaPublicKeyPEM(t *testing.T, key *rsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

func staticServer(status int) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
	}))
}

func findResult(results []crack.ProbeResult, name string) (crack.ProbeResult, bool) {
	for _, r := range results {
		if r.Name == name {
			return r, true
		}
	}
	return crack.ProbeResult{}, false
}

func findResultPrefix(results []crack.ProbeResult, prefix string) []crack.ProbeResult {
	var out []crack.ProbeResult
	for _, r := range results {
		if strings.HasPrefix(r.Name, prefix) {
			out = append(out, r)
		}
	}
	return out
}

func TestProbeAll_MalformedToken_ReturnsError(t *testing.T) {
	srv := staticServer(401)
	defer srv.Close()

	_, _, err := crack.ProbeAll(context.Background(), "not-a-jwt", crack.ProbeOptions{URL: srv.URL})
	assert.Error(t, err)
}

func TestProbeAll_BaselineProbeError_ReturnsError(t *testing.T) {
	token := makeHS256Token(t, "secret")
	_, _, err := crack.ProbeAll(context.Background(), token, crack.ProbeOptions{
		URL: "http://127.0.0.1:0",
	})
	assert.Error(t, err)
}

func TestProbeAll_NoVerification_NotVulnerable_When401(t *testing.T) {
	srv := staticServer(401)
	defer srv.Close()

	token := makeHS256Token(t, "secret")
	results, _, err := crack.ProbeAll(context.Background(), token, crack.ProbeOptions{URL: srv.URL})
	require.NoError(t, err)

	r, ok := findResult(results, "no_verification")
	require.True(t, ok)
	assert.False(t, r.Vulnerable)
	assert.Equal(t, 401, r.Status)
}

func TestProbeAll_NoVerification_Vulnerable_When200(t *testing.T) {
	srv := staticServer(200)
	defer srv.Close()

	token := makeHS256Token(t, "secret")
	results, _, err := crack.ProbeAll(context.Background(), token, crack.ProbeOptions{URL: srv.URL})
	require.NoError(t, err)

	r, ok := findResult(results, "no_verification")
	require.True(t, ok)
	assert.True(t, r.Vulnerable, "server accepts invalid JWTs → vulnerable")
}

func TestProbeAll_BaselineStatus_ReturnedCorrectly(t *testing.T) {
	srv := staticServer(403)
	defer srv.Close()

	token := makeHS256Token(t, "secret")
	_, baseline, err := crack.ProbeAll(context.Background(), token, crack.ProbeOptions{URL: srv.URL})
	require.NoError(t, err)
	assert.Equal(t, 403, baseline)
}

func TestProbeAll_WithExpectedStatus_SkipsAutoDetect(t *testing.T) {
	srv := staticServer(200)
	defer srv.Close()

	token := makeHS256Token(t, "secret")
	results, baseline, err := crack.ProbeAll(context.Background(), token, crack.ProbeOptions{
		URL:            srv.URL,
		ExpectedStatus: 401,
	})
	require.NoError(t, err)
	assert.Equal(t, 401, baseline, "baseline should be the provided ExpectedStatus")

	r, ok := findResult(results, "no_verification")
	require.True(t, ok)
	assert.False(t, r.Vulnerable, "no_verification checks baselineStatus < 400, not server response")

	algNone := findResultPrefix(results, "algnone")
	for _, ar := range algNone {
		assert.True(t, ar.Vulnerable, "algnone probe should be vulnerable when server returns 200 vs baseline 401")
	}
}

func TestProbeAll_AlgNone_ProducesOneResultPerVariant(t *testing.T) {
	srv := staticServer(401)
	defer srv.Close()

	token := makeHS256Token(t, "secret")
	results, _, err := crack.ProbeAll(context.Background(), token, crack.ProbeOptions{URL: srv.URL})
	require.NoError(t, err)

	algNone := findResultPrefix(results, "algnone")
	assert.Len(t, algNone, len(exploit.AlgNoneVariants))
}

func TestProbeAll_AlgNone_NotVulnerable_When401(t *testing.T) {
	srv := staticServer(401)
	defer srv.Close()

	token := makeHS256Token(t, "secret")
	results, _, err := crack.ProbeAll(context.Background(), token, crack.ProbeOptions{URL: srv.URL})
	require.NoError(t, err)

	for _, r := range findResultPrefix(results, "algnone") {
		assert.False(t, r.Vulnerable, "algnone %s should not be vulnerable when server returns 401", r.Name)
		assert.Nil(t, r.Err)
	}
}

func TestProbeAll_BlankSecret_ProbedForHMAC(t *testing.T) {
	srv := staticServer(401)
	defer srv.Close()

	token := makeHS256Token(t, "secret")
	results, _, err := crack.ProbeAll(context.Background(), token, crack.ProbeOptions{URL: srv.URL})
	require.NoError(t, err)

	r, ok := findResult(results, "blanksecret")
	require.True(t, ok)
	assert.False(t, r.Skipped, "blanksecret should be probed for HMAC tokens")
	assert.Nil(t, r.Err)
}

func TestProbeAll_BlankSecret_SkippedForAsymmetric(t *testing.T) {
	srv := staticServer(401)
	defer srv.Close()

	token, _ := makeRS256Token(t)
	results, _, err := crack.ProbeAll(context.Background(), token, crack.ProbeOptions{URL: srv.URL})
	require.NoError(t, err)

	r, ok := findResult(results, "blanksecret")
	require.True(t, ok)
	assert.True(t, r.Skipped)
	assert.Contains(t, r.SkipReason, "HMAC-only")
}

func TestProbeAll_NullSig_ProbedForAnyAlgorithm(t *testing.T) {
	srv := staticServer(401)
	defer srv.Close()

	for _, token := range []string{
		makeHS256Token(t, "secret"),
		func() string { s, _ := makeRS256Token(t); return s }(),
		makeES256Token(t),
	} {
		results, _, err := crack.ProbeAll(context.Background(), token, crack.ProbeOptions{URL: srv.URL})
		require.NoError(t, err)

		r, ok := findResult(results, "nullsig")
		require.True(t, ok)
		assert.False(t, r.Skipped, "nullsig should be probed for every algorithm")
		assert.Nil(t, r.Err)
	}
}

func TestProbeAll_HMACConfusion_SkippedForHMAC(t *testing.T) {
	srv := staticServer(401)
	defer srv.Close()

	token := makeHS256Token(t, "secret")
	results, _, err := crack.ProbeAll(context.Background(), token, crack.ProbeOptions{URL: srv.URL})
	require.NoError(t, err)

	r, ok := findResult(results, "hmacconfusion")
	require.True(t, ok)
	assert.True(t, r.Skipped)
	assert.Contains(t, r.SkipReason, "not applicable")
}

func TestProbeAll_HMACConfusion_SkippedWhenNoPublicKey(t *testing.T) {
	srv := staticServer(401)
	defer srv.Close()

	token, _ := makeRS256Token(t)
	results, _, err := crack.ProbeAll(context.Background(), token, crack.ProbeOptions{
		URL: srv.URL,
	})
	require.NoError(t, err)

	r, ok := findResult(results, "hmacconfusion")
	require.True(t, ok)
	assert.True(t, r.Skipped)
	assert.Contains(t, r.SkipReason, "no public key")
}

func TestProbeAll_HMACConfusion_ProbedWhenPublicKeyProvided(t *testing.T) {
	srv := staticServer(401)
	defer srv.Close()

	token, key := makeRS256Token(t)
	results, _, err := crack.ProbeAll(context.Background(), token, crack.ProbeOptions{
		URL:          srv.URL,
		PublicKeyPEM: rsaPublicKeyPEM(t, key),
	})
	require.NoError(t, err)

	r, ok := findResult(results, "hmacconfusion")
	require.True(t, ok)
	assert.False(t, r.Skipped)
	assert.Nil(t, r.Err)
}

func TestProbeAll_HMACConfusion_SkippedForES256(t *testing.T) {
	srv := staticServer(401)
	defer srv.Close()

	token := makeES256Token(t)
	results, _, err := crack.ProbeAll(context.Background(), token, crack.ProbeOptions{URL: srv.URL})
	require.NoError(t, err)

	r, ok := findResult(results, "hmacconfusion")
	require.True(t, ok)
	assert.True(t, r.Skipped)
	assert.Contains(t, r.SkipReason, "no public key")
}

func TestProbeAll_KidInjection_SQL_Probed(t *testing.T) {
	srv := staticServer(401)
	defer srv.Close()

	token := makeHS256Token(t, "secret")
	results, _, err := crack.ProbeAll(context.Background(), token, crack.ProbeOptions{URL: srv.URL})
	require.NoError(t, err)

	r, ok := findResult(results, "kidinjection (sql)")
	require.True(t, ok)
	assert.False(t, r.Skipped)
	assert.Nil(t, r.Err)
}

func TestProbeAll_KidInjection_Path_Probed(t *testing.T) {
	srv := staticServer(401)
	defer srv.Close()

	token := makeHS256Token(t, "secret")
	results, _, err := crack.ProbeAll(context.Background(), token, crack.ProbeOptions{URL: srv.URL})
	require.NoError(t, err)

	r, ok := findResult(results, "kidinjection (path)")
	require.True(t, ok)
	assert.False(t, r.Skipped)
	assert.Nil(t, r.Err)
}

func TestProbeAll_Secret_SkippedForAsymmetric(t *testing.T) {
	srv := staticServer(401)
	defer srv.Close()

	token, _ := makeRS256Token(t)
	results, _, err := crack.ProbeAll(context.Background(), token, crack.ProbeOptions{
		URL:        srv.URL,
		Candidates: []string{"secret"},
	})
	require.NoError(t, err)

	r, ok := findResult(results, "secret")
	require.True(t, ok)
	assert.True(t, r.Skipped)
	assert.Contains(t, r.SkipReason, "HMAC-only")
}

func TestProbeAll_Secret_SkippedWhenNoCandidates(t *testing.T) {
	srv := staticServer(401)
	defer srv.Close()

	token := makeHS256Token(t, "secret")
	results, _, err := crack.ProbeAll(context.Background(), token, crack.ProbeOptions{
		URL: srv.URL,
	})
	require.NoError(t, err)

	r, ok := findResult(results, "secret")
	require.True(t, ok)
	assert.True(t, r.Skipped)
	assert.Contains(t, r.SkipReason, "not found")
}

func TestProbeAll_Secret_SkippedWhenNotInCandidates(t *testing.T) {
	srv := staticServer(401)
	defer srv.Close()

	token := makeHS256Token(t, "supersecret")
	results, _, err := crack.ProbeAll(context.Background(), token, crack.ProbeOptions{
		URL:        srv.URL,
		Candidates: []string{"wrong", "also-wrong"},
	})
	require.NoError(t, err)

	r, ok := findResult(results, "secret")
	require.True(t, ok)
	assert.True(t, r.Skipped)
	assert.Contains(t, r.SkipReason, "not found")
}

func TestProbeAll_Secret_ProbedWhenSecretFound(t *testing.T) {
	srv := staticServer(401)
	defer srv.Close()

	const secret = "hunter2"
	token := makeHS256Token(t, secret)
	results, _, err := crack.ProbeAll(context.Background(), token, crack.ProbeOptions{
		URL:        srv.URL,
		Candidates: []string{"wrong", secret, "also-wrong"},
	})
	require.NoError(t, err)

	r, ok := findResult(results, "secret")
	require.True(t, ok)
	assert.False(t, r.Skipped, "secret probe should not be skipped when secret is found")
	assert.Nil(t, r.Err)
	assert.Contains(t, r.Extra, secret, "Extra field should contain the found secret")
}

func TestProbeAll_HMAC_ResultNames(t *testing.T) {
	srv := staticServer(401)
	defer srv.Close()

	token := makeHS256Token(t, "secret")
	results, _, err := crack.ProbeAll(context.Background(), token, crack.ProbeOptions{URL: srv.URL})
	require.NoError(t, err)

	names := make([]string, len(results))
	for i, r := range results {
		names[i] = r.Name
	}

	require.Contains(t, names, "no_verification")
	require.Contains(t, names, "blanksecret")
	require.Contains(t, names, "nullsig")
	require.Contains(t, names, "hmacconfusion")
	require.Contains(t, names, "kidinjection (sql)")
	require.Contains(t, names, "kidinjection (path)")
	require.Contains(t, names, "secret")

	algNone := findResultPrefix(results, "algnone")
	assert.Len(t, algNone, len(exploit.AlgNoneVariants))
}

func TestProbeAll_Asymmetric_ResultNames(t *testing.T) {
	srv := staticServer(401)
	defer srv.Close()

	token, _ := makeRS256Token(t)
	results, _, err := crack.ProbeAll(context.Background(), token, crack.ProbeOptions{URL: srv.URL})
	require.NoError(t, err)

	names := make([]string, len(results))
	for i, r := range results {
		names[i] = r.Name
	}

	require.Contains(t, names, "no_verification")
	require.Contains(t, names, "blanksecret")
	require.Contains(t, names, "nullsig")
	require.Contains(t, names, "hmacconfusion")
	require.Contains(t, names, "kidinjection (sql)")
	require.Contains(t, names, "kidinjection (path)")
	require.Contains(t, names, "secret")
}

func TestProbeAll_CancelledContext_ReturnsError(t *testing.T) {
	srv := staticServer(401)
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	token := makeHS256Token(t, "secret")
	_, _, err := crack.ProbeAll(ctx, token, crack.ProbeOptions{URL: srv.URL})
	assert.Error(t, err, "cancelled context should propagate as an error")
}
