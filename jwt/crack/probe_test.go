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

func makeBlankSecretToken(t *testing.T) string {
	t.Helper()
	tok := jwtlib.NewWithClaims(jwtlib.SigningMethodHS256, jwtlib.MapClaims{"sub": "user1"})
	s, err := tok.SignedString([]byte(""))
	require.NoError(t, err)
	return s
}

func makeAlgNoneToken(t *testing.T) string {
	t.Helper()
	tok := jwtlib.NewWithClaims(jwtlib.SigningMethodNone, jwtlib.MapClaims{"sub": "user1"})
	s, err := tok.SignedString(jwtlib.UnsafeAllowNoneSignatureType)
	require.NoError(t, err)
	return s
}

func makeNullSigToken(t *testing.T) string {
	t.Helper()
	parts := strings.SplitN(makeHS256Token(t, "secret"), ".", 3)
	return parts[0] + "." + parts[1] + "."
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

// tokenAwareServer returns validStatus for the original token and rejectedStatus
// for all other requests, mirroring real server behaviour.
func tokenAwareServer(token string, validStatus, rejectedStatus int) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "Bearer "+token {
			w.WriteHeader(validStatus)
		} else {
			w.WriteHeader(rejectedStatus)
		}
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

func TestProbeAll_AlreadyRejectedToken_AutoDetectsBaseline(t *testing.T) {
	srv := staticServer(401)
	defer srv.Close()

	token := makeHS256Token(t, "secret")
	_, baseline, err := crack.ProbeAll(context.Background(), token, crack.ProbeOptions{URL: srv.URL})
	require.NoError(t, err)
	assert.Equal(t, 401, baseline)
}

func TestProbeAll_AlreadyRejectedToken_WithExpectedStatus_Succeeds(t *testing.T) {
	srv := staticServer(401)
	defer srv.Close()

	token := makeHS256Token(t, "secret")
	_, baseline, err := crack.ProbeAll(context.Background(), token, crack.ProbeOptions{
		URL:            srv.URL,
		ExpectedStatus: 401,
	})
	require.NoError(t, err)
	assert.Equal(t, 401, baseline)
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
	token := makeHS256Token(t, "secret")
	srv := tokenAwareServer(token, 200, 401)
	defer srv.Close()

	results, _, err := crack.ProbeAll(context.Background(), token, crack.ProbeOptions{URL: srv.URL})
	require.NoError(t, err)

	r, ok := findResult(results, "No Verification")
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

	r, ok := findResult(results, "No Verification")
	require.True(t, ok)
	assert.True(t, r.Vulnerable, "server accepts invalid JWTs → vulnerable")
}

func TestProbeAll_BaselineStatus_ReturnedCorrectly(t *testing.T) {
	token := makeHS256Token(t, "secret")
	srv := tokenAwareServer(token, 200, 403)
	defer srv.Close()

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

	r, ok := findResult(results, "No Verification")
	require.True(t, ok)
	assert.False(t, r.Vulnerable, "no_verification checks baselineStatus < 400, not server response")

	// Both nullsig and algnone forge the token independently and probe the
	// live server — an over-permissive server that accepts everything is a
	// genuine finding for each, so neither suppresses the other.
	nullsig, ok := findResult(results, "Null Signature")
	require.True(t, ok)
	assert.True(t, nullsig.Vulnerable, "nullsig probe should be vulnerable when server returns 200 vs baseline 401")

	algNone := findResultPrefix(results, "Algorithm None (")
	for _, ar := range algNone {
		assert.False(t, ar.Skipped, "algnone should still be probed for a non-none input token")
		assert.True(t, ar.Vulnerable, "algnone probe should be vulnerable when server returns 200 vs baseline 401")
	}
}

func TestProbeAll_AlgNone_ProducesOneResultPerVariant(t *testing.T) {
	token := makeHS256Token(t, "secret")
	srv := tokenAwareServer(token, 200, 401)
	defer srv.Close()

	results, _, err := crack.ProbeAll(context.Background(), token, crack.ProbeOptions{URL: srv.URL})
	require.NoError(t, err)

	algNone := findResultPrefix(results, "Algorithm None (")
	assert.Len(t, algNone, len(exploit.AlgNoneVariants))
}

func TestProbeAll_AlgNone_NotVulnerable_When401(t *testing.T) {
	token := makeHS256Token(t, "secret")
	srv := tokenAwareServer(token, 200, 401)
	defer srv.Close()

	results, _, err := crack.ProbeAll(context.Background(), token, crack.ProbeOptions{URL: srv.URL})
	require.NoError(t, err)

	for _, r := range findResultPrefix(results, "Algorithm None (") {
		assert.False(t, r.Vulnerable, "algnone %s should not be vulnerable when server returns 401", r.Name)
		assert.Nil(t, r.Err)
	}
}

func TestProbeAll_BlankSecret_ProbedForHMAC(t *testing.T) {
	token := makeHS256Token(t, "secret")
	srv := tokenAwareServer(token, 200, 401)
	defer srv.Close()

	results, _, err := crack.ProbeAll(context.Background(), token, crack.ProbeOptions{URL: srv.URL})
	require.NoError(t, err)

	r, ok := findResult(results, "Blank Secret")
	require.True(t, ok)
	assert.False(t, r.Skipped, "blanksecret should be probed for HMAC tokens")
	assert.Nil(t, r.Err)
}

func TestProbeAll_BlankSecret_SkippedForAsymmetric(t *testing.T) {
	token, _ := makeRS256Token(t)
	srv := tokenAwareServer(token, 200, 401)
	defer srv.Close()

	results, _, err := crack.ProbeAll(context.Background(), token, crack.ProbeOptions{URL: srv.URL})
	require.NoError(t, err)

	r, ok := findResult(results, "Blank Secret")
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
		results, _, err := crack.ProbeAll(context.Background(), token, crack.ProbeOptions{URL: srv.URL, ExpectedStatus: 401})
		require.NoError(t, err)

		r, ok := findResult(results, "Null Signature")
		require.True(t, ok)
		assert.False(t, r.Skipped, "nullsig should be probed for every algorithm")
		assert.Nil(t, r.Err)
	}
}

func TestProbeAll_HMACConfusion_SkippedForHMAC(t *testing.T) {
	token := makeHS256Token(t, "secret")
	srv := tokenAwareServer(token, 200, 401)
	defer srv.Close()

	results, _, err := crack.ProbeAll(context.Background(), token, crack.ProbeOptions{URL: srv.URL})
	require.NoError(t, err)

	r, ok := findResult(results, "HMAC Confusion")
	require.True(t, ok)
	assert.True(t, r.Skipped)
	assert.Contains(t, r.SkipReason, "not applicable")
}

func TestProbeAll_HMACConfusion_SkippedWhenNoPublicKey(t *testing.T) {
	token, _ := makeRS256Token(t)
	srv := tokenAwareServer(token, 200, 401)
	defer srv.Close()

	results, _, err := crack.ProbeAll(context.Background(), token, crack.ProbeOptions{
		URL: srv.URL,
	})
	require.NoError(t, err)

	r, ok := findResult(results, "HMAC Confusion")
	require.True(t, ok)
	assert.True(t, r.Skipped)
	assert.Contains(t, r.SkipReason, "no public key")
}

func TestProbeAll_HMACConfusion_ProbedWhenPublicKeyProvided(t *testing.T) {
	token, key := makeRS256Token(t)
	srv := tokenAwareServer(token, 200, 401)
	defer srv.Close()

	results, _, err := crack.ProbeAll(context.Background(), token, crack.ProbeOptions{
		URL:          srv.URL,
		PublicKeyPEM: rsaPublicKeyPEM(t, key),
	})
	require.NoError(t, err)

	r, ok := findResult(results, "HMAC Confusion")
	require.True(t, ok)
	assert.False(t, r.Skipped)
	assert.Nil(t, r.Err)
}

func TestProbeAll_HMACConfusion_SkippedForES256(t *testing.T) {
	token := makeES256Token(t)
	srv := tokenAwareServer(token, 200, 401)
	defer srv.Close()

	results, _, err := crack.ProbeAll(context.Background(), token, crack.ProbeOptions{URL: srv.URL})
	require.NoError(t, err)

	r, ok := findResult(results, "HMAC Confusion")
	require.True(t, ok)
	assert.True(t, r.Skipped)
	assert.Contains(t, r.SkipReason, "no public key")
}

func TestProbeAll_KidInjection_SQL_Probed(t *testing.T) {
	token := makeHS256Token(t, "secret")
	srv := tokenAwareServer(token, 200, 401)
	defer srv.Close()

	results, _, err := crack.ProbeAll(context.Background(), token, crack.ProbeOptions{URL: srv.URL})
	require.NoError(t, err)

	r, ok := findResult(results, "KID SQL Injection")
	require.True(t, ok)
	assert.False(t, r.Skipped)
	assert.Nil(t, r.Err)
}

func TestProbeAll_KidInjection_Path_Probed(t *testing.T) {
	token := makeHS256Token(t, "secret")
	srv := tokenAwareServer(token, 200, 401)
	defer srv.Close()

	results, _, err := crack.ProbeAll(context.Background(), token, crack.ProbeOptions{URL: srv.URL})
	require.NoError(t, err)

	r, ok := findResult(results, "KID Path Traversal")
	require.True(t, ok)
	assert.False(t, r.Skipped)
	assert.Nil(t, r.Err)
}

func TestProbeAll_Secret_SkippedForAsymmetric(t *testing.T) {
	token, _ := makeRS256Token(t)
	srv := tokenAwareServer(token, 200, 401)
	defer srv.Close()

	results, _, err := crack.ProbeAll(context.Background(), token, crack.ProbeOptions{
		URL:        srv.URL,
		Candidates: []string{"secret"},
	})
	require.NoError(t, err)

	r, ok := findResult(results, "Weak Secret")
	require.True(t, ok)
	assert.True(t, r.Skipped)
	assert.Contains(t, r.SkipReason, "HMAC-only")
}

func TestProbeAll_Secret_SkippedWhenNoCandidates(t *testing.T) {
	token := makeHS256Token(t, "secret")
	srv := tokenAwareServer(token, 200, 401)
	defer srv.Close()

	results, _, err := crack.ProbeAll(context.Background(), token, crack.ProbeOptions{
		URL: srv.URL,
	})
	require.NoError(t, err)

	r, ok := findResult(results, "Weak Secret")
	require.True(t, ok)
	assert.True(t, r.Skipped)
	assert.Contains(t, r.SkipReason, "not found")
}

func TestProbeAll_Secret_SkippedWhenNotInCandidates(t *testing.T) {
	token := makeHS256Token(t, "supersecret")
	srv := tokenAwareServer(token, 200, 401)
	defer srv.Close()

	results, _, err := crack.ProbeAll(context.Background(), token, crack.ProbeOptions{
		URL:        srv.URL,
		Candidates: []string{"wrong", "also-wrong"},
	})
	require.NoError(t, err)

	r, ok := findResult(results, "Weak Secret")
	require.True(t, ok)
	assert.True(t, r.Skipped)
	assert.Contains(t, r.SkipReason, "not found")
}

func TestProbeAll_Secret_ProbedWhenSecretFound(t *testing.T) {
	const secret = "hunter2"
	token := makeHS256Token(t, secret)
	srv := tokenAwareServer(token, 200, 401)
	defer srv.Close()

	results, _, err := crack.ProbeAll(context.Background(), token, crack.ProbeOptions{
		URL:        srv.URL,
		Candidates: []string{"wrong", secret, "also-wrong"},
	})
	require.NoError(t, err)

	r, ok := findResult(results, "Weak Secret")
	require.True(t, ok)
	assert.False(t, r.Skipped, "secret probe should not be skipped when secret is found")
	assert.True(t, r.Vulnerable, "secret was cracked — token is vulnerable")
	assert.Nil(t, r.Err)
	assert.Contains(t, r.Extra, secret, "Extra field should contain the found secret")
}

func TestProbeAll_HMAC_ResultNames(t *testing.T) {
	token := makeHS256Token(t, "secret")
	srv := tokenAwareServer(token, 200, 401)
	defer srv.Close()

	results, _, err := crack.ProbeAll(context.Background(), token, crack.ProbeOptions{URL: srv.URL})
	require.NoError(t, err)

	names := make([]string, len(results))
	for i, r := range results {
		names[i] = r.Name
	}

	require.Contains(t, names, "No Verification")
	require.Contains(t, names, "Blank Secret")
	require.Contains(t, names, "Null Signature")
	require.Contains(t, names, "HMAC Confusion")
	require.Contains(t, names, "KID SQL Injection")
	require.Contains(t, names, "KID Path Traversal")
	require.Contains(t, names, "Weak Secret")

	algNone := findResultPrefix(results, "Algorithm None (")
	assert.Len(t, algNone, len(exploit.AlgNoneVariants))
}

func TestProbeAll_Asymmetric_ResultNames(t *testing.T) {
	token, _ := makeRS256Token(t)
	srv := tokenAwareServer(token, 200, 401)
	defer srv.Close()

	results, _, err := crack.ProbeAll(context.Background(), token, crack.ProbeOptions{URL: srv.URL})
	require.NoError(t, err)

	names := make([]string, len(results))
	for i, r := range results {
		names[i] = r.Name
	}

	require.Contains(t, names, "No Verification")
	require.Contains(t, names, "Blank Secret")
	require.Contains(t, names, "Null Signature")
	require.Contains(t, names, "HMAC Confusion")
	require.Contains(t, names, "KID SQL Injection")
	require.Contains(t, names, "KID Path Traversal")
	require.Contains(t, names, "Weak Secret")
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

// Offline mode tests (no URL provided).

func TestProbeAll_Offline_MalformedToken_ReturnsError(t *testing.T) {
	_, _, err := crack.ProbeAll(context.Background(), "not-a-jwt", crack.ProbeOptions{})
	assert.Error(t, err)
}

func TestProbeAll_Offline_BaselineStatus_IsZero(t *testing.T) {
	token := makeHS256Token(t, "secret")
	_, baseline, err := crack.ProbeAll(context.Background(), token, crack.ProbeOptions{})
	require.NoError(t, err)
	assert.Equal(t, 0, baseline)
}

func TestProbeAll_Offline_NoVerification_Skipped(t *testing.T) {
	token := makeHS256Token(t, "secret")
	results, _, err := crack.ProbeAll(context.Background(), token, crack.ProbeOptions{})
	require.NoError(t, err)

	r, ok := findResult(results, "No Verification")
	require.True(t, ok)
	assert.True(t, r.Skipped)
	assert.Contains(t, r.SkipReason, "requires live server")
}

func TestProbeAll_Offline_AlgNone_DetectsExistingAlgNone(t *testing.T) {
	token := makeAlgNoneToken(t)
	results, _, err := crack.ProbeAll(context.Background(), token, crack.ProbeOptions{})
	require.NoError(t, err)

	r, ok := findResult(results, "Algorithm None (none)")
	require.True(t, ok)
	assert.False(t, r.Skipped, "already-none is reported as a finding, not skipped")
	assert.True(t, r.Vulnerable, "token already using alg=none is itself the vulnerability")
}

func TestProbeAll_Offline_AlgNone_NotVulnerable_ForNormalToken(t *testing.T) {
	token := makeHS256Token(t, "secret")
	results, _, err := crack.ProbeAll(context.Background(), token, crack.ProbeOptions{})
	require.NoError(t, err)

	r, ok := findResult(results, "Algorithm None (none)")
	require.True(t, ok)
	assert.False(t, r.Vulnerable, "variant 'none' should not be vulnerable for HS256 token offline")
}

func TestProbeAll_Offline_AlgNone_AllVariants_Skipped(t *testing.T) {
	token := makeHS256Token(t, "secret")
	results, _, err := crack.ProbeAll(context.Background(), token, crack.ProbeOptions{})
	require.NoError(t, err)

	// algnone requires a live server to demonstrate the manipulation exploit
	for _, r := range findResultPrefix(results, "Algorithm None (") {
		assert.True(t, r.Skipped, "variant %s should be skipped offline", r.Name)
		assert.Contains(t, r.SkipReason, "requires live server")
	}
}

func TestProbeAll_Offline_BlankSecret_VulnerableWhenSignedWithEmptyKey(t *testing.T) {
	token := makeBlankSecretToken(t)
	results, _, err := crack.ProbeAll(context.Background(), token, crack.ProbeOptions{})
	require.NoError(t, err)

	r, ok := findResult(results, "Blank Secret")
	require.True(t, ok)
	assert.False(t, r.Skipped)
	assert.True(t, r.Vulnerable)
}

func TestProbeAll_Offline_BlankSecret_NotVulnerableForNormalToken(t *testing.T) {
	token := makeHS256Token(t, "notempty")
	results, _, err := crack.ProbeAll(context.Background(), token, crack.ProbeOptions{})
	require.NoError(t, err)

	r, ok := findResult(results, "Blank Secret")
	require.True(t, ok)
	assert.False(t, r.Skipped)
	assert.False(t, r.Vulnerable)
}

func TestProbeAll_Offline_NullSignature_VulnerableWhenEmptySignature(t *testing.T) {
	token := makeNullSigToken(t)
	results, _, err := crack.ProbeAll(context.Background(), token, crack.ProbeOptions{})
	require.NoError(t, err)

	r, ok := findResult(results, "Null Signature")
	require.True(t, ok)
	assert.False(t, r.Skipped)
	assert.True(t, r.Vulnerable)
}

func TestProbeAll_Offline_NullSignature_NotVulnerableForNormalToken(t *testing.T) {
	token := makeHS256Token(t, "secret")
	results, _, err := crack.ProbeAll(context.Background(), token, crack.ProbeOptions{})
	require.NoError(t, err)

	r, ok := findResult(results, "Null Signature")
	require.True(t, ok)
	assert.False(t, r.Skipped)
	assert.False(t, r.Vulnerable)
}

func TestProbeAll_Offline_HMACConfusion_Skipped(t *testing.T) {
	token, _ := makeRS256Token(t)
	results, _, err := crack.ProbeAll(context.Background(), token, crack.ProbeOptions{})
	require.NoError(t, err)

	r, ok := findResult(results, "HMAC Confusion")
	require.True(t, ok)
	assert.True(t, r.Skipped)
	assert.Contains(t, r.SkipReason, "requires live server")
}

func TestProbeAll_Offline_KidSQL_Skipped(t *testing.T) {
	token := makeHS256Token(t, "secret")
	results, _, err := crack.ProbeAll(context.Background(), token, crack.ProbeOptions{})
	require.NoError(t, err)

	r, ok := findResult(results, "KID SQL Injection")
	require.True(t, ok)
	assert.True(t, r.Skipped)
	assert.Contains(t, r.SkipReason, "requires live server")
}

func TestProbeAll_Offline_KidPath_Skipped(t *testing.T) {
	token := makeHS256Token(t, "secret")
	results, _, err := crack.ProbeAll(context.Background(), token, crack.ProbeOptions{})
	require.NoError(t, err)

	r, ok := findResult(results, "KID Path Traversal")
	require.True(t, ok)
	assert.True(t, r.Skipped)
	assert.Contains(t, r.SkipReason, "requires live server")
}

func TestProbeAll_Offline_KidSQL_CustomTableOption_StillSkipped(t *testing.T) {
	token := makeHS256Token(t, "secret")
	results, _, err := crack.ProbeAll(context.Background(), token, crack.ProbeOptions{
		KidSQLTable: "custom_tokens",
	})
	require.NoError(t, err)

	r, ok := findResult(results, "KID SQL Injection")
	require.True(t, ok)
	assert.True(t, r.Skipped)
	assert.Contains(t, r.SkipReason, "requires live server")
}

func TestProbeAll_Offline_KidPath_CustomPathOption_StillSkipped(t *testing.T) {
	token := makeHS256Token(t, "secret")
	results, _, err := crack.ProbeAll(context.Background(), token, crack.ProbeOptions{
		KidPath: "/etc/passwd",
	})
	require.NoError(t, err)

	r, ok := findResult(results, "KID Path Traversal")
	require.True(t, ok)
	assert.True(t, r.Skipped)
	assert.Contains(t, r.SkipReason, "requires live server")
}

func TestProbeAll_Offline_WeakSecret_VulnerableWhenSecretInCandidates(t *testing.T) {
	const secret = "hunter2"
	token := makeHS256Token(t, secret)
	results, _, err := crack.ProbeAll(context.Background(), token, crack.ProbeOptions{
		Candidates: []string{"wrong", secret},
	})
	require.NoError(t, err)

	r, ok := findResult(results, "Weak Secret")
	require.True(t, ok)
	assert.False(t, r.Skipped)
	assert.True(t, r.Vulnerable)
	assert.Contains(t, r.Extra, secret)
}

func TestProbeAll_Offline_WeakSecret_SkippedWhenNoCandidates(t *testing.T) {
	token := makeHS256Token(t, "secret")
	results, _, err := crack.ProbeAll(context.Background(), token, crack.ProbeOptions{})
	require.NoError(t, err)

	r, ok := findResult(results, "Weak Secret")
	require.True(t, ok)
	assert.True(t, r.Skipped)
}

func TestProbeAll_Offline_WeakSecret_SkippedForAsymmetric(t *testing.T) {
	token, _ := makeRS256Token(t)
	results, _, err := crack.ProbeAll(context.Background(), token, crack.ProbeOptions{
		Candidates: []string{"secret"},
	})
	require.NoError(t, err)

	r, ok := findResult(results, "Weak Secret")
	require.True(t, ok)
	assert.True(t, r.Skipped)
	assert.Contains(t, r.SkipReason, "HMAC-only")
}
