package cmd

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/cerberauth/jwtop/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func runGenkey(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()

	// Reset package-level flag state between invocations.
	genkeyAlg = ""
	genkeyRSABits = 0
	genkeySecretBytes = 0
	genkeySecretFormat = "base64url"
	genkeyOut = ""
	genkeyForce = false
	genkeyPublicOnly = false

	var outBuf, errBuf bytes.Buffer
	genkeyCmd.SetOut(&outBuf)
	genkeyCmd.SetErr(&errBuf)
	genkeyCmd.SetArgs(args)
	err = genkeyCmd.Execute()
	return outBuf.String(), errBuf.String(), err
}

func TestGenkeyCmd_FlagsRegistered(t *testing.T) {
	for _, name := range []string{"alg", "rsa-bits", "secret-bytes", "secret-format", "out", "force", "public-only"} {
		require.NotNilf(t, genkeyCmd.Flags().Lookup(name), "expected --%s to be registered", name)
	}
}

func TestGenkeyCmd_RequiresAlg(t *testing.T) {
	_, _, err := runGenkey(t)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--alg is required")
}

func TestGenkeyCmd_HMACToStdout(t *testing.T) {
	stdout, _, err := runGenkey(t, "--alg", "HS256")
	require.NoError(t, err)

	secret, decErr := base64.RawURLEncoding.DecodeString(trim(stdout))
	require.NoError(t, decErr)
	assert.Len(t, secret, 32)
}

func TestGenkeyCmd_HMACHexFormatAndLength(t *testing.T) {
	stdout, _, err := runGenkey(t, "--alg", "HS512", "--secret-bytes", "64", "--secret-format", "hex")
	require.NoError(t, err)
	assert.Len(t, trim(stdout), 128) // 64 bytes hex-encoded
}

func TestGenkeyCmd_HMACWeakSecretRejected(t *testing.T) {
	_, _, err := runGenkey(t, "--alg", "HS256", "--secret-bytes", "8")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least 32 bytes")
}

func TestGenkeyCmd_RSATooSmallRejected(t *testing.T) {
	_, _, err := runGenkey(t, "--alg", "RS256", "--rsa-bits", "512")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least 2048 bits")
}

func TestGenkeyCmd_AsymmetricToStdout(t *testing.T) {
	stdout, _, err := runGenkey(t, "--alg", "ES256")
	require.NoError(t, err)
	assert.Contains(t, stdout, "-----BEGIN PRIVATE KEY-----")
	assert.Contains(t, stdout, "-----BEGIN PUBLIC KEY-----")

	_, loadErr := jwt.LoadPrivateKeyFromPEM([]byte(stdout))
	require.NoError(t, loadErr)
}

func TestGenkeyCmd_PublicOnly(t *testing.T) {
	stdout, _, err := runGenkey(t, "--alg", "ES256", "--public-only")
	require.NoError(t, err)
	assert.NotContains(t, stdout, "PRIVATE KEY")
	assert.Contains(t, stdout, "-----BEGIN PUBLIC KEY-----")
}

func TestGenkeyCmd_PublicOnlyRejectedForHMAC(t *testing.T) {
	_, _, err := runGenkey(t, "--alg", "HS256", "--public-only")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "symmetric")
}

func TestGenkeyCmd_WritesFilesWithPerms(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key")

	_, stderr, err := runGenkey(t, "--alg", "RS256", "--out", path)
	require.NoError(t, err)
	assert.Contains(t, stderr, "mode 0600")

	privInfo, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), privInfo.Mode().Perm())

	pubInfo, err := os.Stat(path + ".pub")
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o644), pubInfo.Mode().Perm())

	privPEM, err := os.ReadFile(path)
	require.NoError(t, err)
	_, loadErr := jwt.LoadPrivateKeyFromPEM(privPEM)
	require.NoError(t, loadErr)
}

func TestGenkeyCmd_RefusesOverwriteWithoutForce(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key")

	_, _, err := runGenkey(t, "--alg", "ES256", "--out", path)
	require.NoError(t, err)

	_, _, err = runGenkey(t, "--alg", "ES256", "--out", path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--force")

	_, _, err = runGenkey(t, "--alg", "ES256", "--out", path, "--force")
	require.NoError(t, err)
}

func TestGenkeyCmd_HMACSecretFileHasSecureMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret")

	_, _, err := runGenkey(t, "--alg", "HS256", "--out", path)
	require.NoError(t, err)

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
}

func trim(s string) string {
	return string(bytes.TrimSpace([]byte(s)))
}
