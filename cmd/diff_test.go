package cmd

import (
	"bytes"
	"testing"

	"github.com/cerberauth/jwtop/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// diffFakeJWT is a pre-built, syntactically valid HS256 token with an empty
// claims set (mirrors jwt_test.FakeJWT).
const diffFakeJWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.ufhxDTmrs4T5MSsvT6lsb3OpdWi5q8O31VX7TgrVamA"

// diffOtherJWT decodes to the same header but different claims (role=admin, sub=1234567890).
const diffOtherJWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiYWRtaW4iLCJzdWIiOiIxMjM0NTY3ODkwIn0.BNTkp24IQLTi6AxavjkdfZ6nXuxlC_LvdcsjhWLkc2s"

func runDiff(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()

	diffFormat = "text"

	var outBuf, errBuf bytes.Buffer
	diffCmd.SetOut(&outBuf)
	diffCmd.SetErr(&errBuf)
	diffCmd.SetArgs(args)
	err = diffCmd.Execute()
	return outBuf.String(), errBuf.String(), err
}

func TestDiffCmd_FlagsRegistered(t *testing.T) {
	require.NotNil(t, diffCmd.Flags().Lookup("format"))
}

func TestDiffCmd_RequiresTwoTokens(t *testing.T) {
	_, _, err := runDiff(t, diffFakeJWT)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least two tokens")
}

func TestDiffCmd_IdenticalTokensExitZero(t *testing.T) {
	stdout, _, err := runDiff(t, diffFakeJWT, diffFakeJWT)
	require.NoError(t, err)
	assert.Contains(t, stdout, "(identical)")
}

// The differing-tokens path exits the process with status 1 (a CI-friendly
// gate, like verify/crack), so it's exercised against printDiffText/
// printDiffJSON directly rather than through diffCmd.Execute().

func TestDiffCmd_TextFormatShowsChanges(t *testing.T) {
	result, err := jwt.Diff(diffFakeJWT, diffOtherJWT)
	require.NoError(t, err)

	var buf bytes.Buffer
	printDiffText(&buf, result)

	assert.Contains(t, buf.String(), "+ role")
	assert.Contains(t, buf.String(), "Signature: changed")
}

func TestDiffCmd_JSONFormat(t *testing.T) {
	result, err := jwt.Diff(diffFakeJWT, diffOtherJWT)
	require.NoError(t, err)

	var buf bytes.Buffer
	require.NoError(t, printDiffJSON(&buf, result))

	assert.Contains(t, buf.String(), `"status": "added"`)
	assert.Contains(t, buf.String(), `"role"`)
}

func TestDiffCmd_InvalidFormat(t *testing.T) {
	_, _, err := runDiff(t, diffFakeJWT, diffOtherJWT, "--format", "yaml")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid --format")
}
