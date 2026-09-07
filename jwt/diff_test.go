package jwt_test

import (
	"testing"

	"github.com/cerberauth/jwtop/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDiff_IdenticalTokens(t *testing.T) {
	result, err := jwt.Diff(FakeJWT, FakeJWT)
	require.NoError(t, err)
	require.Len(t, result.Diffs, 1)

	d := result.Diffs[0]
	assert.True(t, d.IdenticalToBase)
	assert.False(t, d.SignatureChanged)
	assert.Empty(t, d.Header)
	assert.Empty(t, d.Claims)
}

func TestDiff_AddedChangedRemovedClaim(t *testing.T) {
	// base: sub=1234567890, name=John Doe, iat=1516239022
	base := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	// other: sub=1234567890 (unchanged), name removed, role=admin added
	other := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiYWRtaW4iLCJzdWIiOiIxMjM0NTY3ODkwIn0.BNTkp24IQLTi6AxavjkdfZ6nXuxlC_LvdcsjhWLkc2s"

	result, err := jwt.Diff(base, other)
	require.NoError(t, err)
	require.Len(t, result.Diffs, 1)

	d := result.Diffs[0]
	assert.False(t, d.IdenticalToBase)
	assert.True(t, d.SignatureChanged)
	assert.Empty(t, d.Header)

	require.Len(t, d.Claims, 3)
	byKey := map[string]jwt.FieldChange{}
	for _, c := range d.Claims {
		byKey[c.Key] = c
	}

	assert.Equal(t, "removed", byKey["name"].Status)
	assert.Equal(t, "John Doe", byKey["name"].Base)

	assert.Equal(t, "added", byKey["role"].Status)
	assert.Equal(t, "admin", byKey["role"].Other)

	assert.Equal(t, "removed", byKey["iat"].Status)
}

func TestDiff_MultipleOthers(t *testing.T) {
	result, err := jwt.Diff(FakeJWT, FakeJWT, FakeJWT)
	require.NoError(t, err)
	require.Len(t, result.Diffs, 2)
	for _, d := range result.Diffs {
		assert.True(t, d.IdenticalToBase)
	}
}

func TestDiff_InvalidBaseToken(t *testing.T) {
	_, err := jwt.Diff("not-a-jwt", FakeJWT)
	assert.Error(t, err)
}

func TestDiff_InvalidOtherToken(t *testing.T) {
	_, err := jwt.Diff(FakeJWT, "not-a-jwt")
	assert.Error(t, err)
}
