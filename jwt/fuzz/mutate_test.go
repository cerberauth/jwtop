package fuzz_test

import (
	"strings"
	"testing"

	"github.com/cerberauth/jwtop/jwt/fuzz"
	jwtlib "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

func TestMutateToken_ReplacesClaimValue(t *testing.T) {
	result, err := fuzz.MutateToken(testToken, "sub", 1337)
	require.NoError(t, err)

	parsed, _, err := new(jwtlib.Parser).ParseUnverified(result, jwtlib.MapClaims{})
	require.NoError(t, err)
	claims := parsed.Claims.(jwtlib.MapClaims)
	assert.EqualValues(t, 1337, claims["sub"])
	assert.Equal(t, "John Doe", claims["name"])
}

func TestMutateToken_EmptySignature(t *testing.T) {
	result, err := fuzz.MutateToken(testToken, "sub", "x")
	require.NoError(t, err)

	parts := strings.Split(result, ".")
	require.Len(t, parts, 3)
	assert.Empty(t, parts[2])
}

func TestMutateToken_NullValue(t *testing.T) {
	result, err := fuzz.MutateToken(testToken, "sub", nil)
	require.NoError(t, err)

	parsed, _, err := new(jwtlib.Parser).ParseUnverified(result, jwtlib.MapClaims{})
	require.NoError(t, err)
	claims := parsed.Claims.(jwtlib.MapClaims)
	assert.Nil(t, claims["sub"])
}

func TestMutateToken_InvalidToken(t *testing.T) {
	_, err := fuzz.MutateToken("not-a-jwt", "sub", 1)
	assert.Error(t, err)
}

func TestMutateAndSignToken_ProducesValidSignature(t *testing.T) {
	secret := []byte("mysecret")
	signed, err := jwtlib.NewWithClaims(jwtlib.SigningMethodHS256, jwtlib.MapClaims{
		"sub": "1234567890", "name": "John Doe",
	}).SignedString(secret)
	require.NoError(t, err)

	result, err := fuzz.MutateAndSignToken(signed, "sub", 1337, secret)
	require.NoError(t, err)

	parsed, err := jwtlib.Parse(result, func(*jwtlib.Token) (interface{}, error) { return secret, nil })
	require.NoError(t, err)
	assert.True(t, parsed.Valid)
	claims := parsed.Claims.(jwtlib.MapClaims)
	assert.EqualValues(t, 1337, claims["sub"])
	assert.Equal(t, "John Doe", claims["name"])
}

func TestMutateAndSignToken_InvalidToken(t *testing.T) {
	_, err := fuzz.MutateAndSignToken("not-a-jwt", "sub", 1, []byte("x"))
	assert.Error(t, err)
}
