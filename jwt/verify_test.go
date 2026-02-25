package jwt_test

import (
	"testing"

	"github.com/cerberauth/jwtop/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVerify_ValidHMAC(t *testing.T) {
	// Create a token first
	opts := jwt.CreateOptions{
		Algorithm: "HS256",
		Claims:    map[string]string{"sub": "testuser"},
		IssuedAt:  true,
	}
	tokenString, err := jwt.CreateWithSecret(opts, []byte("mysecret"))
	require.NoError(t, err)

	result, err := jwt.Verify(tokenString, jwt.VerifyOptions{Secret: []byte("mysecret")})
	require.NoError(t, err)
	assert.True(t, result.Valid)
	assert.Equal(t, "HS256", result.Algorithm)
	assert.Equal(t, "testuser", result.Claims["sub"])
}

func TestVerify_InvalidSecret(t *testing.T) {
	opts := jwt.CreateOptions{
		Algorithm: "HS256",
		Claims:    map[string]string{"sub": "testuser"},
	}
	tokenString, err := jwt.CreateWithSecret(opts, []byte("correctsecret"))
	require.NoError(t, err)

	result, err := jwt.Verify(tokenString, jwt.VerifyOptions{Secret: []byte("wrongsecret")})
	require.NoError(t, err)
	assert.False(t, result.Valid)
	assert.NotNil(t, result.Error)
}

func TestVerify_NoKeyProvided(t *testing.T) {
	_, err := jwt.Verify("some.token.here", jwt.VerifyOptions{})
	assert.Error(t, err)
}
