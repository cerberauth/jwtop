package jwt_test

import (
	"testing"

	"github.com/cerberauth/jwtop/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// FakeJWT is a pre-built, syntactically valid HS256 token with an empty claims
// set. Useful as a placeholder in tests when token content does not matter.
const FakeJWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.ufhxDTmrs4T5MSsvT6lsb3OpdWi5q8O31VX7TgrVamA"

func TestDecode_ValidToken(t *testing.T) {
	// HS256 token with sub=1234567890, name=John Doe, iat=1516239022
	tokenString := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

	decoded, err := jwt.Decode(tokenString)
	require.NoError(t, err)
	require.NotNil(t, decoded)

	assert.Equal(t, "HS256", decoded.Header["alg"])
	assert.Equal(t, "JWT", decoded.Header["typ"])
	assert.Equal(t, "1234567890", decoded.Claims["sub"])
	assert.Equal(t, "John Doe", decoded.Claims["name"])
	assert.NotEmpty(t, decoded.Signature)
	assert.Equal(t, tokenString, decoded.Raw)
}

func TestDecode_InvalidFormat(t *testing.T) {
	_, err := jwt.Decode("not.a.valid.jwt.string.here")
	assert.Error(t, err)
}

func TestDecode_EmptyString(t *testing.T) {
	_, err := jwt.Decode("")
	assert.Error(t, err)
}

func TestDecode_FakeJWT(t *testing.T) {
	decoded, err := jwt.Decode(FakeJWT)
	require.NoError(t, err)
	assert.Equal(t, "HS256", decoded.Header["alg"])
}
