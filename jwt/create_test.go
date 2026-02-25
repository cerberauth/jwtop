package jwt_test

import (
	"testing"
	"time"

	"github.com/cerberauth/jwtop/jwt"
	libjwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateWithSecret_HS256(t *testing.T) {
	opts := jwt.CreateOptions{
		Algorithm: "HS256",
		Claims:    map[string]string{"sub": "testuser"},
		IssuedAt:  true,
	}

	tokenString, err := jwt.CreateWithSecret(opts, []byte("mysecret"))
	require.NoError(t, err)
	assert.NotEmpty(t, tokenString)

	parsed, err := libjwt.Parse(tokenString, func(t *libjwt.Token) (interface{}, error) {
		return []byte("mysecret"), nil
	})
	require.NoError(t, err)
	assert.True(t, parsed.Valid)

	claims := parsed.Claims.(libjwt.MapClaims)
	assert.Equal(t, "testuser", claims["sub"])
}

func TestCreate_WithExpiration(t *testing.T) {
	opts := jwt.CreateOptions{
		Algorithm:  "HS256",
		Claims:     map[string]string{"sub": "user1"},
		Expiration: time.Hour,
	}

	tokenString, err := jwt.CreateWithSecret(opts, []byte("secret"))
	require.NoError(t, err)

	parsed, err := libjwt.Parse(tokenString, func(t *libjwt.Token) (interface{}, error) {
		return []byte("secret"), nil
	})
	require.NoError(t, err)

	expTime, err := parsed.Claims.GetExpirationTime()
	require.NoError(t, err)
	assert.True(t, expTime.After(time.Now()))
}

func TestCreate_IntegerClaim(t *testing.T) {
	opts := jwt.CreateOptions{
		Algorithm: "HS256",
		Claims:    map[string]string{"count": "42"},
	}

	tokenString, err := jwt.CreateWithSecret(opts, []byte("secret"))
	require.NoError(t, err)

	parsed, _, _ := new(libjwt.Parser).ParseUnverified(tokenString, libjwt.MapClaims{})
	claims := parsed.Claims.(libjwt.MapClaims)
	assert.EqualValues(t, 42, claims["count"])
}

func TestParseSigningMethod_Valid(t *testing.T) {
	m, err := jwt.ParseSigningMethod("HS256")
	assert.NoError(t, err)
	assert.Equal(t, libjwt.SigningMethodHS256, m)
}

func TestParseSigningMethod_Invalid(t *testing.T) {
	_, err := jwt.ParseSigningMethod("INVALID")
	assert.Error(t, err)
}
