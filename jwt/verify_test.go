package jwt_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cerberauth/jwtop/jwt"
	jwtlib "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVerify_ValidHMAC(t *testing.T) {
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
	opts := jwt.CreateOptions{
		Algorithm: "HS256",
		Claims:    map[string]string{"sub": "testuser"},
	}
	tokenString, err := jwt.CreateWithSecret(opts, []byte("secret"))
	require.NoError(t, err)

	_, err = jwt.Verify(tokenString, jwt.VerifyOptions{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no verification key provided")
}

func TestVerify_InvalidTokenString(t *testing.T) {
	_, err := jwt.Verify("not-a-jwt", jwt.VerifyOptions{Secret: []byte("secret")})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode token")
}

func TestVerify_SecretWithNonHMACAlgorithm(t *testing.T) {
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	tok := jwtlib.NewWithClaims(jwtlib.SigningMethodRS256, jwtlib.MapClaims{"sub": "rsa-user"})
	tokenString, err := tok.SignedString(rsaPriv)
	require.NoError(t, err)

	result, err := jwt.Verify(tokenString, jwt.VerifyOptions{Secret: []byte("some-secret")})
	require.NoError(t, err)
	assert.False(t, result.Valid)
	assert.NotNil(t, result.Error)
	assert.Contains(t, result.Error.Error(), "unexpected signing method")
}

func TestVerify_PublicKeyPEM_RSA(t *testing.T) {
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	tok := jwtlib.NewWithClaims(jwtlib.SigningMethodRS256, jwtlib.MapClaims{"sub": "rsa-user"})
	tokenString, err := tok.SignedString(rsaPriv)
	require.NoError(t, err)

	pubBytes, err := x509.MarshalPKIXPublicKey(&rsaPriv.PublicKey)
	require.NoError(t, err)
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})

	result, err := jwt.Verify(tokenString, jwt.VerifyOptions{KeyPEM: pubPEM})
	require.NoError(t, err)
	assert.True(t, result.Valid)
	assert.Equal(t, "RS256", result.Algorithm)
	assert.Equal(t, "rsa-user", result.Claims["sub"])
}

func TestVerify_PrivateKeyPEM_RSA(t *testing.T) {
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	tok := jwtlib.NewWithClaims(jwtlib.SigningMethodRS256, jwtlib.MapClaims{"sub": "rsa-user"})
	tokenString, err := tok.SignedString(rsaPriv)
	require.NoError(t, err)

	privBytes, err := x509.MarshalPKCS8PrivateKey(rsaPriv)
	require.NoError(t, err)
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})

	result, err := jwt.Verify(tokenString, jwt.VerifyOptions{KeyPEM: privPEM})
	require.NoError(t, err)
	assert.True(t, result.Valid)
	assert.Equal(t, "RS256", result.Algorithm)
}

func TestVerify_PrivateKeyPEM_EC(t *testing.T) {
	ecPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tok := jwtlib.NewWithClaims(jwtlib.SigningMethodES256, jwtlib.MapClaims{"sub": "ec-user"})
	tokenString, err := tok.SignedString(ecPriv)
	require.NoError(t, err)

	privBytes, err := x509.MarshalECPrivateKey(ecPriv)
	require.NoError(t, err)
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes})

	result, err := jwt.Verify(tokenString, jwt.VerifyOptions{KeyPEM: privPEM})
	require.NoError(t, err)
	assert.True(t, result.Valid)
	assert.Equal(t, "ES256", result.Algorithm)
}

func TestVerify_InvalidKeyPEM(t *testing.T) {
	opts := jwt.CreateOptions{
		Algorithm: "HS256",
		Claims:    map[string]string{"sub": "testuser"},
	}
	tokenString, err := jwt.CreateWithSecret(opts, []byte("secret"))
	require.NoError(t, err)

	_, err = jwt.Verify(tokenString, jwt.VerifyOptions{KeyPEM: []byte("invalid-pem")})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load key from PEM")
}

func TestVerify_JWKS(t *testing.T) {
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	tok := jwtlib.NewWithClaims(jwtlib.SigningMethodRS256, jwtlib.MapClaims{"sub": "jwks-user"})
	tok.Header["kid"] = "rsa-key-1"
	tokenString, err := tok.SignedString(rsaPriv)
	require.NoError(t, err)

	jwks := jwksData{
		Keys: []jwkData{
			rsaToJWK(&rsaPriv.PublicKey, "rsa-key-1", "RS256"),
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	defer server.Close()

	result, err := jwt.Verify(tokenString, jwt.VerifyOptions{JWKSURI: server.URL})
	require.NoError(t, err)
	assert.True(t, result.Valid)
	assert.Equal(t, "jwks-user", result.Claims["sub"])
}

func TestVerify_JWKS_FetchError(t *testing.T) {
	opts := jwt.CreateOptions{
		Algorithm: "HS256",
		Claims:    map[string]string{"sub": "testuser"},
	}
	tokenString, err := jwt.CreateWithSecret(opts, []byte("secret"))
	require.NoError(t, err)

	result, err := jwt.Verify(tokenString, jwt.VerifyOptions{JWKSURI: "http://127.0.0.1:0/jwks.json"})
	require.NoError(t, err)
	assert.False(t, result.Valid)
	assert.NotNil(t, result.Error)
}
