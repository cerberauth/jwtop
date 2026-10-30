package jwt_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"testing"

	"github.com/cerberauth/jwtop/jwt"
	jwtlib "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type unsupportedSigningMethod struct{}

func (u *unsupportedSigningMethod) Verify(signingString string, sig []byte, key interface{}) error {
	return nil
}
func (u *unsupportedSigningMethod) Sign(signingString string, key interface{}) ([]byte, error) {
	return nil, nil
}
func (u *unsupportedSigningMethod) Alg() string { return "UNSUPPORTED" }

func TestGenerateKey_RSA(t *testing.T) {
	methods := []jwtlib.SigningMethod{
		jwtlib.SigningMethodRS256,
		jwtlib.SigningMethodRS384,
		jwtlib.SigningMethodRS512,
		jwtlib.SigningMethodPS256,
		jwtlib.SigningMethodPS384,
		jwtlib.SigningMethodPS512,
	}

	for _, method := range methods {
		t.Run(method.Alg(), func(t *testing.T) {
			key, err := jwt.GenerateKey(method)
			require.NoError(t, err)
			rsaKey, ok := key.(*rsa.PrivateKey)
			require.True(t, ok)
			assert.Equal(t, 2048, rsaKey.N.BitLen())
		})
	}
}

func TestGenerateKey_ECDSA(t *testing.T) {
	tests := []struct {
		method jwtlib.SigningMethod
		curve  elliptic.Curve
	}{
		{jwtlib.SigningMethodES256, elliptic.P256()},
		{jwtlib.SigningMethodES384, elliptic.P384()},
		{jwtlib.SigningMethodES512, elliptic.P521()},
	}

	for _, tc := range tests {
		t.Run(tc.method.Alg(), func(t *testing.T) {
			key, err := jwt.GenerateKey(tc.method)
			require.NoError(t, err)
			ecKey, ok := key.(*ecdsa.PrivateKey)
			require.True(t, ok)
			assert.Equal(t, tc.curve, ecKey.Curve)
		})
	}
}

func TestGenerateKey_HMAC(t *testing.T) {
	methods := []jwtlib.SigningMethod{
		jwtlib.SigningMethodHS256,
		jwtlib.SigningMethodHS384,
		jwtlib.SigningMethodHS512,
	}

	for _, method := range methods {
		t.Run(method.Alg(), func(t *testing.T) {
			key, err := jwt.GenerateKey(method)
			require.NoError(t, err)
			hmacKey, ok := key.([]byte)
			require.True(t, ok)
			assert.Len(t, hmacKey, 64)
		})
	}
}

func TestGenerateKey_None(t *testing.T) {
	key, err := jwt.GenerateKey(jwtlib.SigningMethodNone)
	require.NoError(t, err)
	assert.Nil(t, key)
}

func TestGenerateKey_Unsupported(t *testing.T) {
	key, err := jwt.GenerateKey(&unsupportedSigningMethod{})
	assert.Error(t, err)
	assert.Nil(t, key)
	assert.Contains(t, err.Error(), "unsupported signing method")
}
