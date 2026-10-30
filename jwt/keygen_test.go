package jwt_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/cerberauth/jwtop/jwt"
	libjwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateKeyPair_HMACDefaults(t *testing.T) {
	tests := []struct {
		alg  string
		size int
	}{
		{"HS256", 32},
		{"HS384", 48},
		{"HS512", 64},
	}

	for _, tc := range tests {
		t.Run(tc.alg, func(t *testing.T) {
			got, err := jwt.GenerateKeyPair(jwt.GenerateKeyOptions{Algorithm: tc.alg})
			require.NoError(t, err)
			require.Len(t, got.Secret, tc.size)
			assert.Nil(t, got.PrivatePEM)

			// Secret is usable to sign and verify a token.
			opts := jwt.CreateOptions{Algorithm: tc.alg, Claims: map[string]string{"sub": "x"}}
			token, err := jwt.CreateWithSecret(opts, got.Secret)
			require.NoError(t, err)
			parsed, err := libjwt.Parse(token, func(*libjwt.Token) (interface{}, error) { return got.Secret, nil })
			require.NoError(t, err)
			assert.True(t, parsed.Valid)
		})
	}
}

func TestGenerateKeyPair_HMACCustomLength(t *testing.T) {
	got, err := jwt.GenerateKeyPair(jwt.GenerateKeyOptions{Algorithm: "HS256", SecretBytes: 48})
	require.NoError(t, err)
	assert.Len(t, got.Secret, 48)
}

func TestGenerateKeyPair_HMACTooShortRejected(t *testing.T) {
	_, err := jwt.GenerateKeyPair(jwt.GenerateKeyOptions{Algorithm: "HS256", SecretBytes: 16})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least 32 bytes")
}

func TestGenerateKeyPair_HMACSecretIsRandom(t *testing.T) {
	a, err := jwt.GenerateKeyPair(jwt.GenerateKeyOptions{Algorithm: "HS256"})
	require.NoError(t, err)
	b, err := jwt.GenerateKeyPair(jwt.GenerateKeyOptions{Algorithm: "HS256"})
	require.NoError(t, err)
	assert.NotEqual(t, a.Secret, b.Secret)
}

func TestGeneratedKey_EncodeSecret(t *testing.T) {
	got, err := jwt.GenerateKeyPair(jwt.GenerateKeyOptions{Algorithm: "HS256"})
	require.NoError(t, err)

	b64url, err := got.EncodeSecret(jwt.SecretFormatBase64URL)
	require.NoError(t, err)
	decoded, err := base64.RawURLEncoding.DecodeString(b64url)
	require.NoError(t, err)
	assert.Equal(t, got.Secret, decoded)

	b64, err := got.EncodeSecret(jwt.SecretFormatBase64)
	require.NoError(t, err)
	decoded, err = base64.StdEncoding.DecodeString(b64)
	require.NoError(t, err)
	assert.Equal(t, got.Secret, decoded)

	h, err := got.EncodeSecret(jwt.SecretFormatHex)
	require.NoError(t, err)
	decoded, err = hex.DecodeString(h)
	require.NoError(t, err)
	assert.Equal(t, got.Secret, decoded)

	raw, err := got.EncodeSecret(jwt.SecretFormatRaw)
	require.NoError(t, err)
	assert.Equal(t, got.Secret, []byte(raw))

	_, err = got.EncodeSecret("bogus")
	assert.Error(t, err)
}

func TestGeneratedKey_EncodeSecretOnAsymmetric(t *testing.T) {
	got, err := jwt.GenerateKeyPair(jwt.GenerateKeyOptions{Algorithm: "ES256"})
	require.NoError(t, err)
	_, err = got.EncodeSecret(jwt.SecretFormatHex)
	assert.Error(t, err)
}

func TestGenerateKeyPair_RSA(t *testing.T) {
	for _, alg := range []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512"} {
		t.Run(alg, func(t *testing.T) {
			got, err := jwt.GenerateKeyPair(jwt.GenerateKeyOptions{Algorithm: alg})
			require.NoError(t, err)

			priv, err := jwt.LoadPrivateKeyFromPEM(got.PrivatePEM)
			require.NoError(t, err)
			rsaPriv, ok := priv.(*rsa.PrivateKey)
			require.True(t, ok)
			assert.Equal(t, 2048, rsaPriv.N.BitLen())

			pub, err := jwt.LoadPublicKeyFromPEM(got.PublicPEM)
			require.NoError(t, err)
			_, ok = pub.(*rsa.PublicKey)
			assert.True(t, ok)
		})
	}
}

func TestGenerateKeyPair_RSACustomBits(t *testing.T) {
	got, err := jwt.GenerateKeyPair(jwt.GenerateKeyOptions{Algorithm: "RS256", RSABits: 3072})
	require.NoError(t, err)
	priv, err := jwt.LoadPrivateKeyFromPEM(got.PrivatePEM)
	require.NoError(t, err)
	assert.Equal(t, 3072, priv.(*rsa.PrivateKey).N.BitLen())
}

func TestGenerateKeyPair_RSATooSmallRejected(t *testing.T) {
	_, err := jwt.GenerateKeyPair(jwt.GenerateKeyOptions{Algorithm: "RS256", RSABits: 1024})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least 2048 bits")
}

func TestGenerateKeyPair_ECDSA(t *testing.T) {
	for _, alg := range []string{"ES256", "ES384", "ES512"} {
		t.Run(alg, func(t *testing.T) {
			got, err := jwt.GenerateKeyPair(jwt.GenerateKeyOptions{Algorithm: alg})
			require.NoError(t, err)

			priv, err := jwt.LoadPrivateKeyFromPEM(got.PrivatePEM)
			require.NoError(t, err)
			ecPriv, ok := priv.(*ecdsa.PrivateKey)
			require.True(t, ok)

			opts := jwt.CreateOptions{Algorithm: alg, Claims: map[string]string{"sub": "x"}}
			token, err := jwt.Create(opts, ecPriv)
			require.NoError(t, err)

			pub, err := jwt.LoadPublicKeyFromPEM(got.PublicPEM)
			require.NoError(t, err)
			parsed, err := libjwt.Parse(token, func(*libjwt.Token) (interface{}, error) { return pub, nil })
			require.NoError(t, err)
			assert.True(t, parsed.Valid)
		})
	}
}

func TestGenerateKeyPair_EdDSA(t *testing.T) {
	got, err := jwt.GenerateKeyPair(jwt.GenerateKeyOptions{Algorithm: "EdDSA"})
	require.NoError(t, err)
	assert.Equal(t, "EdDSA", got.Algorithm)

	priv, err := jwt.LoadPrivateKeyFromPEM(got.PrivatePEM)
	require.NoError(t, err)
	edPriv, ok := priv.(ed25519.PrivateKey)
	require.True(t, ok)

	opts := jwt.CreateOptions{Algorithm: "EdDSA", Claims: map[string]string{"sub": "x"}}
	token, err := jwt.Create(opts, edPriv)
	require.NoError(t, err)

	pub, err := jwt.LoadPublicKeyFromPEM(got.PublicPEM)
	require.NoError(t, err)
	parsed, err := libjwt.Parse(token, func(*libjwt.Token) (interface{}, error) { return pub, nil })
	require.NoError(t, err)
	assert.True(t, parsed.Valid)
}

func TestGenerateKeyPair_CaseInsensitiveAlg(t *testing.T) {
	got, err := jwt.GenerateKeyPair(jwt.GenerateKeyOptions{Algorithm: "  es256  "})
	require.NoError(t, err)
	assert.NotEmpty(t, got.PrivatePEM)
}

func TestGenerateKeyPair_NoneRejected(t *testing.T) {
	_, err := jwt.GenerateKeyPair(jwt.GenerateKeyOptions{Algorithm: "none"})
	assert.Error(t, err)
}

func TestGenerateKeyPair_UnsupportedRejected(t *testing.T) {
	_, err := jwt.GenerateKeyPair(jwt.GenerateKeyOptions{Algorithm: "XYZ999"})
	assert.Error(t, err)
}
