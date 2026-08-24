package jwt_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/cerberauth/jwtop/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadPublicKeyFromPEM_InvalidPEM(t *testing.T) {
	_, err := jwt.LoadPublicKeyFromPEM([]byte("not a pem"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode PEM block")
}

func TestLoadPublicKeyFromPEM_UnsupportedType(t *testing.T) {
	block := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: []byte("dummy"),
	})
	_, err := jwt.LoadPublicKeyFromPEM(block)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported PEM block type")
}

func TestLoadPublicKeyFromPEM_RSAPKIX(t *testing.T) {
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pubBytes, err := x509.MarshalPKIXPublicKey(&rsaPriv.PublicKey)
	require.NoError(t, err)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})

	pub, err := jwt.LoadPublicKeyFromPEM(pemBytes)
	require.NoError(t, err)
	rsaPub, ok := pub.(*rsa.PublicKey)
	require.True(t, ok)
	assert.Equal(t, rsaPriv.PublicKey.N, rsaPub.N)
}

func TestLoadPublicKeyFromPEM_RSAPKCS1(t *testing.T) {
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pubBytes := x509.MarshalPKCS1PublicKey(&rsaPriv.PublicKey)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: pubBytes})

	pub, err := jwt.LoadPublicKeyFromPEM(pemBytes)
	require.NoError(t, err)
	rsaPub, ok := pub.(*rsa.PublicKey)
	require.True(t, ok)
	assert.Equal(t, rsaPriv.PublicKey.N, rsaPub.N)
}

func TestLoadPublicKeyFromPEM_ECPKIX(t *testing.T) {
	ecPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pubBytes, err := x509.MarshalPKIXPublicKey(&ecPriv.PublicKey)
	require.NoError(t, err)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})

	pub, err := jwt.LoadPublicKeyFromPEM(pemBytes)
	require.NoError(t, err)
	ecPub, ok := pub.(*ecdsa.PublicKey)
	require.True(t, ok)
	assert.Equal(t, ecPriv.PublicKey.X, ecPub.X)
}

func TestLoadPublicKeyFromPEM_Ed25519PKIX(t *testing.T) {
	pubKey, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	pubBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	require.NoError(t, err)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})

	pub, err := jwt.LoadPublicKeyFromPEM(pemBytes)
	require.NoError(t, err)
	edPub, ok := pub.(ed25519.PublicKey)
	require.True(t, ok)
	assert.Equal(t, pubKey, edPub)
}

func TestLoadPublicKeyFromPEM_CorruptBytes(t *testing.T) {
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("corrupt")})
	_, err := jwt.LoadPublicKeyFromPEM(pemBytes)
	assert.Error(t, err)
}

func TestLoadPrivateKeyFromPEM_InvalidPEM(t *testing.T) {
	_, err := jwt.LoadPrivateKeyFromPEM([]byte("not a pem"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode PEM block")
}

func TestLoadPrivateKeyFromPEM_UnsupportedType(t *testing.T) {
	block := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: []byte("dummy"),
	})
	_, err := jwt.LoadPrivateKeyFromPEM(block)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported PEM block type")
}

func TestLoadPrivateKeyFromPEM_RSAPKCS8(t *testing.T) {
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	privBytes, err := x509.MarshalPKCS8PrivateKey(rsaPriv)
	require.NoError(t, err)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})

	priv, err := jwt.LoadPrivateKeyFromPEM(pemBytes)
	require.NoError(t, err)
	loadedRSA, ok := priv.(*rsa.PrivateKey)
	require.True(t, ok)
	assert.Equal(t, rsaPriv.N, loadedRSA.N)
}

func TestLoadPrivateKeyFromPEM_RSAPKCS1(t *testing.T) {
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	privBytes := x509.MarshalPKCS1PrivateKey(rsaPriv)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes})

	priv, err := jwt.LoadPrivateKeyFromPEM(pemBytes)
	require.NoError(t, err)
	loadedRSA, ok := priv.(*rsa.PrivateKey)
	require.True(t, ok)
	assert.Equal(t, rsaPriv.N, loadedRSA.N)
}

func TestLoadPrivateKeyFromPEM_ECPKCS8(t *testing.T) {
	ecPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	privBytes, err := x509.MarshalPKCS8PrivateKey(ecPriv)
	require.NoError(t, err)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})

	priv, err := jwt.LoadPrivateKeyFromPEM(pemBytes)
	require.NoError(t, err)
	loadedEC, ok := priv.(*ecdsa.PrivateKey)
	require.True(t, ok)
	assert.Equal(t, ecPriv.D, loadedEC.D)
}

func TestLoadPrivateKeyFromPEM_ECSEC1(t *testing.T) {
	ecPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	privBytes, err := x509.MarshalECPrivateKey(ecPriv)
	require.NoError(t, err)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes})

	priv, err := jwt.LoadPrivateKeyFromPEM(pemBytes)
	require.NoError(t, err)
	loadedEC, ok := priv.(*ecdsa.PrivateKey)
	require.True(t, ok)
	assert.Equal(t, ecPriv.D, loadedEC.D)
}

func TestLoadPrivateKeyFromPEM_Ed25519PKCS8(t *testing.T) {
	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	privBytes, err := x509.MarshalPKCS8PrivateKey(privKey)
	require.NoError(t, err)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})

	priv, err := jwt.LoadPrivateKeyFromPEM(pemBytes)
	require.NoError(t, err)
	loadedEd, ok := priv.(ed25519.PrivateKey)
	require.True(t, ok)
	assert.Equal(t, privKey, loadedEd)
}

func TestLoadPrivateKeyFromPEM_CorruptBytes(t *testing.T) {
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("corrupt")})
	_, err := jwt.LoadPrivateKeyFromPEM(pemBytes)
	assert.Error(t, err)
}
