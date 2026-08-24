package jwt_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cerberauth/jwtop/jwt"
	jwtlib "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type jwkData struct {
	Kty string `json:"kty"`
	Kid string `json:"kid,omitempty"`
	Alg string `json:"alg,omitempty"`
	Use string `json:"use,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
	Crv string `json:"crv,omitempty"`
}

type jwksData struct {
	Keys []jwkData `json:"keys"`
}

func rsaToJWK(key *rsa.PublicKey, kid, alg string) jwkData {
	n := base64.RawURLEncoding.EncodeToString(key.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())
	return jwkData{
		Kty: "RSA",
		Kid: kid,
		Alg: alg,
		N:   n,
		E:   e,
	}
}

func ecToJWK(key *ecdsa.PublicKey, kid, alg, crv string) jwkData {
	curveSize := (key.Curve.Params().BitSize + 7) / 8
	xBytes := key.X.Bytes()
	yBytes := key.Y.Bytes()
	paddedX := make([]byte, curveSize)
	paddedY := make([]byte, curveSize)
	copy(paddedX[curveSize-len(xBytes):], xBytes)
	copy(paddedY[curveSize-len(yBytes):], yBytes)

	return jwkData{
		Kty: "EC",
		Kid: kid,
		Alg: alg,
		Crv: crv,
		X:   base64.RawURLEncoding.EncodeToString(paddedX),
		Y:   base64.RawURLEncoding.EncodeToString(paddedY),
	}
}

func TestFetchJWKS_Success_RSAAndEC(t *testing.T) {
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	ec256Priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ec384Priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	ec521Priv, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)

	jwks := jwksData{
		Keys: []jwkData{
			rsaToJWK(&rsaPriv.PublicKey, "rsa-1", "RS256"),
			ecToJWK(&ec256Priv.PublicKey, "ec-p256", "ES256", "P-256"),
			ecToJWK(&ec384Priv.PublicKey, "ec-p384", "ES384", "P-384"),
			ecToJWK(&ec521Priv.PublicKey, "ec-p521", "ES512", "P-521"),
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	defer server.Close()

	keyFunc, err := jwt.FetchJWKS(server.URL)
	require.NoError(t, err)
	require.NotNil(t, keyFunc)

	// Test RSA by kid
	tokenRSA := &jwtlib.Token{
		Header: map[string]interface{}{"kid": "rsa-1", "alg": "RS256"},
	}
	key, err := keyFunc(tokenRSA)
	require.NoError(t, err)
	rsaPub, ok := key.(*rsa.PublicKey)
	require.True(t, ok)
	assert.Equal(t, rsaPriv.PublicKey.N, rsaPub.N)

	// Test EC-256 by kid
	tokenEC256 := &jwtlib.Token{
		Header: map[string]interface{}{"kid": "ec-p256", "alg": "ES256"},
	}
	key, err = keyFunc(tokenEC256)
	require.NoError(t, err)
	ecPub, ok := key.(*ecdsa.PublicKey)
	require.True(t, ok)
	assert.Equal(t, ec256Priv.PublicKey.X, ecPub.X)

	// Test EC-384 by kid
	tokenEC384 := &jwtlib.Token{
		Header: map[string]interface{}{"kid": "ec-p384", "alg": "ES384"},
	}
	key, err = keyFunc(tokenEC384)
	require.NoError(t, err)
	assert.IsType(t, &ecdsa.PublicKey{}, key)

	// Test EC-521 by kid
	tokenEC521 := &jwtlib.Token{
		Header: map[string]interface{}{"kid": "ec-p521", "alg": "ES512"},
	}
	key, err = keyFunc(tokenEC521)
	require.NoError(t, err)
	assert.IsType(t, &ecdsa.PublicKey{}, key)

	// Test fallback to Alg matching when kid is missing
	tokenNoKid := &jwtlib.Token{
		Header: map[string]interface{}{"alg": "ES256"},
	}
	key, err = keyFunc(tokenNoKid)
	require.NoError(t, err)
	ecPub, ok = key.(*ecdsa.PublicKey)
	require.True(t, ok)
	assert.Equal(t, ec256Priv.PublicKey.X, ecPub.X)

	// Test unknown kid
	tokenUnknown := &jwtlib.Token{
		Header: map[string]interface{}{"kid": "nonexistent"},
	}
	_, err = keyFunc(tokenUnknown)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no matching key found")
}

func TestFetchJWKS_Errors(t *testing.T) {
	t.Run("HTTP Non-200", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "Not found", http.StatusNotFound)
		}))
		defer server.Close()

		_, err := jwt.FetchJWKS(server.URL)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "HTTP 404")
	})

	t.Run("Invalid JSON", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = fmt.Fprint(w, "invalid json")
		}))
		defer server.Close()

		_, err := jwt.FetchJWKS(server.URL)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "decoding JWKS response")
	})

	t.Run("Unreachable URI", func(t *testing.T) {
		_, err := jwt.FetchJWKS("http://127.0.0.1:0/jwks.json")
		assert.Error(t, err)
	})

	t.Run("Unsupported Key Type", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(jwksData{
				Keys: []jwkData{{Kty: "oct", Kid: "key-1"}},
			})
		}))
		defer server.Close()

		keyFunc, err := jwt.FetchJWKS(server.URL)
		require.NoError(t, err)

		_, err = keyFunc(&jwtlib.Token{Header: map[string]interface{}{"kid": "key-1"}})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported key type: oct")
	})

	t.Run("Unsupported EC Curve", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(jwksData{
				Keys: []jwkData{{
					Kty: "EC",
					Kid: "ec-unknown",
					Crv: "secp256k1",
					X:   "AAAA",
					Y:   "BBBB",
				}},
			})
		}))
		defer server.Close()

		keyFunc, err := jwt.FetchJWKS(server.URL)
		require.NoError(t, err)

		_, err = keyFunc(&jwtlib.Token{Header: map[string]interface{}{"kid": "ec-unknown"}})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported EC curve")
	})

	t.Run("Invalid RSA Modulus Base64", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(jwksData{
				Keys: []jwkData{{
					Kty: "RSA",
					Kid: "rsa-bad",
					N:   "???invalid-base64???",
					E:   "AQAB",
				}},
			})
		}))
		defer server.Close()

		keyFunc, err := jwt.FetchJWKS(server.URL)
		require.NoError(t, err)

		_, err = keyFunc(&jwtlib.Token{Header: map[string]interface{}{"kid": "rsa-bad"}})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "decoding RSA modulus")
	})

	t.Run("Invalid RSA Exponent Base64", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(jwksData{
				Keys: []jwkData{{
					Kty: "RSA",
					Kid: "rsa-bad",
					N:   "AQAB",
					E:   "???invalid-base64???",
				}},
			})
		}))
		defer server.Close()

		keyFunc, err := jwt.FetchJWKS(server.URL)
		require.NoError(t, err)

		_, err = keyFunc(&jwtlib.Token{Header: map[string]interface{}{"kid": "rsa-bad"}})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "decoding RSA exponent")
	})

	t.Run("Invalid EC Coordinates Base64", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(jwksData{
				Keys: []jwkData{{
					Kty: "EC",
					Kid: "ec-bad",
					Crv: "P-256",
					X:   "???bad???",
					Y:   "AQAB",
				}},
			})
		}))
		defer server.Close()

		keyFunc, err := jwt.FetchJWKS(server.URL)
		require.NoError(t, err)

		_, err = keyFunc(&jwtlib.Token{Header: map[string]interface{}{"kid": "ec-bad"}})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "decoding EC x coordinate")
	})

	t.Run("Invalid EC Y Coordinate Base64", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(jwksData{
				Keys: []jwkData{{
					Kty: "EC",
					Kid: "ec-bad",
					Crv: "P-256",
					X:   "AQAB",
					Y:   "???bad???",
				}},
			})
		}))
		defer server.Close()

		keyFunc, err := jwt.FetchJWKS(server.URL)
		require.NoError(t, err)

		_, err = keyFunc(&jwtlib.Token{Header: map[string]interface{}{"kid": "ec-bad"}})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "decoding EC y coordinate")
	})
}
