package jwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"

	jwtlib "github.com/golang-jwt/jwt/v5"
)

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
	X   string `json:"x"`
	Y   string `json:"y"`
	Crv string `json:"crv"`
}

type jwksResponse struct {
	Keys []jwk `json:"keys"`
}

// FetchJWKS retrieves a JWKS from a remote URI and returns a Keyfunc that
// selects the matching key by kid header, falling back to alg-based matching
// when no kid is present. Supported key types: RSA (kty=RSA) and EC (kty=EC).
// The URI is passed without modification; callers should use HTTPS in production.
func FetchJWKS(uri string) (jwtlib.Keyfunc, error) {
	resp, err := http.Get(uri) //nolint:gosec // URI comes from user-controlled config
	if err != nil {
		return nil, fmt.Errorf("fetching JWKS from %s: %w", uri, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS endpoint returned HTTP %d", resp.StatusCode)
	}

	var jwks jwksResponse
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, fmt.Errorf("decoding JWKS response: %w", err)
	}

	return func(token *jwtlib.Token) (interface{}, error) {
		kid, _ := token.Header["kid"].(string)
		alg, _ := token.Header["alg"].(string)

		for _, key := range jwks.Keys {
			if kid != "" && key.Kid != kid {
				continue
			}
			if kid == "" && alg != "" && key.Alg != "" && key.Alg != alg {
				continue
			}
			return parseJWK(key)
		}

		return nil, errors.New("no matching key found in JWKS")
	}, nil
}

func parseJWK(key jwk) (interface{}, error) {
	switch key.Kty {
	case "RSA":
		return parseRSAPublicKey(key)
	case "EC":
		return parseECPublicKey(key)
	default:
		return nil, fmt.Errorf("unsupported key type: %s", key.Kty)
	}
}

func parseRSAPublicKey(key jwk) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(key.N)
	if err != nil {
		return nil, fmt.Errorf("decoding RSA modulus: %w", err)
	}

	eBytes, err := base64.RawURLEncoding.DecodeString(key.E)
	if err != nil {
		return nil, fmt.Errorf("decoding RSA exponent: %w", err)
	}

	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes)

	return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
}

func parseECPublicKey(key jwk) (*ecdsa.PublicKey, error) {
	xBytes, err := base64.RawURLEncoding.DecodeString(key.X)
	if err != nil {
		return nil, fmt.Errorf("decoding EC x coordinate: %w", err)
	}

	yBytes, err := base64.RawURLEncoding.DecodeString(key.Y)
	if err != nil {
		return nil, fmt.Errorf("decoding EC y coordinate: %w", err)
	}

	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)

	curve, err := getCurve(key.Crv)
	if err != nil {
		return nil, err
	}

	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}

func getCurve(crv string) (elliptic.Curve, error) {
	switch crv {
	case "P-256":
		return elliptic.P256(), nil
	case "P-384":
		return elliptic.P384(), nil
	case "P-521":
		return elliptic.P521(), nil
	default:
		return nil, fmt.Errorf("unsupported EC curve: %s", crv)
	}
}
