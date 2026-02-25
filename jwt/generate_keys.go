package jwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"

	"github.com/golang-jwt/jwt/v5"
)

// GenerateKey generates a random cryptographic key appropriate for the given
// signing method. The returned key type depends on the algorithm family:
//   - HMAC (HS256/HS384/HS512): []byte of length 64
//   - RSA (RS256/RS384/RS512/PS256/PS384/PS512): *rsa.PrivateKey (2048-bit)
//   - ECDSA ES256: *ecdsa.PrivateKey (P-256)
//   - ECDSA ES384: *ecdsa.PrivateKey (P-384)
//   - ECDSA ES512: *ecdsa.PrivateKey (P-521)
//   - none: returns (nil, nil)
func GenerateKey(method jwt.SigningMethod) (interface{}, error) {
	switch method.Alg() {
	case jwt.SigningMethodRS256.Alg(),
		jwt.SigningMethodRS384.Alg(),
		jwt.SigningMethodRS512.Alg(),
		jwt.SigningMethodPS256.Alg(),
		jwt.SigningMethodPS384.Alg(),
		jwt.SigningMethodPS512.Alg():
		privateKeyRS, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}
		return privateKeyRS, nil

	case jwt.SigningMethodES256.Alg():
		privateKeyES256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		return privateKeyES256, nil

	case jwt.SigningMethodES384.Alg():
		privateKeyES384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			return nil, err
		}
		return privateKeyES384, nil

	case jwt.SigningMethodES512.Alg():
		privateKeyES512, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		if err != nil {
			return nil, err
		}
		return privateKeyES512, nil

	case jwt.SigningMethodHS256.Alg(),
		jwt.SigningMethodHS384.Alg(),
		jwt.SigningMethodHS512.Alg():
		keyHS := make([]byte, 64)
		_, err := rand.Read(keyHS)
		if err != nil {
			return nil, err
		}
		return keyHS, nil

	case jwt.SigningMethodNone.Alg():
		return nil, nil
	}

	return nil, errors.New("unsupported signing method")
}
