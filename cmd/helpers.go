package cmd

import (
	"errors"
	"os"

	"github.com/cerberauth/jwtop/jwt"
	jwtlib "github.com/golang-jwt/jwt/v5"
)

// resolveKey returns the signing/verification key from either a raw secret string
// or a PEM file path. If publicKey is true and a PEM file is provided, the public
// key is loaded; otherwise the private key is loaded.
func resolveKey(secret, keyFile string, publicKey bool) (interface{}, []byte, error) {
	if secret != "" && keyFile != "" {
		return nil, nil, errors.New("specify either --secret or --key, not both")
	}

	if secret != "" {
		return []byte(secret), []byte(secret), nil
	}

	if keyFile != "" {
		pemData, err := os.ReadFile(keyFile)
		if err != nil {
			return nil, nil, err
		}

		var key interface{}
		if publicKey {
			key, err = jwt.LoadPublicKeyFromPEM(pemData)
			if err != nil {
				// Fall back: try private key (caller may use public component)
				key, err = jwt.LoadPrivateKeyFromPEM(pemData)
				if err != nil {
					return nil, nil, err
				}
			}
		} else {
			key, err = jwt.LoadPrivateKeyFromPEM(pemData)
			if err != nil {
				return nil, nil, err
			}
		}

		return key, pemData, nil
	}

	return nil, nil, errors.New("no key provided: use --secret or --key")
}

// ParseSigningMethod returns the jwt.SigningMethod for the given algorithm name.
func ParseSigningMethod(alg string) (jwtlib.SigningMethod, error) {
	return jwt.ParseSigningMethod(alg)
}
