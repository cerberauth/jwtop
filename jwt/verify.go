package jwt

import (
	"crypto"
	"errors"
	"fmt"

	jwtlib "github.com/golang-jwt/jwt/v5"
)

// VerifyOptions holds the configuration for token verification.
// Exactly one of Secret, KeyPEM, or JWKSURI must be set.
type VerifyOptions struct {
	Secret  []byte // HMAC secret (for HS256, HS384, HS512).
	KeyPEM  []byte // PEM-encoded public key bytes (RSA, EC, or Ed25519); a private key is also accepted and the public part is extracted.
	JWKSURI string // URL of a JWKS endpoint; the matching key is selected by kid, falling back to alg.
}

// VerifyResult contains the outcome of a token verification attempt.
type VerifyResult struct {
	Valid     bool                   // True only when the signature and all standard claims are valid.
	Claims    map[string]interface{} // Decoded payload claims; populated even when Valid is false.
	Algorithm string                 // Signing algorithm extracted from the token header.
	Error     error                  // Verification error when Valid is false; nil when Valid is true.
}

// Verify validates the given JWT token using the provided options.
// It returns (result, nil) even when the signature is invalid — the failure
// reason is captured in result.Error and result.Valid is false. A non-nil
// returned error indicates a structural problem (malformed token or missing key).
func Verify(tokenString string, opts VerifyOptions) (*VerifyResult, error) {
	decoded, err := Decode(tokenString)
	if err != nil {
		return nil, fmt.Errorf("failed to decode token: %w", err)
	}

	alg, _ := decoded.Header["alg"].(string)

	var keyFunc jwtlib.Keyfunc

	switch {
	case opts.JWKSURI != "":
		keyFunc, err = FetchJWKS(opts.JWKSURI)
		if err != nil {
			return &VerifyResult{Valid: false, Algorithm: alg, Error: err}, nil
		}
	case len(opts.KeyPEM) > 0:
		pubKey, err := LoadPublicKeyFromPEM(opts.KeyPEM)
		if err != nil {
			// Try as private key and extract the public component.
			privKey, err2 := LoadPrivateKeyFromPEM(opts.KeyPEM)
			if err2 != nil {
				return nil, fmt.Errorf("failed to load key from PEM: %w", err)
			}
			signer, ok := privKey.(crypto.Signer)
			if !ok {
				return nil, fmt.Errorf("failed to load key from PEM: %w", err)
			}
			pubKey = signer.Public()
		}
		keyFunc = func(t *jwtlib.Token) (interface{}, error) {
			return pubKey, nil
		}
	case len(opts.Secret) > 0:
		keyFunc = func(t *jwtlib.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwtlib.SigningMethodHMAC); !ok {
				return nil, errors.New("unexpected signing method")
			}
			return opts.Secret, nil
		}
	default:
		return nil, errors.New("no verification key provided: set Secret, KeyPEM, or JWKSURI")
	}

	token, err := jwtlib.Parse(tokenString, keyFunc)
	if err != nil {
		return &VerifyResult{Valid: false, Algorithm: alg, Error: err}, nil
	}

	claims, ok := token.Claims.(jwtlib.MapClaims)
	if !ok {
		return &VerifyResult{Valid: false, Algorithm: alg, Error: errors.New("unexpected claims type")}, nil
	}

	claimsMap := make(map[string]interface{}, len(claims))
	for k, v := range claims {
		claimsMap[k] = v
	}

	return &VerifyResult{
		Valid:     token.Valid,
		Claims:    claimsMap,
		Algorithm: alg,
	}, nil
}
