package jwt

import (
	"errors"
	"strconv"
	"time"

	jwtlib "github.com/golang-jwt/jwt/v5"
)

// CreateOptions holds parameters for creating a new JWT.
type CreateOptions struct {
	Algorithm  string            // Signing algorithm name (e.g. "HS256", "RS256", "ES256").
	Claims     map[string]string // Custom payload claims; values are auto-parsed to int64, bool, or string.
	Expiration time.Duration     // If > 0, sets the "exp" claim relative to now.
	NotBefore  time.Duration     // If > 0, sets the "nbf" claim relative to now.
	IssuedAt   bool              // If true, sets the "iat" claim to the current Unix time.
}

// ParseSigningMethod returns the jwt.SigningMethod for the given algorithm name.
func ParseSigningMethod(alg string) (jwtlib.SigningMethod, error) {
	method := jwtlib.GetSigningMethod(alg)
	if method == nil {
		return nil, errors.New("unknown signing algorithm: " + alg)
	}
	return method, nil
}

// Create builds and signs a new JWT using the provided options and signing key.
// The key type must match the algorithm family: []byte for HMAC, *rsa.PrivateKey
// for RS*/PS*, and *ecdsa.PrivateKey for ES*.
func Create(opts CreateOptions, signingKey interface{}) (string, error) {
	method, err := ParseSigningMethod(opts.Algorithm)
	if err != nil {
		return "", err
	}

	claims := jwtlib.MapClaims{}

	for k, v := range opts.Claims {
		claims[k] = parseClaimValue(v)
	}

	now := time.Now()

	if opts.IssuedAt {
		claims["iat"] = now.Unix()
	}

	if opts.Expiration > 0 {
		claims["exp"] = now.Add(opts.Expiration).Unix()
	}

	if opts.NotBefore > 0 {
		claims["nbf"] = now.Add(opts.NotBefore).Unix()
	}

	token := jwtlib.NewWithClaims(method, claims)
	return token.SignedString(signingKey)
}

// CreateWithSecret builds and signs a new JWT using an HMAC secret.
func CreateWithSecret(opts CreateOptions, secret []byte) (string, error) {
	return Create(opts, secret)
}

// parseClaimValue attempts to parse a string value as int64, bool, or falls back to string.
func parseClaimValue(v string) interface{} {
	if i, err := strconv.ParseInt(v, 10, 64); err == nil {
		return i
	}
	if b, err := strconv.ParseBool(v); err == nil {
		return b
	}
	return v
}
