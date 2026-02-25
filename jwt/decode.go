package jwt

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// DecodedJWT holds the decoded parts of a JWT token.
type DecodedJWT struct {
	Header    map[string]interface{} // Decoded JOSE header (e.g. alg, typ, kid).
	Claims    map[string]interface{} // Decoded payload claims.
	Signature string                 // Raw base64url-encoded signature segment.
	Raw       string                 // Original token string as received.
}

// Decode parses a JWT token string without verifying the signature.
// It returns an error only if the token is structurally malformed.
func Decode(tokenString string) (*DecodedJWT, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format: expected 3 parts, got %d", len(parts))
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWT header: %w", err)
	}

	claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWT claims: %w", err)
	}

	var header map[string]interface{}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("failed to parse JWT header: %w", err)
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		return nil, fmt.Errorf("failed to parse JWT claims: %w", err)
	}

	return &DecodedJWT{
		Header:    header,
		Claims:    claims,
		Signature: parts[2],
		Raw:       tokenString,
	}, nil
}
