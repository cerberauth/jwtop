package jwt

import (
	"encoding/json"
	"time"
)

// RegisteredClaimDescriptions maps well-known JWT claim and header names to a
// short human-readable description, used to annotate decoded tokens.
var RegisteredClaimDescriptions = map[string]string{
	// Registered payload claims (RFC 7519).
	"iss": "Issuer — who created and signed the token",
	"sub": "Subject — the principal the token is about",
	"aud": "Audience — intended recipient(s) of the token",
	"exp": "Expiration Time — token must be rejected after this time",
	"nbf": "Not Before — token must be rejected before this time",
	"iat": "Issued At — when the token was created",
	"jti": "JWT ID — unique identifier for the token",

	// Registered header parameters (RFC 7515/7516).
	"alg":  "Algorithm — how the token is signed (or \"none\")",
	"typ":  "Type — media type of the token, typically \"JWT\"",
	"cty":  "Content Type — media type of the payload, if nested",
	"kid":  "Key ID — hints which key was used to sign the token",
	"jku":  "JWK Set URL — where to fetch the signer's public keys",
	"jwk":  "JSON Web Key — the signer's public key, embedded inline",
	"x5c":  "X.509 Certificate Chain — embedded signer certificate(s)",
	"x5u":  "X.509 URL — where to fetch the signer's certificate",
	"x5t":  "X.509 Certificate SHA-1 Thumbprint",
	"crit": "Critical — extensions that must be understood to process the token",
}

// TimeClaimNames lists registered claims that hold a NumericDate (Unix
// timestamp) value, per RFC 7519.
var TimeClaimNames = map[string]bool{
	"exp": true,
	"nbf": true,
	"iat": true,
}

// AsTime attempts to interpret a decoded claim value as a Unix timestamp,
// as used by the exp/nbf/iat claims. It returns false if the value isn't a
// plausible numeric timestamp.
func AsTime(v interface{}) (time.Time, bool) {
	var seconds float64
	switch n := v.(type) {
	case float64:
		seconds = n
	case int64:
		seconds = float64(n)
	case json.Number:
		f, err := n.Float64()
		if err != nil {
			return time.Time{}, false
		}
		seconds = f
	default:
		return time.Time{}, false
	}

	return time.Unix(int64(seconds), 0).UTC(), true
}
