// Package jwt provides functions for decoding, verifying, creating, and
// re-signing JSON Web Tokens (JWTs). It wraps github.com/golang-jwt/jwt/v5
// with a simpler API suited for tooling, testing, and security research.
package jwt

import (
	"regexp"

	"github.com/golang-jwt/jwt/v5"
)

var jwtRegex = regexp.MustCompile(`^[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$`)

// IsJWT reports whether s looks like a well-formed JWT.
func IsJWT(token string) bool {
	if !jwtRegex.MatchString(token) {
		return false
	}
	_, _, err := new(jwt.Parser).ParseUnverified(token, jwt.MapClaims{})
	return err == nil
}
