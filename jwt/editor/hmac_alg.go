package editor

import jwtlib "github.com/golang-jwt/jwt/v5"

// IsHMACAlg reports whether the token uses an HMAC-based signing algorithm.
func (j *TokenEditor) IsHMACAlg() bool {
	_, ok := j.GetToken().Method.(*jwtlib.SigningMethodHMAC)
	return ok
}
