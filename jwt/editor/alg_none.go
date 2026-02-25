package editor

import jwtlib "github.com/golang-jwt/jwt/v5"

// WithAlgNone re-signs the token with alg=none and an empty signature,
// producing a token accepted by parsers that allow the "none" algorithm.
// Unlike WithoutSignature, the header alg field is explicitly changed to "none".
func (j *TokenEditor) WithAlgNone() (string, error) {
	return j.SignWithMethodAndKey(jwtlib.SigningMethodNone, jwtlib.UnsafeAllowNoneSignatureType)
}
