package fuzz

import (
	"errors"

	"github.com/cerberauth/jwtop/jwt/editor"
	jwtlib "github.com/golang-jwt/jwt/v5"
)

// ErrClaimsNotMap is returned by MutateToken when the token's claims can't
// be addressed by name (not expected for JWTs parsed by this package, but
// guarded against defensively).
var ErrClaimsNotMap = errors.New("fuzz: token claims are not a map")

// mutatedEditor parses tokenString and replaces claim with value, returning
// the editor positioned on the mutated claims (not yet re-encoded/signed).
func mutatedEditor(tokenString, claim string, value any) (*editor.TokenEditor, error) {
	e, err := editor.NewTokenEditor(tokenString)
	if err != nil {
		return nil, err
	}
	claims, ok := e.GetToken().Claims.(jwtlib.MapClaims)
	if !ok {
		return nil, ErrClaimsNotMap
	}
	claims[claim] = value
	return e, nil
}

// MutateToken returns tokenString with claim replaced by value, re-encoded
// with an empty signature (same approach as editor.WithoutSignature): the
// header and every other claim are preserved, only the signature segment is
// dropped since the original one no longer matches the mutated payload.
// This still exercises the server's claim-parsing path even against
// implementations that check the signature only after decoding the claims.
func MutateToken(tokenString, claim string, value any) (string, error) {
	e, err := mutatedEditor(tokenString, claim, value)
	if err != nil {
		return "", err
	}
	return e.WithoutSignature()
}

// MutateAndSignToken is the counterpart of MutateToken for when the HMAC
// signing secret is known (e.g. cracked by the weak_secret check): it
// mutates claim the same way, then re-signs the token with secret using
// its original algorithm, producing a token with a genuinely valid
// signature. This is required to reach handlers on servers that verify the
// signature correctly (the mutation only breaks a claim's value, not the
// server's trust in who sent it) — see the jwt-claim-* challenges.
func MutateAndSignToken(tokenString, claim string, value any, secret []byte) (string, error) {
	e, err := mutatedEditor(tokenString, claim, value)
	if err != nil {
		return "", err
	}
	return e.SignWithKey(secret)
}
