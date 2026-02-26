package editor

import (
	"errors"
	"time"

	jwtpkg "github.com/cerberauth/jwtop/jwt"
	"github.com/golang-jwt/jwt/v5"
)

// TokenEditor wraps a parsed JWT token and provides signing/mutation helpers.
type TokenEditor struct {
	token *jwt.Token
}

// NewTokenEditor parses a JWT string (without verifying the signature) and returns a TokenEditor.
func NewTokenEditor(token string) (*TokenEditor, error) {
	tokenParsed, _, err := new(jwt.Parser).ParseUnverified(token, jwt.MapClaims{})
	if err != nil && !errors.Is(err, jwt.ErrTokenUnverifiable) && !errors.Is(err, jwt.ErrTokenSignatureInvalid) {
		return nil, err
	}

	if tokenParsed == nil {
		return nil, errors.New("invalid JWT token")
	}

	return &TokenEditor{token: tokenParsed}, nil
}

// NewTokenEditorWithValidClaims returns a clone of j with exp/nbf adjusted so
// the token passes temporal validation at the moment of the call. Specifically:
//   - If exp is in the past, it is moved to now+5 minutes.
//   - If nbf is in the future, it is set to now.
func NewTokenEditorWithValidClaims(j *TokenEditor) *TokenEditor {
	editor := j.Clone()
	token := editor.GetToken()

	claims := token.Claims.(jwt.MapClaims)

	expirationTime, err := claims.GetExpirationTime()
	if err == nil && expirationTime != nil && expirationTime.Before(time.Now()) {
		editor.token.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(5 * time.Minute).Unix()
	}

	notBeforeTime, err := claims.GetNotBefore()
	if err == nil && notBeforeTime != nil && notBeforeTime.After(time.Now()) {
		editor.token.Claims.(jwt.MapClaims)["nbf"] = time.Now().Unix()
	}

	return editor
}

// GetToken returns the underlying jwt.Token.
func (j *TokenEditor) GetToken() *jwt.Token {
	return j.token
}

// SignWithMethodAndKey signs the token with the given method and key, returning the token string.
func (j *TokenEditor) SignWithMethodAndKey(method jwt.SigningMethod, key interface{}) (string, error) {
	token := jwt.NewWithClaims(method, jwtpkg.NewOrderedMapClaims(j.token))

	tokenString, err := token.SignedString(key)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

// SignWithMethodAndRandomKey generates a random key for the method and signs the token.
func (j *TokenEditor) SignWithMethodAndRandomKey(method jwt.SigningMethod) (string, error) {
	key, err := jwtpkg.GenerateKey(method)
	if err != nil {
		return "", err
	}
	return j.SignWithMethodAndKey(method, key)
}

// SignWithKey signs the token using the token's existing method and the provided key.
func (j *TokenEditor) SignWithKey(key interface{}) (string, error) {
	return j.SignWithMethodAndKey(j.token.Method, key)
}

// NewEmptyTokenEditor creates a TokenEditor with empty claims and HS256 signing
// method. Useful as a fallback when no real token is available.
func NewEmptyTokenEditor() (*TokenEditor, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{})
	tokenString, err := token.SignedString([]byte(""))
	if err != nil {
		return nil, err
	}
	return NewTokenEditor(tokenString)
}

// Clone creates a deep copy of this TokenEditor by re-parsing the underlying raw
// token. Panics if the raw token is invalid (which cannot happen in normal use).
func (j *TokenEditor) Clone() *TokenEditor {
	w, err := NewTokenEditor(j.GetToken().Raw)
	if err != nil {
		panic(err)
	}

	return w
}
