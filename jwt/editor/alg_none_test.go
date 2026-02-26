package editor_test

import (
	"strings"
	"testing"

	"github.com/cerberauth/jwtop/jwt/editor"
	libjwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

func TestTokenEditor_WithAlgNone_SetsAlgNone(t *testing.T) {
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	e, _ := editor.NewTokenEditor(token)

	result, err := e.WithAlgNone()
	assert.NoError(t, err)
	assert.NotEmpty(t, result)

	parsed, _, err := new(libjwt.Parser).ParseUnverified(result, libjwt.MapClaims{})
	assert.NoError(t, err)
	assert.Equal(t, libjwt.SigningMethodNone, parsed.Method)
}

func TestTokenEditor_WithAlgNone_EmptySignature(t *testing.T) {
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	e, _ := editor.NewTokenEditor(token)

	result, err := e.WithAlgNone()
	assert.NoError(t, err)

	parts := strings.Split(result, ".")
	assert.Len(t, parts, 3)
	assert.Empty(t, parts[2])
}

func TestTokenEditor_WithAlgNone_PreservesClaims(t *testing.T) {
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	original, _, _ := new(libjwt.Parser).ParseUnverified(token, libjwt.MapClaims{})
	e, _ := editor.NewTokenEditor(token)

	result, err := e.WithAlgNone()
	assert.NoError(t, err)

	parsed, _, err := new(libjwt.Parser).ParseUnverified(result, libjwt.MapClaims{})
	assert.NoError(t, err)
	assert.Equal(t, original.Claims, parsed.Claims)
}
