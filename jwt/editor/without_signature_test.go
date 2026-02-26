package editor_test

import (
	"strings"
	"testing"

	"github.com/cerberauth/jwtop/jwt/editor"
	libjwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

func TestTokenEditor_WithoutSignature_EmptySignature(t *testing.T) {
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	e, _ := editor.NewTokenEditor(token)

	result, err := e.WithoutSignature()
	assert.NoError(t, err)

	parts := strings.Split(result, ".")
	assert.Len(t, parts, 3)
	assert.Empty(t, parts[2])
}

func TestTokenEditor_WithoutSignature_PreservesOriginalHeader(t *testing.T) {
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	originalHeader := strings.SplitN(token, ".", 3)[0]
	e, _ := editor.NewTokenEditor(token)

	result, err := e.WithoutSignature()
	assert.NoError(t, err)

	resultHeader := strings.SplitN(result, ".", 3)[0]
	assert.Equal(t, originalHeader, resultHeader)
}

func TestTokenEditor_WithoutSignature_PreservesAlgorithm(t *testing.T) {
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	e, _ := editor.NewTokenEditor(token)

	result, err := e.WithoutSignature()
	assert.NoError(t, err)

	parsed, _, err := new(libjwt.Parser).ParseUnverified(result, libjwt.MapClaims{})
	assert.NoError(t, err)
	assert.Equal(t, libjwt.SigningMethodHS256, parsed.Method)
}

func TestTokenEditor_WithoutSignature_PreservesClaims(t *testing.T) {
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	original, _, _ := new(libjwt.Parser).ParseUnverified(token, libjwt.MapClaims{})
	e, _ := editor.NewTokenEditor(token)

	result, err := e.WithoutSignature()
	assert.NoError(t, err)

	parsed, _, err := new(libjwt.Parser).ParseUnverified(result, libjwt.MapClaims{})
	assert.NoError(t, err)
	assert.Equal(t, original.Claims, parsed.Claims)
}
