package editor_test

import (
	"testing"

	"github.com/cerberauth/jwtop/jwt/editor"
	jwtlib "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

func TestIsHMACAlgWithHS256(t *testing.T) {
	token := jwtlib.New(jwtlib.SigningMethodHS256)
	tokenString, _ := token.SignedString([]byte(""))
	e, err := editor.NewTokenEditor(tokenString)

	assert.NoError(t, err)
	assert.True(t, e.IsHMACAlg())
}

func TestIsHMACAlgWithRSA(t *testing.T) {
	privateKeyData := []byte(`
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIKwkZA+Y19xPuGLCkk+JkrTnCo5bQvJcf0MdC73xg473
-----END PRIVATE KEY-----
`)

	key, _ := jwtlib.ParseEdPrivateKeyFromPEM(privateKeyData)
	token := jwtlib.New(jwtlib.SigningMethodEdDSA)
	tokenString, _ := token.SignedString(key)
	e, err := editor.NewTokenEditor(tokenString)

	assert.NoError(t, err)
	assert.False(t, e.IsHMACAlg())
}
