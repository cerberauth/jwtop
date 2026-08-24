package jwt_test

import (
	"strings"
	"testing"
	"testing/iotest"

	"github.com/cerberauth/jwtop/jwt"
	"github.com/stretchr/testify/assert"
)

const sampleToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.Gfx6VO9tcxwk6xqx9yYzSfebfeakZp5JYIgP_edcw_A"

func TestFindAll_BareToken(t *testing.T) {
	got := jwt.FindAll(sampleToken)
	assert.Equal(t, []string{sampleToken}, got)
}

func TestFindAll_TokenInURL(t *testing.T) {
	text := "https://example.com/callback?token=" + sampleToken + "&state=xyz"
	got := jwt.FindAll(text)
	assert.Equal(t, []string{sampleToken}, got)
}

func TestFindAll_TokenInJSON(t *testing.T) {
	text := `{"access_token":"` + sampleToken + `","token_type":"bearer"}`
	got := jwt.FindAll(text)
	assert.Equal(t, []string{sampleToken}, got)
}

func TestFindAll_TokenInAuthorizationHeader(t *testing.T) {
	text := "Authorization: Bearer " + sampleToken
	got := jwt.FindAll(text)
	assert.Equal(t, []string{sampleToken}, got)
}

func TestFindAll_MultipleTokens(t *testing.T) {
	token2 := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI5ODc2NTQzMjEwIn0."
	text := "first=" + sampleToken + " second=" + token2
	got := jwt.FindAll(text)
	assert.Len(t, got, 2)
	assert.Contains(t, got, sampleToken)
	assert.Contains(t, got, token2)
}

func TestFindAll_Deduplication(t *testing.T) {
	text := sampleToken + " " + sampleToken
	got := jwt.FindAll(text)
	assert.Equal(t, []string{sampleToken}, got)
}

func TestFindAll_NoToken(t *testing.T) {
	got := jwt.FindAll("no tokens here, just plain text")
	assert.Empty(t, got)
}

func TestFindAll_Empty(t *testing.T) {
	got := jwt.FindAll("")
	assert.Empty(t, got)
}

func TestFindAllReader_Basic(t *testing.T) {
	r := strings.NewReader("Bearer " + sampleToken)
	got, err := jwt.FindAllReader(r)
	assert.NoError(t, err)
	assert.Equal(t, []string{sampleToken}, got)
}

func TestFindAllReader_Error(t *testing.T) {
	r := iotest.ErrReader(assert.AnError)
	_, err := jwt.FindAllReader(r)
	assert.Error(t, err)
}
