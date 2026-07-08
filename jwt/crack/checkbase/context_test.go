package checkbase_test

import (
	"testing"

	"github.com/cerberauth/jwtop/jwt/crack/checkbase"
	"github.com/stretchr/testify/assert"
)

func TestDefaultTokenLocation(t *testing.T) {
	loc := checkbase.DefaultTokenLocation()
	assert.Equal(t, checkbase.TokenLocationHeader, loc.In)
	assert.Equal(t, "Authorization", loc.Name)
	assert.Equal(t, "Bearer ", loc.Prefix)
}

func TestTokenLocation_WithDefaults_EmptyUsesHeaderAuthorization(t *testing.T) {
	loc := checkbase.TokenLocation{}.WithDefaults()
	assert.Equal(t, checkbase.TokenLocationHeader, loc.In)
	assert.Equal(t, "Authorization", loc.Name)
	assert.Equal(t, "Bearer ", loc.Prefix)
}

func TestTokenLocation_WithDefaults_NonHeaderUsesTokenName(t *testing.T) {
	loc := checkbase.TokenLocation{In: checkbase.TokenLocationQuery}.WithDefaults()
	assert.Equal(t, checkbase.TokenLocationQuery, loc.In)
	assert.Equal(t, "token", loc.Name)
	assert.Empty(t, loc.Prefix)
}

func TestTokenLocation_WithDefaults_HeaderWithCustomNameNoPrefix(t *testing.T) {
	loc := checkbase.TokenLocation{In: checkbase.TokenLocationHeader, Name: "X-Token"}.WithDefaults()
	assert.Equal(t, "X-Token", loc.Name)
	assert.Empty(t, loc.Prefix)
}

func TestTokenLocation_WithDefaults_HeaderAuthorizationCaseInsensitive(t *testing.T) {
	loc := checkbase.TokenLocation{In: checkbase.TokenLocationHeader, Name: "authorization"}.WithDefaults()
	assert.Equal(t, "Bearer ", loc.Prefix)
}

func TestTokenLocation_WithDefaults_PreservesExplicitPrefix(t *testing.T) {
	loc := checkbase.TokenLocation{In: checkbase.TokenLocationCookie, Name: "session", Prefix: "tok="}.WithDefaults()
	assert.Equal(t, "tok=", loc.Prefix)
}

func TestTokenLocation_Validate_ValidValues(t *testing.T) {
	for _, in := range []string{"", checkbase.TokenLocationHeader, checkbase.TokenLocationCookie, checkbase.TokenLocationQuery, checkbase.TokenLocationBody} {
		assert.NoError(t, checkbase.TokenLocation{In: in}.Validate())
	}
}

func TestTokenLocation_Validate_InvalidValue(t *testing.T) {
	err := checkbase.TokenLocation{In: "form-data"}.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "form-data")
}
