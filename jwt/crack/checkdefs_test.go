package crack_test

import (
	"testing"

	"github.com/cerberauth/jwtop/jwt/crack"
	"github.com/stretchr/testify/assert"
)

func TestCheckDefs_CVSSScoresMatchVectors(t *testing.T) {
	defs := crack.CheckDefs()
	assert.NotEmpty(t, defs)
	for id, def := range defs {
		assert.NoError(t, def.ValidateCVSS(), id)
	}
}
