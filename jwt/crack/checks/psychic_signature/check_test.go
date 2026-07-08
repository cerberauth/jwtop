package psychicsignature_test

import (
	"context"
	"testing"

	"github.com/cerberauth/harnessx"
	"github.com/stretchr/testify/assert"

	"github.com/cerberauth/jwtop/jwt/crack/checkbase"
	psychicsignature "github.com/cerberauth/jwtop/jwt/crack/checks/psychic_signature"
)

func TestCheck_Skip_Offline(t *testing.T) {
	store := harnessx.NewStaticResultStore()
	target := harnessx.Target{Data: &checkbase.ProbeCtx{Offline: true, Alg: "ES256"}}

	reason := psychicsignature.Check.Skip.Eval(context.Background(), target, store)
	assert.NotEmpty(t, reason)
}

func TestCheck_Skip_NotECDSA(t *testing.T) {
	store := harnessx.NewStaticResultStore()
	target := harnessx.Target{Data: &checkbase.ProbeCtx{Alg: "HS256"}}

	reason := psychicsignature.Check.Skip.Eval(context.Background(), target, store)
	assert.NotEmpty(t, reason)
}

func TestCheck_Skip_RunsForECDSAAlgs(t *testing.T) {
	store := harnessx.NewStaticResultStore()
	for _, alg := range []string{"ES256", "ES384", "ES512"} {
		target := harnessx.Target{Data: &checkbase.ProbeCtx{Alg: alg}}
		reason := psychicsignature.Check.Skip.Eval(context.Background(), target, store)
		assert.Empty(t, reason, "alg %s should not be skipped", alg)
	}
}
