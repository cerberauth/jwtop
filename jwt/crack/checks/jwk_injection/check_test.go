package jwkinjection_test

import (
	"context"
	"testing"

	"github.com/cerberauth/harnessx"
	"github.com/stretchr/testify/assert"

	"github.com/cerberauth/jwtop/jwt/crack/checkbase"
	jwkinjection "github.com/cerberauth/jwtop/jwt/crack/checks/jwk_injection"
)

func TestCheck_Skip_Offline(t *testing.T) {
	store := harnessx.NewStaticResultStore()
	target := harnessx.Target{Data: &checkbase.ProbeCtx{Offline: true, IsAsymmetric: true}}

	reason := jwkinjection.Check.Skip.Eval(context.Background(), target, store)
	assert.NotEmpty(t, reason)
}

func TestCheck_Skip_NotAsymmetric(t *testing.T) {
	store := harnessx.NewStaticResultStore()
	target := harnessx.Target{Data: &checkbase.ProbeCtx{IsAsymmetric: false, Alg: "HS256"}}

	reason := jwkinjection.Check.Skip.Eval(context.Background(), target, store)
	assert.NotEmpty(t, reason)
}

func TestCheck_Skip_RunsWhenOnlineAndAsymmetric(t *testing.T) {
	store := harnessx.NewStaticResultStore()
	target := harnessx.Target{Data: &checkbase.ProbeCtx{Offline: false, IsAsymmetric: true, Alg: "RS256"}}

	reason := jwkinjection.Check.Skip.Eval(context.Background(), target, store)
	assert.Empty(t, reason)
}
