package x5uinjection_test

import (
	"context"
	"testing"

	"github.com/cerberauth/harnessx"
	"github.com/stretchr/testify/assert"

	"github.com/cerberauth/jwtop/jwt/crack/checkbase"
	x5uinjection "github.com/cerberauth/jwtop/jwt/crack/checks/x5u_injection"
)

func TestCheck_Skip_Offline(t *testing.T) {
	store := harnessx.NewStaticResultStore()
	target := harnessx.Target{Data: &checkbase.ProbeCtx{Offline: true, IsAsymmetric: true, X5UServerAddr: "127.0.0.1:0"}}

	reason := x5uinjection.Check.Skip.Eval(context.Background(), target, store)
	assert.NotEmpty(t, reason)
}

func TestCheck_Skip_NotAsymmetric(t *testing.T) {
	store := harnessx.NewStaticResultStore()
	target := harnessx.Target{Data: &checkbase.ProbeCtx{IsAsymmetric: false, Alg: "HS256", X5UServerAddr: "127.0.0.1:0"}}

	reason := x5uinjection.Check.Skip.Eval(context.Background(), target, store)
	assert.NotEmpty(t, reason)
}

func TestCheck_Skip_NoX5UServerAddr(t *testing.T) {
	store := harnessx.NewStaticResultStore()
	target := harnessx.Target{Data: &checkbase.ProbeCtx{Offline: false, IsAsymmetric: true, Alg: "RS256"}}

	reason := x5uinjection.Check.Skip.Eval(context.Background(), target, store)
	assert.NotEmpty(t, reason)
}

func TestCheck_Skip_RunsWhenOnlineAsymmetricAndAddrConfigured(t *testing.T) {
	store := harnessx.NewStaticResultStore()
	target := harnessx.Target{Data: &checkbase.ProbeCtx{Offline: false, IsAsymmetric: true, Alg: "RS256", X5UServerAddr: "127.0.0.1:0"}}

	reason := x5uinjection.Check.Skip.Eval(context.Background(), target, store)
	assert.Empty(t, reason)
}
