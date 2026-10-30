package jkuinjection_test

import (
	"context"
	"testing"

	"github.com/cerberauth/harnessx"
	"github.com/stretchr/testify/assert"

	"github.com/cerberauth/jwtop/jwt/crack/checkbase"
	jkuinjection "github.com/cerberauth/jwtop/jwt/crack/checks/jku_injection"
)

func TestCheck_Skip_Offline(t *testing.T) {
	store := harnessx.NewStaticResultStore()
	target := harnessx.Target{Data: &checkbase.ProbeCtx{Offline: true, IsAsymmetric: true, JKUServerAddr: "127.0.0.1:0"}}

	reason := jkuinjection.Check.Skip.Eval(context.Background(), target, store)
	assert.NotEmpty(t, reason)
}

func TestCheck_Skip_NotAsymmetric(t *testing.T) {
	store := harnessx.NewStaticResultStore()
	target := harnessx.Target{Data: &checkbase.ProbeCtx{IsAsymmetric: false, Alg: "HS256", JKUServerAddr: "127.0.0.1:0"}}

	reason := jkuinjection.Check.Skip.Eval(context.Background(), target, store)
	assert.NotEmpty(t, reason)
}

func TestCheck_Skip_NoJKUServerAddr(t *testing.T) {
	store := harnessx.NewStaticResultStore()
	target := harnessx.Target{Data: &checkbase.ProbeCtx{Offline: false, IsAsymmetric: true, Alg: "RS256"}}

	reason := jkuinjection.Check.Skip.Eval(context.Background(), target, store)
	assert.NotEmpty(t, reason)
}

func TestCheck_Skip_RunsWhenOnlineAsymmetricAndAddrConfigured(t *testing.T) {
	store := harnessx.NewStaticResultStore()
	target := harnessx.Target{Data: &checkbase.ProbeCtx{Offline: false, IsAsymmetric: true, Alg: "RS256", JKUServerAddr: "127.0.0.1:0"}}

	reason := jkuinjection.Check.Skip.Eval(context.Background(), target, store)
	assert.Empty(t, reason)
}
