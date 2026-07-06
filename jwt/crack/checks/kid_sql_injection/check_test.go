package kidsqlinjection_test

import (
	"context"
	"testing"

	"github.com/cerberauth/harnessx"
	"github.com/stretchr/testify/assert"

	"github.com/cerberauth/jwtop/jwt/crack/checkbase"
	kidsqlinjection "github.com/cerberauth/jwtop/jwt/crack/checks/kid_sql_injection"
)

func TestCheck_Skip_Offline(t *testing.T) {
	store := harnessx.NewStaticResultStore()
	target := harnessx.Target{Data: &checkbase.ProbeCtx{Offline: true}}

	reason := kidsqlinjection.Check.Skip.Eval(context.Background(), target, store)
	assert.NotEmpty(t, reason)
}

func TestCheck_Skip_WeakSecretAlreadyVulnerable(t *testing.T) {
	store := harnessx.NewStaticResultStore(
		harnessx.ResultData("secret", checkbase.ProbeResult{Vulnerable: true}),
	)
	target := harnessx.Target{Data: &checkbase.ProbeCtx{Offline: false}}

	reason := kidsqlinjection.Check.Skip.Eval(context.Background(), target, store)
	assert.NotEmpty(t, reason)
}

func TestCheck_Skip_RunsWhenOnlineAndNoWeakSecret(t *testing.T) {
	store := harnessx.NewStaticResultStore(
		harnessx.ResultData("secret", checkbase.ProbeResult{Vulnerable: false}),
	)
	target := harnessx.Target{Data: &checkbase.ProbeCtx{Offline: false}}

	reason := kidsqlinjection.Check.Skip.Eval(context.Background(), target, store)
	assert.Empty(t, reason)
}
