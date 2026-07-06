package weaksecret_test

import (
	"context"
	"testing"

	"github.com/cerberauth/harnessx"
	"github.com/stretchr/testify/assert"

	"github.com/cerberauth/jwtop/jwt/crack/checkbase"
	weaksecret "github.com/cerberauth/jwtop/jwt/crack/checks/weak_secret"
)

func TestCheck_Skip_NonHMAC(t *testing.T) {
	store := harnessx.NewStaticResultStore()
	target := harnessx.Target{Data: &checkbase.ProbeCtx{IsHMAC: false, Alg: "RS256"}}

	reason := weaksecret.Check.Skip.Eval(context.Background(), target, store)
	assert.NotEmpty(t, reason)
}

func TestCheck_Skip_BlankSecretAlreadyVulnerable(t *testing.T) {
	store := harnessx.NewStaticResultStore(
		harnessx.ResultData("blanksecret", checkbase.ProbeResult{Vulnerable: true}),
	)
	target := harnessx.Target{Data: &checkbase.ProbeCtx{IsHMAC: true, Alg: "HS256"}}

	reason := weaksecret.Check.Skip.Eval(context.Background(), target, store)
	assert.NotEmpty(t, reason)
}

func TestCheck_Skip_RunsWhenHMACAndNoBlankSecret(t *testing.T) {
	store := harnessx.NewStaticResultStore(
		harnessx.ResultData("blanksecret", checkbase.ProbeResult{Vulnerable: false}),
	)
	target := harnessx.Target{Data: &checkbase.ProbeCtx{IsHMAC: true, Alg: "HS256"}}

	reason := weaksecret.Check.Skip.Eval(context.Background(), target, store)
	assert.Empty(t, reason)
}
