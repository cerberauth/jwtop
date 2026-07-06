package blanksecret_test

import (
	"context"
	"testing"

	"github.com/cerberauth/harnessx"
	"github.com/stretchr/testify/assert"

	"github.com/cerberauth/jwtop/jwt/crack/checkbase"
	blanksecret "github.com/cerberauth/jwtop/jwt/crack/checks/blank_secret"
)

func TestCheck_Skip_NonHMAC(t *testing.T) {
	store := harnessx.NewStaticResultStore()
	target := harnessx.Target{Data: &checkbase.ProbeCtx{IsHMAC: false, Alg: "RS256"}}

	reason := blanksecret.Check.Skip.Eval(context.Background(), target, store)
	assert.NotEmpty(t, reason)
}

func TestCheck_Skip_RunsWhenHMAC(t *testing.T) {
	store := harnessx.NewStaticResultStore()
	target := harnessx.Target{Data: &checkbase.ProbeCtx{IsHMAC: true, Alg: "HS256"}}

	reason := blanksecret.Check.Skip.Eval(context.Background(), target, store)
	assert.Empty(t, reason)
}
