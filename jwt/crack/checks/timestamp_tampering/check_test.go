package timestamptampering_test

import (
	"context"
	"testing"

	"github.com/cerberauth/harnessx"
	"github.com/stretchr/testify/assert"

	"github.com/cerberauth/jwtop/jwt/crack/checkbase"
	timestamptampering "github.com/cerberauth/jwtop/jwt/crack/checks/timestamp_tampering"
)

func TestCheck_Skip_Offline(t *testing.T) {
	store := harnessx.NewStaticResultStore()
	target := harnessx.Target{Data: &checkbase.ProbeCtx{Offline: true, IsHMAC: true, CrackedHMACSecret: "secret"}}

	reason := timestamptampering.Check.Skip.Eval(context.Background(), target, store)
	assert.NotEmpty(t, reason)
}

func TestCheck_Skip_NonHMAC(t *testing.T) {
	store := harnessx.NewStaticResultStore()
	target := harnessx.Target{Data: &checkbase.ProbeCtx{IsHMAC: false, Alg: "RS256", CrackedHMACSecret: "secret"}}

	reason := timestamptampering.Check.Skip.Eval(context.Background(), target, store)
	assert.NotEmpty(t, reason)
}

func TestCheck_Skip_SecretNotCracked(t *testing.T) {
	store := harnessx.NewStaticResultStore()
	target := harnessx.Target{Data: &checkbase.ProbeCtx{IsHMAC: true, CrackedHMACSecret: ""}}

	reason := timestamptampering.Check.Skip.Eval(context.Background(), target, store)
	assert.NotEmpty(t, reason)
}

func TestCheck_Skip_RunsWhenHMACAndSecretCracked(t *testing.T) {
	store := harnessx.NewStaticResultStore()
	target := harnessx.Target{Data: &checkbase.ProbeCtx{IsHMAC: true, CrackedHMACSecret: "secret"}}

	reason := timestamptampering.Check.Skip.Eval(context.Background(), target, store)
	assert.Empty(t, reason)
}
