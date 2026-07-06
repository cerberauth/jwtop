package nullsignature_test

import (
	"context"
	"testing"

	"github.com/cerberauth/harnessx"
	"github.com/stretchr/testify/assert"

	"github.com/cerberauth/jwtop/jwt/crack/checkbase"
	nullsignature "github.com/cerberauth/jwtop/jwt/crack/checks/null_signature"
)

func TestCheck_Skip_AlgNone(t *testing.T) {
	store := harnessx.NewStaticResultStore()
	target := harnessx.Target{Data: &checkbase.ProbeCtx{Alg: "none"}}

	reason := nullsignature.Check.Skip.Eval(context.Background(), target, store)
	assert.NotEmpty(t, reason)
}

func TestCheck_Skip_RunsForOtherAlgs(t *testing.T) {
	store := harnessx.NewStaticResultStore()
	target := harnessx.Target{Data: &checkbase.ProbeCtx{Alg: "HS256"}}

	reason := nullsignature.Check.Skip.Eval(context.Background(), target, store)
	assert.Empty(t, reason)
}

func TestCheck_Run_Offline_VulnerableWhenSignatureEmpty(t *testing.T) {
	store := harnessx.NewStaticResultStore()
	target := harnessx.Target{Data: &checkbase.ProbeCtx{
		TokenString: "header.payload.",
		Offline:     true,
	}}

	result, err := nullsignature.Check.Run(context.Background(), target, store)
	assert.NoError(t, err)
	pr, ok := harnessx.DataAs[checkbase.ProbeResult](result)
	assert.True(t, ok)
	assert.True(t, pr.Vulnerable)
}

func TestCheck_Run_Offline_NotVulnerableForNormalToken(t *testing.T) {
	store := harnessx.NewStaticResultStore()
	target := harnessx.Target{Data: &checkbase.ProbeCtx{
		TokenString: "header.payload.signature",
		Offline:     true,
	}}

	result, err := nullsignature.Check.Run(context.Background(), target, store)
	assert.NoError(t, err)
	pr, ok := harnessx.DataAs[checkbase.ProbeResult](result)
	assert.True(t, ok)
	assert.False(t, pr.Vulnerable)
}
