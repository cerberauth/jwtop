package noverification_test

import (
	"context"
	"testing"

	"github.com/cerberauth/harnessx"
	"github.com/stretchr/testify/assert"

	"github.com/cerberauth/jwtop/jwt/crack/checkbase"
	noverification "github.com/cerberauth/jwtop/jwt/crack/checks/no_verification"
)

func TestCheck_Skip_Offline(t *testing.T) {
	store := harnessx.NewStaticResultStore()
	target := harnessx.Target{Data: &checkbase.ProbeCtx{Offline: true}}

	reason := noverification.Check.Skip.Eval(context.Background(), target, store)
	assert.NotEmpty(t, reason)
}

func TestCheck_Skip_RunsWhenOnline(t *testing.T) {
	store := harnessx.NewStaticResultStore()
	target := harnessx.Target{Data: &checkbase.ProbeCtx{Offline: false}}

	reason := noverification.Check.Skip.Eval(context.Background(), target, store)
	assert.Empty(t, reason)
}

func TestCheck_Run_VulnerableWhenBaselineBelow400(t *testing.T) {
	store := harnessx.NewStaticResultStore(
		harnessx.ResultData(checkbase.CheckIDBaseline, 200),
	)
	target := harnessx.Target{Data: &checkbase.ProbeCtx{InvalidToken: "invalid.token.here"}}

	result, err := noverification.Check.Run(context.Background(), target, store)
	assert.NoError(t, err)
	pr, ok := harnessx.DataAs[checkbase.ProbeResult](result)
	assert.True(t, ok)
	assert.True(t, pr.Vulnerable)
}

func TestCheck_Run_NotVulnerableWhenBaseline401(t *testing.T) {
	store := harnessx.NewStaticResultStore(
		harnessx.ResultData(checkbase.CheckIDBaseline, 401),
	)
	target := harnessx.Target{Data: &checkbase.ProbeCtx{InvalidToken: "invalid.token.here"}}

	result, err := noverification.Check.Run(context.Background(), target, store)
	assert.NoError(t, err)
	pr, ok := harnessx.DataAs[checkbase.ProbeResult](result)
	assert.True(t, ok)
	assert.False(t, pr.Vulnerable)
}
