package algnone_test

import (
	"context"
	"testing"

	"github.com/cerberauth/harnessx"
	"github.com/stretchr/testify/assert"

	algnone "github.com/cerberauth/jwtop/jwt/crack/checks/alg_none"
	"github.com/cerberauth/jwtop/jwt/crack/checkbase"
)

func TestChecks_OneResultPerVariant(t *testing.T) {
	assert.Len(t, algnone.Checks, 4)
}

func TestChecks_First_Skip_EmptyWhenTokenAlreadyAlgNone(t *testing.T) {
	store := harnessx.NewStaticResultStore()
	target := harnessx.Target{Data: &checkbase.ProbeCtx{Alg: "none"}}

	reason := algnone.Checks[0].Skip.Eval(context.Background(), target, store)
	assert.Empty(t, reason)
}

func TestChecks_First_Skip_OfflineWhenTokenNotAlgNone(t *testing.T) {
	store := harnessx.NewStaticResultStore()
	target := harnessx.Target{Data: &checkbase.ProbeCtx{Alg: "HS256", Offline: true}}

	reason := algnone.Checks[0].Skip.Eval(context.Background(), target, store)
	assert.NotEmpty(t, reason)
}

func TestChecks_First_Skip_RunsOnlineWhenTokenNotAlgNone(t *testing.T) {
	store := harnessx.NewStaticResultStore()
	target := harnessx.Target{Data: &checkbase.ProbeCtx{Alg: "HS256", Offline: false}}

	reason := algnone.Checks[0].Skip.Eval(context.Background(), target, store)
	assert.Empty(t, reason)
}

func TestChecks_First_Run_VulnerableWhenTokenAlreadyAlgNone(t *testing.T) {
	store := harnessx.NewStaticResultStore()
	target := harnessx.Target{Data: &checkbase.ProbeCtx{Alg: "none"}}

	result, err := algnone.Checks[0].Run(context.Background(), target, store)
	assert.NoError(t, err)
	pr, ok := harnessx.DataAs[checkbase.ProbeResult](result)
	assert.True(t, ok)
	assert.True(t, pr.Vulnerable)
}

func TestChecks_First_Run_ReturnsErrorFromAlgNoneGeneration(t *testing.T) {
	store := harnessx.NewStaticResultStore()
	wantErr := assert.AnError
	target := harnessx.Target{Data: &checkbase.ProbeCtx{Alg: "HS256", AlgNoneErr: wantErr}}

	result, err := algnone.Checks[0].Run(context.Background(), target, store)
	assert.NoError(t, err)
	assert.Equal(t, wantErr, result.Err)
}
