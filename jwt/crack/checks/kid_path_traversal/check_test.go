package kidpathtraversal_test

import (
	"context"
	"testing"

	"github.com/cerberauth/harnessx"
	"github.com/stretchr/testify/assert"

	"github.com/cerberauth/jwtop/jwt/crack/checkbase"
	kidpathtraversal "github.com/cerberauth/jwtop/jwt/crack/checks/kid_path_traversal"
)

func TestCheck_Skip_Offline(t *testing.T) {
	store := harnessx.NewStaticResultStore()
	target := harnessx.Target{Data: &checkbase.ProbeCtx{Offline: true}}

	reason := kidpathtraversal.Check.Skip.Eval(context.Background(), target, store)
	assert.NotEmpty(t, reason)
}

func TestCheck_Skip_BlankSecretAlreadyVulnerable(t *testing.T) {
	store := harnessx.NewStaticResultStore(
		harnessx.ResultData("blanksecret", checkbase.ProbeResult{Vulnerable: true}),
	)
	target := harnessx.Target{Data: &checkbase.ProbeCtx{Offline: false}}

	reason := kidpathtraversal.Check.Skip.Eval(context.Background(), target, store)
	assert.NotEmpty(t, reason)
}

func TestCheck_Skip_RunsWhenOnlineAndNoBlankSecret(t *testing.T) {
	store := harnessx.NewStaticResultStore(
		harnessx.ResultData("blanksecret", checkbase.ProbeResult{Vulnerable: false}),
	)
	target := harnessx.Target{Data: &checkbase.ProbeCtx{Offline: false}}

	reason := kidpathtraversal.Check.Skip.Eval(context.Background(), target, store)
	assert.Empty(t, reason)
}
