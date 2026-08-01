package weaksecret

import (
	"context"
	"errors"
	"testing"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/jwtop/jwt/crack/checkbase"
	"github.com/cerberauth/jwtop/jwt/exploit"
	"github.com/cerberauth/jwtop/jwt/exploit/external"
	jwtlib "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// This file uses the internal `weaksecret` package (not `weaksecret_test`)
// specifically to reach the unexported crackWithJohn/crackWithHashcat seams
// without spawning real john/hashcat processes.

func makeHS256Token(t *testing.T, secret string) string {
	t.Helper()
	tok := jwtlib.NewWithClaims(jwtlib.SigningMethodHS256, jwtlib.MapClaims{"sub": "user1"})
	s, err := tok.SignedString([]byte(secret))
	require.NoError(t, err)
	return s
}

func withFakeExternals(t *testing.T, john, hashcat func(context.Context, string, []string, any) (external.ExternalCrackResult, error)) {
	t.Helper()
	origJohn, origHashcat := crackWithJohn, crackWithHashcat
	t.Cleanup(func() { crackWithJohn, crackWithHashcat = origJohn, origHashcat })

	if john != nil {
		crackWithJohn = func(ctx context.Context, token string, candidates []string, opts external.JohnOptions) (external.ExternalCrackResult, error) {
			return john(ctx, token, candidates, opts)
		}
	}
	if hashcat != nil {
		crackWithHashcat = func(ctx context.Context, token string, candidates []string, opts external.HashcatOptions) (external.ExternalCrackResult, error) {
			return hashcat(ctx, token, candidates, opts)
		}
	}
}

func runCheck(t *testing.T, pctx *checkbase.ProbeCtx) harnessx.Result {
	t.Helper()
	store := harnessx.NewStaticResultStore()
	target := harnessx.Target{Data: pctx}
	result, err := Check.Run(context.Background(), target, store)
	require.NoError(t, err)
	return result
}

func TestCheck_Run_BuiltinFoundSkipsExternal(t *testing.T) {
	johnCalled := false
	withFakeExternals(t,
		func(context.Context, string, []string, any) (external.ExternalCrackResult, error) {
			johnCalled = true
			return external.ExternalCrackResult{}, nil
		}, nil)

	token := makeHS256Token(t, "hunter2")
	pctx := &checkbase.ProbeCtx{
		TokenString: token, Candidates: []string{"hunter2"}, Workers: 1,
		ExternalTools: checkbase.ExternalToolOptions{UseJohn: true},
	}
	result := runCheck(t, pctx)

	pr, ok := harnessx.DataAs[checkbase.ProbeResult](result)
	require.True(t, ok)
	assert.True(t, pr.Vulnerable)
	assert.False(t, johnCalled, "builtin already found the secret; john must not be invoked")
}

func TestCheck_Run_FallsBackToJohnWhenBuiltinMisses(t *testing.T) {
	var events []checkbase.ExternalToolEvent
	withFakeExternals(t,
		func(_ context.Context, token string, _ []string, _ any) (external.ExternalCrackResult, error) {
			return external.ExternalCrackResult{
				CrackResult: exploit.CrackResult{Found: true, Secret: "fromjohn"},
				Format:      "HMAC-SHA256", ExitCode: 0, CandidatesCount: 3,
			}, nil
		}, nil)

	token := makeHS256Token(t, "fromjohn")
	pctx := &checkbase.ProbeCtx{
		TokenString: token, Candidates: []string{"wrong"}, Workers: 1,
		ExternalTools:      checkbase.ExternalToolOptions{UseJohn: true},
		ExternalToolEvents: &events,
	}
	result := runCheck(t, pctx)

	pr, ok := harnessx.DataAs[checkbase.ProbeResult](result)
	require.True(t, ok)
	assert.True(t, pr.Vulnerable)
	assert.Contains(t, pr.Extra, "fromjohn")
	require.Len(t, events, 1)
	assert.Equal(t, "john", events[0].Tool)
	assert.Equal(t, "success", events[0].Outcome)
}

func TestCheck_Run_FallsBackToHashcatWhenJohnMisses(t *testing.T) {
	var events []checkbase.ExternalToolEvent
	withFakeExternals(t,
		func(context.Context, string, []string, any) (external.ExternalCrackResult, error) {
			return external.ExternalCrackResult{Format: "HMAC-SHA256"}, nil // not found
		},
		func(_ context.Context, token string, _ []string, _ any) (external.ExternalCrackResult, error) {
			return external.ExternalCrackResult{
				CrackResult: exploit.CrackResult{Found: true, Secret: "fromhashcat"},
				Format:      "16500",
			}, nil
		})

	token := makeHS256Token(t, "fromhashcat")
	pctx := &checkbase.ProbeCtx{
		TokenString: token, Candidates: []string{"wrong"}, Workers: 1,
		ExternalTools:      checkbase.ExternalToolOptions{UseJohn: true, UseHashcat: true},
		ExternalToolEvents: &events,
	}
	result := runCheck(t, pctx)

	pr, ok := harnessx.DataAs[checkbase.ProbeResult](result)
	require.True(t, ok)
	assert.True(t, pr.Vulnerable)
	assert.Contains(t, pr.Extra, "fromhashcat")
	require.Len(t, events, 2)
	assert.Equal(t, "john", events[0].Tool)
	assert.Equal(t, "notfound", events[0].Outcome)
	assert.Equal(t, "hashcat", events[1].Tool)
	assert.Equal(t, "success", events[1].Outcome)
}

func TestCheck_Run_ExternalToolTimeout(t *testing.T) {
	var events []checkbase.ExternalToolEvent
	withFakeExternals(t,
		func(context.Context, string, []string, any) (external.ExternalCrackResult, error) {
			return external.ExternalCrackResult{TimedOut: true, ExitCode: -1}, external.ErrTimedOut
		}, nil)

	token := makeHS256Token(t, "neverfound")
	pctx := &checkbase.ProbeCtx{
		TokenString: token, Candidates: []string{"wrong"}, Workers: 1,
		ExternalTools:      checkbase.ExternalToolOptions{UseJohn: true},
		ExternalToolEvents: &events,
	}
	result := runCheck(t, pctx)

	assert.True(t, result.Skipped)
	require.Len(t, events, 1)
	assert.Equal(t, "timeout", events[0].Outcome)
	assert.True(t, errors.Is(events[0].Err, external.ErrTimedOut))
}

func TestCheck_Run_NeitherExternalToolEnabled(t *testing.T) {
	johnCalled, hashcatCalled := false, false
	withFakeExternals(t,
		func(context.Context, string, []string, any) (external.ExternalCrackResult, error) {
			johnCalled = true
			return external.ExternalCrackResult{}, nil
		},
		func(context.Context, string, []string, any) (external.ExternalCrackResult, error) {
			hashcatCalled = true
			return external.ExternalCrackResult{}, nil
		})

	token := makeHS256Token(t, "neverfound")
	pctx := &checkbase.ProbeCtx{TokenString: token, Candidates: []string{"wrong"}, Workers: 1}
	result := runCheck(t, pctx)

	assert.True(t, result.Skipped)
	assert.False(t, johnCalled)
	assert.False(t, hashcatCalled)
}
