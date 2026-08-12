package checkbase

import (
	"context"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/checkdef"
)

// TokenFunc computes the exploit-mutated token to probe with, from the
// shared probe context.
type TokenFunc func(pctx *ProbeCtx) (string, error)

// SendToken sends token as the probe payload and compares the response to
// the baseline, or — if err is non-nil — returns err wrapped as a Result.
// It's the shared tail end of every token-substitution check, exported so a
// check with a bespoke Run (e.g. an offline-only fallback) can still reuse
// it for its online path.
func SendToken(ctx context.Context, target harnessx.Target, store harnessx.ResultStore, token string, err error) (harnessx.Result, error) {
	if err != nil {
		r := harnessx.DataResult(ProbeResult{Err: err})
		r.Err = err
		return r, nil
	}
	pctx := target.Data.(*ProbeCtx)
	return SendProbe(ctx, pctx.Probe, target.URL, token, pctx.TokenLocation, store)
}

// NewTokenCheck builds the common "mutate the token, send it, compare to
// baseline" Check. tokenFn is the one line that differs between these
// checks; skip wiring, error handling, and sending the probe are shared.
func NewTokenCheck(def CheckDef, skip harnessx.SkipDecision, tokenFn TokenFunc) harnessx.Check {
	return checkdef.NewCheck(def, func(ctx context.Context, target harnessx.Target, store harnessx.ResultStore) (harnessx.Result, error) {
		token, err := tokenFn(target.Data.(*ProbeCtx))
		return SendToken(ctx, target, store, token, err)
	}, checkdef.WithSkip(skip))
}
