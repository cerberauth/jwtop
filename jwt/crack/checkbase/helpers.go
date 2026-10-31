package checkbase

import (
	"context"
	"net/http"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/probe"
)

// RequestBuilder mirrors ProbeCtx.NewRequest's signature: given the token
// under test, it returns the base request to send (before the token is
// placed on it at a TokenLocation).
type RequestBuilder func(ctx context.Context, token string) (*http.Request, error)

// NewTokenRequest builds the probe request with the token placed at loc.
// loc should already have WithDefaults() applied.
//
// newRequest is optional (pass none, or ProbeCtx.NewRequest) — a variadic
// slot rather than a plain parameter so existing callers keep compiling
// unchanged. When newRequest[0] is nil or omitted, this is the historical
// behavior: a fresh GET to target carrying only the token
// (probe.NewCredentialRequest). When set, it builds the base request via
// newRequest[0](ctx, token) and places the token on it with
// probe.ApplyCredential instead.
func NewTokenRequest(ctx context.Context, target string, token string, loc TokenLocation, newRequest ...RequestBuilder) (*http.Request, error) {
	var build RequestBuilder
	if len(newRequest) > 0 {
		build = newRequest[0]
	}
	if build == nil {
		return probe.NewCredentialRequest(ctx, target, token, loc)
	}
	req, err := build(ctx, token)
	if err != nil {
		return nil, err
	}
	return probe.ApplyCredential(req, token, loc)
}

// SendProbe sends token as the probe payload and compares the response to
// the baseline stored under CheckIDBaseline. newRequest is optional (see
// NewTokenRequest) and should be the check's ProbeCtx.NewRequest when set.
func SendProbe(ctx context.Context, p *probe.Probe, target string, token string, loc TokenLocation, store harnessx.ResultStore, newRequest ...RequestBuilder) (harnessx.Result, error) {
	current, vulnerable, err := harnessx.ProbeAndCompareBaseline(ctx, p, func(ctx context.Context) (*http.Request, error) {
		return NewTokenRequest(ctx, target, token, loc, newRequest...)
	}, store, CheckIDBaseline)
	if err != nil {
		return harnessx.Result{}, err
	}
	pr := ProbeResult{Payload: token, Status: current.StatusCode, Vulnerable: vulnerable}
	return harnessx.DataResult(pr), nil
}

func SkippedProbeResult(reason string) harnessx.Result {
	r := harnessx.DataResult(ProbeResult{Skipped: true, SkipReason: reason})
	r.Skipped = true
	r.SkipReason = reason
	return r
}
