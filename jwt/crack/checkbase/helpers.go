package checkbase

import (
	"context"
	"net/http"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/probe"
)

// NewTokenRequest builds the probe request with the token placed at loc.
// loc should already have WithDefaults() applied.
func NewTokenRequest(ctx context.Context, target string, token string, loc TokenLocation) (*http.Request, error) {
	return probe.NewCredentialRequest(ctx, target, token, loc)
}

func SendProbe(ctx context.Context, p *probe.Probe, target string, token string, loc TokenLocation, store harnessx.ResultStore) (harnessx.Result, error) {
	current, vulnerable, err := harnessx.ProbeAndCompareBaseline(ctx, p, func(ctx context.Context) (*http.Request, error) {
		return NewTokenRequest(ctx, target, token, loc)
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
