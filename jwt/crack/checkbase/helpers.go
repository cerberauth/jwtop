package checkbase

import (
	"context"
	"net/http"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/probe"
)

func SendProbe(ctx context.Context, p *probe.Probe, url string, token string, store harnessx.ResultStore) (harnessx.Result, error) {
	baseline, _ := harnessx.GetData[int](store, CheckIDBaseline)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return harnessx.Result{}, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := p.Client().Do(req)
	if err != nil {
		return harnessx.Result{}, err
	}
	resp.Body.Close()
	pr := ProbeResult{Token: token, Status: resp.StatusCode, Vulnerable: resp.StatusCode != baseline}
	return harnessx.DataResult(pr), nil
}

func SkippedProbeResult(reason string) harnessx.Result {
	r := harnessx.DataResult(ProbeResult{Skipped: true, SkipReason: reason})
	r.Skipped = true
	r.SkipReason = reason
	return r
}
