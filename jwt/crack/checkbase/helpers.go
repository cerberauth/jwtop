package checkbase

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/probe"
)

// NewTokenRequest builds the probe request with the token placed at loc.
// loc should already have WithDefaults() applied.
func NewTokenRequest(ctx context.Context, target string, token string, loc TokenLocation) (*http.Request, error) {
	value := loc.Prefix + token
	method := http.MethodGet
	var body io.Reader
	if loc.In == TokenLocationBody {
		method = http.MethodPost
		form := url.Values{}
		form.Set(loc.Name, value)
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(ctx, method, target, body)
	if err != nil {
		return nil, err
	}
	switch loc.In {
	case TokenLocationCookie:
		req.AddCookie(&http.Cookie{
			Name:     loc.Name,
			Value:    value,
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
		})
	case TokenLocationQuery:
		q := req.URL.Query()
		q.Set(loc.Name, value)
		req.URL.RawQuery = q.Encode()
	case TokenLocationBody:
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	default:
		req.Header.Set(loc.Name, value)
	}
	return req, nil
}

func SendProbe(ctx context.Context, p *probe.Probe, target string, token string, loc TokenLocation, store harnessx.ResultStore) (harnessx.Result, error) {
	baseline, _ := harnessx.GetData[int](store, CheckIDBaseline)
	req, err := NewTokenRequest(ctx, target, token, loc)
	if err != nil {
		return harnessx.Result{}, err
	}
	resp, err := p.Client().Do(req)
	if err != nil {
		return harnessx.Result{}, err
	}
	resp.Body.Close()
	pr := ProbeResult{Payload: token, Status: resp.StatusCode, Vulnerable: resp.StatusCode != baseline}
	return harnessx.DataResult(pr), nil
}

func SkippedProbeResult(reason string) harnessx.Result {
	r := harnessx.DataResult(ProbeResult{Skipped: true, SkipReason: reason})
	r.Skipped = true
	r.SkipReason = reason
	return r
}
