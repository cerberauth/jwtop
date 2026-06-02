package crack

import (
	"context"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/probe"
	"github.com/cerberauth/jwtop/jwt/crack/checkbase"
	algnone "github.com/cerberauth/jwtop/jwt/crack/checks/alg_none"
	"github.com/cerberauth/jwtop/jwt/crack/checks/baseline"
	blanksecret "github.com/cerberauth/jwtop/jwt/crack/checks/blank_secret"
	hmacconfusion "github.com/cerberauth/jwtop/jwt/crack/checks/hmac_confusion"
	kidpathtraversal "github.com/cerberauth/jwtop/jwt/crack/checks/kid_path_traversal"
	kidsqlinjection "github.com/cerberauth/jwtop/jwt/crack/checks/kid_sql_injection"
	noverification "github.com/cerberauth/jwtop/jwt/crack/checks/no_verification"
	nullsignature "github.com/cerberauth/jwtop/jwt/crack/checks/null_signature"
	weaksecret "github.com/cerberauth/jwtop/jwt/crack/checks/weak_secret"
)

type ProbeResult = checkbase.ProbeResult

type ProbeOptions struct {
	URL            string
	ExpectedStatus int
	PublicKeyPEM   []byte
	Candidates     []string
	Workers        int
	Probe          *probe.Probe
	Reporter       harnessx.Reporter
}

func ProbeAll(ctx context.Context, tokenString string, opts ProbeOptions) ([]ProbeResult, int, error) {
	p := opts.Probe
	if p == nil {
		p = probe.New()
	}
	pctx := &checkbase.ProbeCtx{
		TokenString:    tokenString,
		Probe:          p,
		PublicKeyPEM:   opts.PublicKeyPEM,
		Candidates:     opts.Candidates,
		Workers:        opts.Workers,
		ExpectedStatus: opts.ExpectedStatus,
	}

	checks := make([]harnessx.Check, 0, len(algnone.Checks)+8)
	checks = append(checks, baseline.Check, noverification.Check)
	checks = append(checks, algnone.Checks...)
	checks = append(checks,
		blanksecret.Check,
		nullsignature.Check,
		hmacconfusion.Check,
		kidsqlinjection.Check,
		kidpathtraversal.Check,
		weaksecret.Check,
	)

	checkNames := make(map[harnessx.CheckID]string, len(checks))
	for _, c := range checks {
		checkNames[c.ID] = c.Name
	}

	var engineOpts []harnessx.Option
	if opts.Reporter != nil {
		engineOpts = append(engineOpts, harnessx.WithReporters(opts.Reporter))
	}
	engine := harnessx.New(engineOpts...)
	if err := engine.Register(checks...); err != nil {
		return nil, 0, err
	}
	summary, err := engine.Run(ctx, harnessx.Target{URL: opts.URL, Data: pctx})
	if err != nil {
		return nil, 0, err
	}

	var results []ProbeResult
	var baselineStatus int
	for _, r := range summary.Results {
		if r.CheckID == checkbase.CheckIDBaseline {
			if r.Err != nil {
				return nil, 0, r.Err
			}
			baselineStatus, _ = harnessx.DataAs[int](r)
			continue
		}
		if pr, ok := harnessx.DataAs[ProbeResult](r); ok {
			if pr.Name == "" {
				pr.Name = checkNames[r.CheckID]
			}
			results = append(results, pr)
		} else if r.Skipped {
			results = append(results, ProbeResult{
				Name:       checkNames[r.CheckID],
				Skipped:    true,
				SkipReason: r.SkipReason,
			})
		}
	}
	return results, baselineStatus, nil
}
