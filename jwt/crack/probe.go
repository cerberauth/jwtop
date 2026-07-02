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
	KidSQLTable    string
	KidPath        string
}

func ProbeAll(ctx context.Context, tokenString string, opts ProbeOptions) ([]ProbeResult, int, error) {
	offline := opts.URL == ""
	p := opts.Probe
	if p == nil && !offline {
		p = probe.New()
	}
	pctx := &checkbase.ProbeCtx{
		TokenString:    tokenString,
		Probe:          p,
		PublicKeyPEM:   opts.PublicKeyPEM,
		Candidates:     opts.Candidates,
		Workers:        opts.Workers,
		ExpectedStatus: opts.ExpectedStatus,
		Offline:        offline,
		KidSQLTable:    opts.KidSQLTable,
		KidPath:        opts.KidPath,
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
	checkDefs := make(map[harnessx.CheckID]checkbase.CheckDef, len(checks))
	for _, c := range checks {
		checkNames[c.ID] = c.Name
	}
	// map each alg_none variant back to the shared Def
	for _, c := range algnone.Checks {
		checkDefs[c.ID] = algnone.Def
	}
	checkDefs[noverification.Check.ID] = noverification.Def
	checkDefs[blanksecret.Check.ID] = blanksecret.Def
	checkDefs[nullsignature.Check.ID] = nullsignature.Def
	checkDefs[hmacconfusion.Check.ID] = hmacconfusion.Def
	checkDefs[kidsqlinjection.Check.ID] = kidsqlinjection.Def
	checkDefs[kidpathtraversal.Check.ID] = kidpathtraversal.Def
	checkDefs[weaksecret.Check.ID] = weaksecret.Def

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
		def := checkDefs[r.CheckID]
		if pr, ok := harnessx.DataAs[ProbeResult](r); ok {
			if pr.Name == "" {
				pr.Name = checkNames[r.CheckID]
			}
			pr.CVSSVector = def.CVSSVector
			pr.CVSSScore = def.CVSSScore
			pr.CWEID = def.CWEID
			pr.OWASP = def.OWASP
			pr.Link = def.Link
			pr.Description = def.Description
			results = append(results, pr)
		} else if r.Skipped {
			results = append(results, ProbeResult{
				Name:        checkNames[r.CheckID],
				Skipped:     true,
				SkipReason:  r.SkipReason,
				CVSSVector:  def.CVSSVector,
				CVSSScore:   def.CVSSScore,
				CWEID:       def.CWEID,
				OWASP:       def.OWASP,
				Link:        def.Link,
				Description: def.Description,
			})
		}
	}
	return results, baselineStatus, nil
}
