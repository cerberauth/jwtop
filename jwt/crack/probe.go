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
	jwkinjection "github.com/cerberauth/jwtop/jwt/crack/checks/jwk_injection"
	kidpathtraversal "github.com/cerberauth/jwtop/jwt/crack/checks/kid_path_traversal"
	kidsqlinjection "github.com/cerberauth/jwtop/jwt/crack/checks/kid_sql_injection"
	noverification "github.com/cerberauth/jwtop/jwt/crack/checks/no_verification"
	nullsignature "github.com/cerberauth/jwtop/jwt/crack/checks/null_signature"
	psychicsignature "github.com/cerberauth/jwtop/jwt/crack/checks/psychic_signature"
	weaksecret "github.com/cerberauth/jwtop/jwt/crack/checks/weak_secret"
)

type ProbeResult = checkbase.ProbeResult

type CheckDef = checkbase.CheckDef

// TokenLocation describes where the exploited JWT is placed in probe
// requests. See checkbase.TokenLocation for details and defaults.
type TokenLocation = checkbase.TokenLocation

const BaselineCheckID = checkbase.CheckIDBaseline

type ProbeOptions struct {
	URL            string
	ExpectedStatus int
	PublicKeyPEM   []byte
	Candidates     []string
	Workers        int
	Probe          *probe.Probe
	Reporters      []harnessx.Reporter
	KidSQLTable    string
	KidPath        string
	TokenLocation  TokenLocation
}

// buildChecks returns the full set of registered checks along with a
// per-check metadata map (name plus CVSS/CWE/OWASP scoring) keyed by
// CheckID, since harnessx.Check itself carries no scoring metadata.
func buildChecks() ([]harnessx.Check, map[harnessx.CheckID]CheckDef) {
	checks := make([]harnessx.Check, 0, len(algnone.Checks)+10)
	checks = append(checks, baseline.Check, noverification.Check)
	checks = append(checks, algnone.Checks...)
	checks = append(checks,
		blanksecret.Check,
		nullsignature.Check,
		hmacconfusion.Check,
		psychicsignature.Check,
		kidsqlinjection.Check,
		kidpathtraversal.Check,
		jwkinjection.Check,
		weaksecret.Check,
	)

	defs := make(map[harnessx.CheckID]CheckDef, len(checks))
	for _, c := range algnone.Checks {
		defs[c.ID] = algnone.Def
	}
	defs[noverification.Check.ID] = noverification.Def
	defs[blanksecret.Check.ID] = blanksecret.Def
	defs[nullsignature.Check.ID] = nullsignature.Def
	defs[hmacconfusion.Check.ID] = hmacconfusion.Def
	defs[psychicsignature.Check.ID] = psychicsignature.Def
	defs[kidsqlinjection.Check.ID] = kidsqlinjection.Def
	defs[kidpathtraversal.Check.ID] = kidpathtraversal.Def
	defs[jwkinjection.Check.ID] = jwkinjection.Def
	defs[weaksecret.Check.ID] = weaksecret.Def
	for _, c := range checks {
		def := defs[c.ID]
		def.Name = c.Name
		defs[c.ID] = def
	}
	return checks, defs
}

// CheckDefs returns per-check metadata (name, CVSS, CWE, OWASP, link,
// description) keyed by CheckID, for callers that need to enrich results
// outside of ProbeAll (e.g. a harnessx.Reporter).
func CheckDefs() map[harnessx.CheckID]CheckDef {
	_, defs := buildChecks()
	return defs
}

func ProbeAll(ctx context.Context, tokenString string, opts ProbeOptions) ([]ProbeResult, int, error) {
	if err := opts.TokenLocation.Validate(); err != nil {
		return nil, 0, err
	}
	offline := opts.URL == ""
	p := opts.Probe
	if p == nil && !offline {
		p = probe.New()
	}
	pctx := &checkbase.ProbeCtx{
		TokenString: tokenString, Probe: p, PublicKeyPEM: opts.PublicKeyPEM,
		Candidates: opts.Candidates, Workers: opts.Workers, ExpectedStatus: opts.ExpectedStatus,
		Offline: offline, KidSQLTable: opts.KidSQLTable, KidPath: opts.KidPath,
		TokenLocation: opts.TokenLocation.WithDefaults(),
	}

	checks, defs := buildChecks()

	var engineOpts []harnessx.Option
	if len(opts.Reporters) > 0 {
		engineOpts = append(engineOpts, harnessx.WithReporters(opts.Reporters...))
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
				pr.Name = defs[r.CheckID].Name
			}
			results = append(results, pr)
		} else if r.Skipped {
			results = append(results, ProbeResult{
				Name:       defs[r.CheckID].Name,
				Skipped:    true,
				SkipReason: r.SkipReason,
			})
		}
	}
	return results, baselineStatus, nil
}
