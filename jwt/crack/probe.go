package crack

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/probe"
	"github.com/cerberauth/jwtop/jwt/crack/checkbase"
	algnone "github.com/cerberauth/jwtop/jwt/crack/checks/alg_none"
	"github.com/cerberauth/jwtop/jwt/crack/checks/baseline"
	blanksecret "github.com/cerberauth/jwtop/jwt/crack/checks/blank_secret"
	claimfuzz "github.com/cerberauth/jwtop/jwt/crack/checks/fuzz"
	hmacconfusion "github.com/cerberauth/jwtop/jwt/crack/checks/hmac_confusion"
	jkuinjection "github.com/cerberauth/jwtop/jwt/crack/checks/jku_injection"
	jwkinjection "github.com/cerberauth/jwtop/jwt/crack/checks/jwk_injection"
	kidpathtraversal "github.com/cerberauth/jwtop/jwt/crack/checks/kid_path_traversal"
	kidsqlinjection "github.com/cerberauth/jwtop/jwt/crack/checks/kid_sql_injection"
	noverification "github.com/cerberauth/jwtop/jwt/crack/checks/no_verification"
	nullsignature "github.com/cerberauth/jwtop/jwt/crack/checks/null_signature"
	psychicsignature "github.com/cerberauth/jwtop/jwt/crack/checks/psychic_signature"
	weaksecret "github.com/cerberauth/jwtop/jwt/crack/checks/weak_secret"
	x5cinjection "github.com/cerberauth/jwtop/jwt/crack/checks/x5c_injection"
	x5uinjection "github.com/cerberauth/jwtop/jwt/crack/checks/x5u_injection"
)

type ProbeResult = checkbase.ProbeResult

type CheckDef = checkbase.CheckDef

// TokenLocation describes where the exploited JWT is placed in probe
// requests. See checkbase.TokenLocation for details and defaults.
type TokenLocation = checkbase.TokenLocation

const BaselineCheckID = checkbase.CheckIDBaseline

type ExternalToolOptions = checkbase.ExternalToolOptions

type ExternalToolEvent = checkbase.ExternalToolEvent

type ProbeOptions struct {
	URL                string
	ExpectedStatus     int
	PublicKeyPEM       []byte
	Candidates         []string
	Workers            int
	Delay              time.Duration
	Probe              *probe.Probe
	Reporters          []harnessx.Reporter
	KidSQLTable        string
	KidPath            string
	TokenLocation      TokenLocation
	ExternalTools      ExternalToolOptions
	ExternalToolEvents *[]ExternalToolEvent
	JKUServerAddr      string
	X5UServerAddr      string
	Fuzz               bool
	FuzzMaxStringLen   int
}

// buildChecks returns the full set of registered checks along with a
// per-check metadata map (name plus CVSS/CWE/OWASP scoring) keyed by
// CheckID, since harnessx.Check itself carries no scoring metadata.
// BuildChecks returns the full jwtop JWT check registry (baseline + every
// crack check) and their metadata, in dependency order. Exported so callers
// embedding jwtop's checks in their own harnessx.Engine (rather than going
// through ProbeAll) build the exact same check list ProbeAll uses.
func BuildChecks() ([]harnessx.Check, map[harnessx.CheckID]CheckDef) {
	checks := []harnessx.Check{
		baseline.Check, noverification.Check,
		algnone.Check,
		blanksecret.Check,
		nullsignature.Check,
		hmacconfusion.Check,
		psychicsignature.Check,
		kidsqlinjection.Check,
		kidpathtraversal.Check,
		jwkinjection.Check,
		jkuinjection.Check,
		x5cinjection.Check,
		x5uinjection.Check,
		weaksecret.Check,
		claimfuzz.Check,
	}

	defs := make(map[harnessx.CheckID]CheckDef, len(checks))
	defs[algnone.Check.ID] = algnone.Def
	defs[noverification.Check.ID] = noverification.Def
	defs[blanksecret.Check.ID] = blanksecret.Def
	defs[nullsignature.Check.ID] = nullsignature.Def
	defs[hmacconfusion.Check.ID] = hmacconfusion.Def
	defs[psychicsignature.Check.ID] = psychicsignature.Def
	defs[kidsqlinjection.Check.ID] = kidsqlinjection.Def
	defs[kidpathtraversal.Check.ID] = kidpathtraversal.Def
	defs[jwkinjection.Check.ID] = jwkinjection.Def
	defs[jkuinjection.Check.ID] = jkuinjection.Def
	defs[x5cinjection.Check.ID] = x5cinjection.Def
	defs[x5uinjection.Check.ID] = x5uinjection.Def
	defs[weaksecret.Check.ID] = weaksecret.Def
	defs[claimfuzz.Check.ID] = claimfuzz.Def
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
	_, defs := BuildChecks()
	return defs
}

func ProbeAll(ctx context.Context, tokenString string, opts ProbeOptions) ([]ProbeResult, int, error) {
	if err := opts.TokenLocation.Validate(); err != nil {
		return nil, 0, err
	}
	offline := opts.URL == ""
	p := opts.Probe
	if p == nil && !offline {
		var probeOpts []probe.Option
		if opts.Delay > 0 {
			probeOpts = append(probeOpts, probe.WithTransport(&delayTransport{delay: opts.Delay, base: http.DefaultTransport}))
		}
		p = probe.New(probeOpts...)
	}
	pctx := &checkbase.ProbeCtx{
		TokenString: tokenString, Probe: p, PublicKeyPEM: opts.PublicKeyPEM,
		Candidates: opts.Candidates, Workers: opts.Workers, ExpectedStatus: opts.ExpectedStatus,
		Offline: offline, KidSQLTable: opts.KidSQLTable, KidPath: opts.KidPath,
		TokenLocation:      opts.TokenLocation.WithDefaults(),
		ExternalTools:      opts.ExternalTools,
		ExternalToolEvents: opts.ExternalToolEvents,
		JKUServerAddr:      opts.JKUServerAddr,
		X5UServerAddr:      opts.X5UServerAddr,
		FuzzEnabled:        opts.Fuzz,
		FuzzMaxStringLen:   opts.FuzzMaxStringLen,
	}

	checks, defs := BuildChecks()

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
			baselineSnap, _ := harnessx.DataAs[harnessx.Snapshot](r)
			baselineStatus = baselineSnap.StatusCode
			continue
		}
		if pr, ok := harnessx.DataAs[ProbeResult](r); ok {
			if pr.Name == "" {
				pr.Name = defs[r.CheckID].Name
			}
			results = append(results, pr)
		} else if pr, ok := checkbase.ResolveVariantResult(r.Attempts); ok {
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

// delayTransport enforces a minimum spacing of delay between outgoing
// requests, so probe requests are spread out to avoid tripping target rate
// limits or WAFs. Checks run concurrently, so spacing is serialized across
// all callers sharing the transport rather than applied independently per
// request.
type delayTransport struct {
	delay time.Duration
	base  http.RoundTripper

	mu   sync.Mutex
	next time.Time
}

func (t *delayTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := t.wait(req.Context()); err != nil {
		return nil, err
	}
	return t.base.RoundTrip(req)
}

func (t *delayTransport) wait(ctx context.Context) error {
	t.mu.Lock()
	now := time.Now()
	start := now
	if t.next.After(start) {
		start = t.next
	}
	t.next = start.Add(t.delay)
	t.mu.Unlock()

	d := start.Sub(now)
	if d <= 0 {
		return nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
