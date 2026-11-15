package crack

import (
	"context"
	"net/http"
	"time"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/probe"
	"github.com/cerberauth/jwtop/jwt/crack/checkbase"
	algnone "github.com/cerberauth/jwtop/jwt/crack/checks/alg_none"
	audiencenotvalidated "github.com/cerberauth/jwtop/jwt/crack/checks/audience_not_validated"
	"github.com/cerberauth/jwtop/jwt/crack/checks/baseline"
	blanksecret "github.com/cerberauth/jwtop/jwt/crack/checks/blank_secret"
	claimremoval "github.com/cerberauth/jwtop/jwt/crack/checks/claim_removal"
	expiredaccepted "github.com/cerberauth/jwtop/jwt/crack/checks/expired_accepted"
	claimfuzz "github.com/cerberauth/jwtop/jwt/crack/checks/fuzz"
	hmacconfusion "github.com/cerberauth/jwtop/jwt/crack/checks/hmac_confusion"
	issuernotvalidated "github.com/cerberauth/jwtop/jwt/crack/checks/issuer_not_validated"
	jkuinjection "github.com/cerberauth/jwtop/jwt/crack/checks/jku_injection"
	jwkinjection "github.com/cerberauth/jwtop/jwt/crack/checks/jwk_injection"
	kidpathtraversal "github.com/cerberauth/jwtop/jwt/crack/checks/kid_path_traversal"
	kidsqlinjection "github.com/cerberauth/jwtop/jwt/crack/checks/kid_sql_injection"
	longlifetime "github.com/cerberauth/jwtop/jwt/crack/checks/long_lifetime"
	missingexpiry "github.com/cerberauth/jwtop/jwt/crack/checks/missing_expiry"
	noverification "github.com/cerberauth/jwtop/jwt/crack/checks/no_verification"
	nullsignature "github.com/cerberauth/jwtop/jwt/crack/checks/null_signature"
	psychicsignature "github.com/cerberauth/jwtop/jwt/crack/checks/psychic_signature"
	scopenotvalidated "github.com/cerberauth/jwtop/jwt/crack/checks/scope_not_validated"
	timestamptampering "github.com/cerberauth/jwtop/jwt/crack/checks/timestamp_tampering"
	weaksecret "github.com/cerberauth/jwtop/jwt/crack/checks/weak_secret"
	x5cinjection "github.com/cerberauth/jwtop/jwt/crack/checks/x5c_injection"
	x5uinjection "github.com/cerberauth/jwtop/jwt/crack/checks/x5u_injection"
	"golang.org/x/time/rate"
)

type ProbeResult = checkbase.ProbeResult

type variantResultReporter struct {
	harnessx.Reporter
}

func (r variantResultReporter) OnCheckComplete(result harnessx.Result) {
	if result.Data == nil {
		if pr, ok := checkbase.ResolveVariantResult(result.Attempts); ok {
			result.Data = pr
		}
	}
	r.Reporter.OnCheckComplete(result)
}

type CheckDef = checkbase.CheckDef

// TokenLocation describes where the exploited JWT is placed in probe
// requests. See checkbase.TokenLocation for details and defaults.
type TokenLocation = checkbase.TokenLocation

const BaselineCheckID = checkbase.CheckIDBaseline

type ExternalToolOptions = checkbase.ExternalToolOptions

type ExternalToolEvent = checkbase.ExternalToolEvent

type ProbeOptions struct {
	URL            string
	ExpectedStatus int
	PublicKeyPEM   []byte
	Candidates     []string
	Workers        int
	Delay          time.Duration
	Probe          *probe.Probe
	Reporters      []harnessx.Reporter
	Engine         *harnessx.Engine
	// KidSQLTable is deprecated: use KidSQLTables. When KidSQLTables is
	// empty and this is set, it seeds the list with this single value.
	KidSQLTable        string
	KidSQLTables       []string
	KidPath            string
	TokenLocation      TokenLocation
	ExternalTools      ExternalToolOptions
	ExternalToolEvents *[]ExternalToolEvent
	// JKUServerAddr / X5UServerAddr enable the jku_injection / x5u_injection
	// checks (skipped by default when unset) by giving jwtop a bind address
	// for the local JWKS / certificate server it stands up to host the
	// forged key material. The address must be reachable by the *target*
	// being probed, not merely by jwtop itself — see checkbase.ProbeCtx's
	// doc comments on these same two fields for the full requirement and
	// pointers to the underlying exploit.NewJWKSServer / NewCertServer.
	JKUServerAddr    string
	X5UServerAddr    string
	Fuzz             bool
	FuzzMaxStringLen int
	// NewRequest, when set, builds the base request used for every probe
	// (and the baseline capture) in place of a bare GET to URL — letting a
	// caller exercise a POST endpoint, one needing a request body, or one
	// needing extra headers. See checkbase.ProbeCtx's doc comment on the
	// same field for the full contract. Left nil, behavior is unchanged.
	NewRequest         func(ctx context.Context, token string) (*http.Request, error)
	OtherAudienceToken string
	OtherIssuerToken   string
	SigningKey         interface{}
	MaxTokenLifetime   time.Duration
}

// BuildChecks returns the full jwtop JWT check registry (baseline + every
// crack check) and their metadata, in dependency order. Exported so callers
// embedding jwtop's checks in their own harnessx.Engine (rather than going
// through ProbeAll) build the exact same check list ProbeAll uses.
//
// The baseline stays visible here: ProbeAll and its reporters read it. Use
// Checks to embed the pack.
func BuildChecks() ([]harnessx.Check, map[harnessx.CheckID]CheckDef) {
	checks, defs := buildChecks()
	for i := range checks {
		checks[i].Internal = false
	}
	return checks, defs
}

func buildChecks() ([]harnessx.Check, map[harnessx.CheckID]CheckDef) {
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
		timestamptampering.Check,
		claimfuzz.Check,
		missingexpiry.Check,
		longlifetime.Check,
		expiredaccepted.Check,
		audiencenotvalidated.Check,
		issuernotvalidated.Check,
		claimremoval.Check,
		scopenotvalidated.Check,
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
	defs[timestamptampering.Check.ID] = timestamptampering.Def
	defs[claimfuzz.Check.ID] = claimfuzz.Def
	defs[missingexpiry.Check.ID] = missingexpiry.Def
	defs[longlifetime.Check.ID] = longlifetime.Def
	defs[expiredaccepted.Check.ID] = expiredaccepted.Def
	defs[audiencenotvalidated.Check.ID] = audiencenotvalidated.Def
	defs[issuernotvalidated.Check.ID] = issuernotvalidated.Def
	defs[claimremoval.Check.ID] = claimremoval.Def
	defs[scopenotvalidated.Check.ID] = scopenotvalidated.Def
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

// NewProbeCtx builds the pack context every jwtop check reads from
// Target.Data, for the JWT tokenString.
func NewProbeCtx(tokenString string, opts ProbeOptions) (*checkbase.ProbeCtx, error) {
	if err := opts.TokenLocation.Validate(); err != nil {
		return nil, err
	}
	offline := opts.URL == ""
	p := opts.Probe
	if p == nil && !offline {
		var probeOpts []probe.Option
		if opts.Delay > 0 {
			probeOpts = append(probeOpts, probe.WithRateLimiter(rate.NewLimiter(rate.Every(opts.Delay), 1)))
		}
		p = probe.New(probeOpts...)
	}
	return &checkbase.ProbeCtx{
		TokenString: tokenString, Probe: p, PublicKeyPEM: opts.PublicKeyPEM,
		Candidates: opts.Candidates, Workers: opts.Workers, ExpectedStatus: opts.ExpectedStatus,
		Offline: offline, KidSQLTable: opts.KidSQLTable, KidSQLTables: opts.KidSQLTables, KidPath: opts.KidPath,
		TokenLocation:      opts.TokenLocation.WithDefaults(),
		ExternalTools:      opts.ExternalTools,
		ExternalToolEvents: opts.ExternalToolEvents,
		JKUServerAddr:      opts.JKUServerAddr,
		X5UServerAddr:      opts.X5UServerAddr,
		FuzzEnabled:        opts.Fuzz,
		FuzzMaxStringLen:   opts.FuzzMaxStringLen,
		NewRequest:         opts.NewRequest,
		OtherAudienceToken: opts.OtherAudienceToken,
		OtherIssuerToken:   opts.OtherIssuerToken,
		SigningKey:         opts.SigningKey,
		MaxTokenLifetime:   opts.MaxTokenLifetime,
	}, nil
}

// Checks returns the jwtop check pack: every check with a `jwt.` ID, the
// baseline marked internal and vulnerable probes reported as Observations, for
// embedding in another harnessx engine with harnessx/embed. Each check reads a
// *checkbase.ProbeCtx built by NewProbeCtx from Target.Data.
func Checks() []harnessx.Check {
	checks, _ := buildChecks()
	for i, c := range checks {
		checks[i] = checkbase.WithObservations(c)
	}
	return checks
}

func ProbeAll(ctx context.Context, tokenString string, opts ProbeOptions) ([]ProbeResult, int, error) {
	pctx, err := NewProbeCtx(tokenString, opts)
	if err != nil {
		return nil, 0, err
	}

	checks, defs := BuildChecks()

	var summary harnessx.ScanSummary
	if opts.Engine != nil {
		summary, err = opts.Engine.RunScenario(ctx, harnessx.Target{URL: opts.URL, Data: pctx}, harnessx.Scenario{Checks: checks})
	} else {
		var engineOpts []harnessx.Option
		if len(opts.Reporters) > 0 {
			reporters := make([]harnessx.Reporter, len(opts.Reporters))
			for i, r := range opts.Reporters {
				reporters[i] = variantResultReporter{r}
			}
			engineOpts = append(engineOpts, harnessx.WithReporters(reporters...))
		}
		engine := harnessx.New(engineOpts...)
		if regErr := engine.Register(checks...); regErr != nil {
			return nil, 0, regErr
		}
		summary, err = engine.Run(ctx, harnessx.Target{URL: opts.URL, Data: pctx})
	}
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
		} else if r.Err != nil {
			// The check's Run returned a plain error (e.g. the probe request
			// itself failed - network error, cancelled context, ...) instead
			// of a Result carrying ProbeResult data, so there's no payload to
			// recover. Surface it as an errored result rather than silently
			// dropping the check from results.
			results = append(results, ProbeResult{
				Name: defs[r.CheckID].Name,
				Err:  r.Err,
			})
		}
	}
	return results, baselineStatus, nil
}
