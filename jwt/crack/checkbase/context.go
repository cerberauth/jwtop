package checkbase

import (
	"time"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/checkdef"
	"github.com/cerberauth/harnessx/probe"
	"github.com/cerberauth/x/reportx/harnessreport"
)

const CheckIDBaseline harnessx.CheckID = "baseline"

const (
	TokenLocationHeader = probe.CredentialLocationHeader
	TokenLocationCookie = probe.CredentialLocationCookie
	TokenLocationQuery  = probe.CredentialLocationQuery
	TokenLocationBody   = probe.CredentialLocationBody
)

type ProbeResult = harnessreport.Result

// TokenLocation describes where the exploited JWT is placed in the probe
// request — an alias for harnessx/probe's generic credential-placement type,
// since injecting a JWT for testing is just injecting a credential.
// Authorization: Bearer is only the default — the token can also be
// injected into a custom header, a cookie, a query parameter, or a
// form-encoded request body.
type TokenLocation = probe.CredentialLocation

// DefaultTokenLocation returns the historical behaviour: the token sent as
// an Authorization: Bearer <token> header.
func DefaultTokenLocation() TokenLocation {
	return TokenLocation{In: TokenLocationHeader, Name: "Authorization", Prefix: "Bearer "}
}

type ProbeCtx struct {
	TokenString        string
	IsHMAC             bool
	IsAsymmetric       bool
	Alg                string
	InvalidToken       string
	AlgNoneTokens      []string
	AlgNoneErr         error
	Probe              *probe.Probe
	PublicKeyPEM       []byte
	Candidates         []string
	Workers            int
	ExpectedStatus     int
	Offline            bool
	KidSQLTable        string
	KidPath            string
	TokenLocation      TokenLocation
	ExternalTools      ExternalToolOptions
	ExternalToolEvents *[]ExternalToolEvent
	JKUServerAddr      string
	X5UServerAddr      string
}

// ExternalToolOptions controls whether the weak-secret check falls back to
// the optional external john-the-ripper / hashcat CLI tools when the
// built-in in-process dictionary brute-force doesn't find the secret.
// Passing a *Path override implies enabling that tool — callers don't need
// to also set the corresponding Use* flag.
type ExternalToolOptions struct {
	UseJohn     bool
	JohnPath    string
	UseHashcat  bool
	HashcatPath string
	Timeout     time.Duration
}

// ExternalToolEvent records the outcome of one external-tool crack attempt,
// for the caller that owns telemetry (cmd/*.go) to report after ProbeAll
// returns. It deliberately carries none of the JWT under test nor the
// cracked secret itself — only operational data about the tool run.
type ExternalToolEvent struct {
	Tool            string // "john" | "hashcat"
	Outcome         string // "success" | "notfound" | "error" | "timeout"
	Err             error
	Duration        time.Duration
	ExitCode        int
	TimedOut        bool
	Format          string
	ToolVersion     string
	DeviceBackend   string
	CandidatesCount int
}

type CheckDef = checkdef.CheckDef
