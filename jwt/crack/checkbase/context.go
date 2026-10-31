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
	// JKUServerAddr is the bind address (host:port) for the local JWKS
	// server the jku_injection check stands up to host the forged key —
	// see exploit.NewJWKSServer, which this address is passed to, and
	// exploit.JKUInjectionWithLocalServer, which calls it and points the
	// token's jku header at the resulting (*JWKSServer).URL().
	//
	// It must be an address the *target server* can reach, not merely one
	// jwtop itself can bind. "127.0.0.1:0"/"localhost:0" only work when the
	// target runs on the same host as jwtop; against a remote target, bind
	// to a publicly reachable interface/port (e.g. "0.0.0.0:8089" behind a
	// port you've opened, or a tunnel's local endpoint) so the target's
	// outbound jku fetch actually lands on this server. Left empty, the
	// check is skipped — jwtop has no way to guess a reachable address.
	JKUServerAddr string
	// X5UServerAddr is the x5u_injection equivalent of JKUServerAddr: the
	// bind address for the local certificate server started via
	// exploit.NewCertServer / exploit.X5UInjectionWithLocalServer. The same
	// reachability requirement applies — it must be an address the target
	// can reach, not just jwtop.
	X5UServerAddr     string
	FuzzEnabled       bool
	FuzzMaxStringLen  int
	CrackedHMACSecret string
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
