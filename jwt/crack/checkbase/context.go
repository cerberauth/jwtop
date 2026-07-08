package checkbase

import (
	"fmt"
	"strings"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/probe"
	xharnessx "github.com/cerberauth/x/harnessx"
	"github.com/cerberauth/x/reportx/harnessreport"
)

const CheckIDBaseline harnessx.CheckID = "baseline"

const (
	TokenLocationHeader = "header"
	TokenLocationCookie = "cookie"
	TokenLocationQuery  = "query"
	TokenLocationBody   = "body"
)

type ProbeResult = harnessreport.Result

// TokenLocation describes where the exploited JWT is placed in the probe
// request. Authorization: Bearer is only the default — the token can also
// be injected into a custom header, a cookie, a query parameter, or a
// form-encoded request body.
type TokenLocation struct {
	In     string // "header" (default), "cookie", "query", or "body"
	Name   string // header/cookie/query/form-field name
	Prefix string // value prefix, e.g. "Bearer "
}

// DefaultTokenLocation returns the historical behaviour: the token sent as
// an Authorization: Bearer <token> header.
func DefaultTokenLocation() TokenLocation {
	return TokenLocation{In: TokenLocationHeader, Name: "Authorization", Prefix: "Bearer "}
}

// WithDefaults fills unset fields, preserving the historical
// Authorization-Bearer-header default when nothing is overridden.
func (l TokenLocation) WithDefaults() TokenLocation {
	if l.In == "" {
		l.In = TokenLocationHeader
	}
	if l.Name == "" {
		if l.In == TokenLocationHeader {
			l.Name = "Authorization"
		} else {
			l.Name = "token"
		}
	}
	if l.Prefix == "" && l.In == TokenLocationHeader && strings.EqualFold(l.Name, "Authorization") {
		l.Prefix = "Bearer "
	}
	return l
}

// Validate rejects unknown "In" locations before a probe is attempted.
func (l TokenLocation) Validate() error {
	switch l.In {
	case "", TokenLocationHeader, TokenLocationCookie, TokenLocationQuery, TokenLocationBody:
		return nil
	default:
		return fmt.Errorf("invalid token location %q: must be one of header, cookie, query, body", l.In)
	}
}

type ProbeCtx struct {
	TokenString    string
	IsHMAC         bool
	IsAsymmetric   bool
	Alg            string
	InvalidToken   string
	AlgNoneTokens  []string
	AlgNoneErr     error
	Probe          *probe.Probe
	PublicKeyPEM   []byte
	Candidates     []string
	Workers        int
	ExpectedStatus int
	Offline        bool
	KidSQLTable    string
	KidPath        string
	TokenLocation  TokenLocation
}

type CheckDef = xharnessx.CheckDef
