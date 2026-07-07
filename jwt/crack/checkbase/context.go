package checkbase

import (
	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/probe"
	xharnessx "github.com/cerberauth/x/harnessx"
	"github.com/cerberauth/x/reportx/harnessreport"
)

const CheckIDBaseline harnessx.CheckID = "baseline"

type ProbeResult = harnessreport.Result

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
}

type CheckDef = xharnessx.CheckDef
