package checkbase

import (
	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/probe"
)

const CheckIDBaseline harnessx.CheckID = "baseline"

type ProbeResult struct {
	Name       string
	Token      string
	Status     int
	Vulnerable bool
	Err        error
	Skipped    bool
	SkipReason string
	Extra      string
}

type ProbeCtx struct {
	TokenString         string
	IsHMAC              bool
	IsAsymmetric        bool
	Alg                 string
	InvalidToken        string
	AlgNoneTokens       []string
	AlgNoneErr          error
	Probe               *probe.Probe
	PublicKeyPEM        []byte
	Candidates          []string
	Workers             int
	ExpectedStatus      int
	OriginalTokenStatus int
	Offline             bool
}

type CheckDef struct {
	ID          string   `yaml:"id"`
	Name        string   `yaml:"name"`
	Description string   `yaml:"description"`
	Link        string   `yaml:"link"`
	Tags        []string `yaml:"tags"`
	DependsOn   []string `yaml:"depends_on"`
}

func (d CheckDef) DependsOnIDs() []harnessx.CheckID {
	ids := make([]harnessx.CheckID, len(d.DependsOn))
	for i, s := range d.DependsOn {
		ids[i] = harnessx.CheckID(s)
	}
	return ids
}
