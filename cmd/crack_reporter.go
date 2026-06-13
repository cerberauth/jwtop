package cmd

import (
	"context"
	"io"

	"github.com/cerberauth/jwtop/jwt/crack"
	"github.com/cerberauth/reportx"
	"github.com/cerberauth/reportx/enrich"
	"github.com/cerberauth/reportx/evidence"
	"github.com/cerberauth/reportx/format"
	"github.com/cerberauth/reportx/score"
	"github.com/cerberauth/reportx/transport"
)

type ReportxReporter struct {
	Formatter format.Formatter
	Writer    io.Writer
	Transport *transport.HTTPTransport // nil = no HTTP delivery
}

func (r *ReportxReporter) Report(ctx context.Context, results []crack.ProbeResult, meta crack.ScanMeta) error {
	var findings []reportx.Finding
	for _, pr := range results {
		if !pr.Vulnerable {
			continue
		}
		f := reportx.Finding{
			ID:           pr.Name,
			Title:        pr.Name,
			Description:  pr.Description,
			URL:          pr.Link,
			CWEID:        pr.CWEID,
			CVSS40Score:  pr.CVSSScore,
			CVSS40Vector: pr.CVSSVector,
			Status:       reportx.StatusActive,
		}
		if pr.CVSSScore > 0 {
			f.Severity = score.Label(pr.CVSSScore)
		}

		f.Parameter = pr.Token

		ev := &evidence.HTTPEvidence{}
		if pr.Status != 0 {
			ev.RequestMethod = "GET"
			ev.RequestURL = meta.Target
			ev.ResponseStatus = pr.Status
		}
		f.Evidence = ev

		if pr.Extra != "" {
			f.Extra = map[string]string{"detail": pr.Extra}
		}
		findings = append(findings, f)
	}

	target := meta.Target
	if target == "" {
		target = "(offline)"
	}

	report, err := reportx.NewBuilder().
		Tool(name, toolVersion).
		Target(target).
		Title("JWT Security Scan").
		Findings(findings).
		Enrich(enrich.EnrichAll).
		Build(ctx)
	if err != nil {
		return err
	}

	if err := report.WriteTo(ctx, r.Writer, r.Formatter); err != nil {
		return err
	}
	if r.Transport != nil {
		return report.Send(ctx, r.Transport, r.Formatter)
	}
	return nil
}
