package weaksecret

import (
	"context"
	_ "embed"
	"errors"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/jwtop/jwt/crack/checkbase"
	"github.com/cerberauth/jwtop/jwt/exploit"
	"github.com/cerberauth/jwtop/jwt/exploit/external"
	"gopkg.in/yaml.v3"
)

//go:embed check.yaml
var checkYAML []byte

var Def checkbase.CheckDef

// Package-var seams so tests can swap in fakes instead of spawning real
// john/hashcat processes.
var (
	crackWithJohn    = external.CrackWithJohn
	crackWithHashcat = external.CrackWithHashcat
)

// externalRun invokes an external cracker, records an ExternalToolEvent on
// pctx (if the caller asked for events), and returns the resulting
// exploit.CrackResult. The event never carries the token or the cracked
// secret — only operational data about the run.
func externalRun(pctx *checkbase.ProbeCtx, tool string, run func() (external.ExternalCrackResult, error)) exploit.CrackResult {
	ext, err := run()

	outcome := "success"
	switch {
	case errors.Is(err, external.ErrTimedOut):
		outcome = "timeout"
	case err != nil:
		outcome = "error"
	case !ext.Found:
		outcome = "notfound"
	}

	if pctx.ExternalToolEvents != nil {
		*pctx.ExternalToolEvents = append(*pctx.ExternalToolEvents, checkbase.ExternalToolEvent{
			Tool: tool, Outcome: outcome, Err: err,
			Duration: ext.Duration, ExitCode: ext.ExitCode, TimedOut: ext.TimedOut,
			Format: ext.Format, ToolVersion: ext.ToolVersion, DeviceBackend: ext.DeviceBackend,
			CandidatesCount: ext.CandidatesCount,
		})
	}
	return ext.CrackResult
}

var Check = func() harnessx.Check {
	if err := yaml.Unmarshal(checkYAML, &Def); err != nil {
		panic("weak_secret: failed to parse check.yaml: " + err.Error())
	}
	return harnessx.Check{
		ID:          harnessx.CheckID(Def.ID),
		Name:        Def.Name,
		Description: Def.Description,
		Link:        Def.Link,
		Tags:        Def.Tags,
		DependsOn:   Def.DependsOnIDs(),
		Skip: harnessx.SkipWhen(func(_ context.Context, target harnessx.Target, store harnessx.ResultStore) string {
			pctx := target.Data.(*checkbase.ProbeCtx)
			if !pctx.IsHMAC {
				return "HMAC-only exploit (token uses " + pctx.Alg + ")"
			}
			if pr, ok := harnessx.GetData[checkbase.ProbeResult](store, "blanksecret"); ok && pr.Vulnerable {
				return "server accepts a blank HMAC secret — see Blank Secret finding"
			}
			return ""
		}),
		Run: func(ctx context.Context, target harnessx.Target, _ harnessx.ResultStore) (harnessx.Result, error) {
			pctx := target.Data.(*checkbase.ProbeCtx)
			result, err := exploit.CrackSecret(pctx.TokenString, pctx.Candidates, pctx.Workers)
			if err != nil {
				return harnessx.Result{}, err
			}

			if !result.Found && pctx.ExternalTools.UseJohn {
				result = externalRun(pctx, "john", func() (external.ExternalCrackResult, error) {
					return crackWithJohn(ctx, pctx.TokenString, pctx.Candidates, external.JohnOptions{
						BinaryPath: pctx.ExternalTools.JohnPath,
						Timeout:    pctx.ExternalTools.Timeout,
					})
				})
			}
			if !result.Found && pctx.ExternalTools.UseHashcat {
				result = externalRun(pctx, "hashcat", func() (external.ExternalCrackResult, error) {
					return crackWithHashcat(ctx, pctx.TokenString, pctx.Candidates, external.HashcatOptions{
						BinaryPath: pctx.ExternalTools.HashcatPath,
						Timeout:    pctx.ExternalTools.Timeout,
					})
				})
			}

			if !result.Found {
				return checkbase.SkippedProbeResult("not found in dictionary"), nil
			}
			return harnessx.DataResult(checkbase.ProbeResult{
				Vulnerable: true,
				Extra:      "secret: " + result.Secret,
			}), nil
		},
	}
}()
