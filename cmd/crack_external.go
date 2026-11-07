package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/cerberauth/jwtop/jwt/crack/checkbase"
	"github.com/cerberauth/jwtop/jwt/exploit/external"
	"github.com/cerberauth/x/telemetryx"
	"github.com/getargvio/argvio-go"
	"github.com/spf13/cobra"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// detectExternalTools is a package-var seam over external.Detect so cmd-level
// tests can fake tool availability without depending on what's actually
// installed on the test machine.
var detectExternalTools = external.Detect

const (
	toolJohn    = "john"
	toolHashcat = "hashcat"

	outcomeSuccess  = "success"
	outcomeNotFound = "notfound"
	outcomeError    = "error"
	outcomeTimeout  = "timeout"
)

// externalToolFlags groups the --john/--john-path/--hashcat/--hashcat-path/
// --crack-timeout flags shared by cmd/crack.go and cmd/exploit_weaksecret.go.
type externalToolFlags struct {
	John        bool
	JohnPath    string
	Hashcat     bool
	HashcatPath string
	Timeout     time.Duration
}

// useJohn/useHashcat: passing an explicit binary path already states intent
// to use that tool, so it isn't necessary to also pass the bool flag.
func (f externalToolFlags) useJohn() bool    { return f.John || f.JohnPath != "" }
func (f externalToolFlags) useHashcat() bool { return f.Hashcat || f.HashcatPath != "" }

func (f externalToolFlags) toOptions() checkbase.ExternalToolOptions {
	return checkbase.ExternalToolOptions{
		UseJohn: f.useJohn(), JohnPath: f.JohnPath,
		UseHashcat: f.useHashcat(), HashcatPath: f.HashcatPath,
		Timeout: f.Timeout,
	}
}

func registerExternalToolFlags(cmd *cobra.Command, f *externalToolFlags) {
	cmd.Flags().BoolVar(&f.John, toolJohn, false, "Crack the HMAC secret via the external john-the-ripper tool as a fallback if the built-in dictionary attack doesn't find it")
	cmd.Flags().StringVar(&f.JohnPath, "john-path", "", "Path to the john binary (implies --john; resolved via PATH when omitted)")
	cmd.Flags().BoolVar(&f.Hashcat, toolHashcat, false, "Crack the HMAC secret via the external hashcat tool as a fallback if the built-in dictionary attack doesn't find it")
	cmd.Flags().StringVar(&f.HashcatPath, "hashcat-path", "", "Path to the hashcat binary (implies --hashcat; resolved via PATH when omitted)")
	cmd.Flags().DurationVar(&f.Timeout, "crack-timeout", 5*time.Minute, "Max time to let an external cracking tool run before it is stopped")
}

// reportExternalToolAvailability records each tool found on PATH as a feature,
// whether or not it is enabled, and prints a one-line advisory to stderr for
// each one that is not.
func reportExternalToolAvailability(ctx context.Context, f externalToolFlags) {
	avail := detectExternalTools()
	if avail.John.Installed {
		telemetryx.Feature(ctx, "crack.john-detected")
		if !f.useJohn() {
			fmt.Fprintln(os.Stderr, "[i] john detected on PATH — pass --john (or --john-path) to use it as a fallback for HMAC secret cracking")
		}
	}
	if avail.Hashcat.Installed {
		telemetryx.Feature(ctx, "crack.hashcat-detected")
		if !f.useHashcat() {
			fmt.Fprintln(os.Stderr, "[i] hashcat detected on PATH — pass --hashcat (or --hashcat-path) to use it as a fallback for faster HMAC secret cracking")
		}
	}
}

// externalToolErrorReason maps an ExternalToolEvent error into the small,
// fixed error_reason vocabulary of the external tool spans.
func externalToolErrorReason(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, external.ErrNotInstalled):
		return "not_installed"
	case errors.Is(err, external.ErrTimedOut):
		return outcomeTimeout
	default:
		return "invocation_failed"
	}
}

// roundDuration rounds to a human-friendly precision: whole seconds once the
// duration reaches a second, otherwise milliseconds (a sub-second timeout
// would otherwise always round display to "0s").
func roundDuration(d time.Duration) time.Duration {
	if d >= time.Second {
		return d.Round(time.Second)
	}
	return d.Round(time.Millisecond)
}

// External cracking tool metrics, declared in the Argvio catalog.
var (
	externalToolRuns     = argvio.NewCounter("crack.external-tool", argvio.Dims("tool", "outcome"))
	externalToolDuration = argvio.NewDuration("crack.external-tool.run", argvio.Dims("tool", "outcome"))
)

// recordExternalToolEvents counts each external tool run by tool and outcome
// for Argvio, emits one OpenTelemetry span per event carrying everything else
// the tool told us (exit code, duration through the span's own start and end
// timestamps, format, tool version, device backend, candidate count), and
// prints a stderr warning for each run that timed out or failed. It never
// receives or records the JWT under test or the cracked secret:
// ExternalToolEvent has no field for either.
//
// A timeout gets its own message, distinct from a plain error, so a run that
// quietly gave up isn't mistaken for one that simply found nothing.
func recordExternalToolEvents(ctx context.Context, tracer trace.Tracer, spanPrefix string, events []checkbase.ExternalToolEvent) {
	now := time.Now()
	for _, ev := range events {
		tool := telemetryx.Vocab(ev.Tool, toolJohn, toolHashcat)
		outcome := telemetryx.Vocab(ev.Outcome, outcomeSuccess, outcomeNotFound, outcomeError, outcomeTimeout)
		externalToolRuns.Add(ctx, 1, tool, outcome)
		externalToolDuration.Record(ctx, ev.Duration, tool, outcome)

		if ev.TimedOut {
			fmt.Fprintf(os.Stderr, "[!] %s timed out after %s without finding the secret — try a larger --crack-timeout or a smaller wordlist\n", ev.Tool, roundDuration(ev.Duration))
		} else if ev.Outcome == outcomeError {
			fmt.Fprintf(os.Stderr, "[!] %s: %v\n", ev.Tool, ev.Err)
		}

		_, span := tracer.Start(ctx, spanPrefix+".external."+ev.Tool, trace.WithTimestamp(now.Add(-ev.Duration)))
		span.SetAttributes(
			attribute.String("tool.version", ev.ToolVersion),
			attribute.String("format", ev.Format),
			attribute.Int("exit_code", ev.ExitCode),
			attribute.Bool("timed_out", ev.TimedOut),
			attribute.Int("candidates_count", ev.CandidatesCount),
			attribute.String("outcome", ev.Outcome),
		)
		if ev.DeviceBackend != "" {
			span.SetAttributes(attribute.String("device_backend", ev.DeviceBackend))
		}
		if reason := externalToolErrorReason(ev.Err); reason != "" {
			span.SetAttributes(attribute.String("error_reason", reason))
		}
		span.End(trace.WithTimestamp(now))
	}
}
