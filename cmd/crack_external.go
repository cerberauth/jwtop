package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/cerberauth/jwtop/jwt/crack/checkbase"
	"github.com/cerberauth/jwtop/jwt/exploit/external"
	"github.com/spf13/cobra"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
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

// reportExternalToolAvailability prints a one-line advisory to stderr for
// each tool found on PATH but not enabled, and increments detectedCounter
// once per tool found on PATH regardless of whether it's enabled.
func reportExternalToolAvailability(ctx context.Context, detectedCounter metric.Int64Counter, f externalToolFlags) {
	avail := detectExternalTools()
	if avail.John.Installed {
		detectedCounter.Add(ctx, 1, metric.WithAttributes(attribute.String("tool", toolJohn)))
		if !f.useJohn() {
			fmt.Fprintln(os.Stderr, "[i] john detected on PATH — pass --john (or --john-path) to use it as a fallback for HMAC secret cracking")
		}
	}
	if avail.Hashcat.Installed {
		detectedCounter.Add(ctx, 1, metric.WithAttributes(attribute.String("tool", toolHashcat)))
		if !f.useHashcat() {
			fmt.Fprintln(os.Stderr, "[i] hashcat detected on PATH — pass --hashcat (or --hashcat-path) to use it as a fallback for faster HMAC secret cracking")
		}
	}
}

// externalToolErrorReason maps an ExternalToolEvent error into the small,
// fixed error_reason vocabulary used across telemetry.
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

type toolOutcomeCounters struct {
	success  metric.Int64Counter
	notFound metric.Int64Counter
	err      metric.Int64Counter
}

// buildToolOutcomeCounters creates the success/notfound/error counters for
// john and hashcat under "<prefix>.<tool>.<outcome>.counter", matching the
// dot-separated naming convention already used by every other command.
func buildToolOutcomeCounters(meter metric.Meter, prefix string) map[string]toolOutcomeCounters {
	counters := make(map[string]toolOutcomeCounters, 2)
	for _, tool := range []string{toolJohn, toolHashcat} {
		success, _ := meter.Int64Counter(prefix + "." + tool + ".success.counter")
		notFound, _ := meter.Int64Counter(prefix + "." + tool + ".notfound.counter")
		errC, _ := meter.Int64Counter(prefix + "." + tool + ".error.counter")
		counters[tool] = toolOutcomeCounters{success: success, notFound: notFound, err: errC}
	}
	return counters
}

// recordExternalToolEvents increments the per-tool outcome counters and
// emits one span per event carrying everything else the tool told us —
// exit code, duration (via the span's own start/end timestamps), format,
// tool version, device backend, candidate count. It never receives or
// records the JWT under test or the cracked secret: ExternalToolEvent has
// no field for either.
//
// A tool that timed out also gets an explicit stderr warning distinct from
// a plain error, so a run that quietly gave up isn't mistaken for one that
// simply found nothing.
func recordExternalToolEvents(ctx context.Context, tracer trace.Tracer, counters map[string]toolOutcomeCounters, spanPrefix string, events []checkbase.ExternalToolEvent) {
	now := time.Now()
	for _, ev := range events {
		c := counters[ev.Tool]
		switch ev.Outcome {
		case outcomeSuccess:
			if c.success != nil {
				c.success.Add(ctx, 1)
			}
		case outcomeNotFound:
			if c.notFound != nil {
				c.notFound.Add(ctx, 1)
			}
		default: // outcomeError, outcomeTimeout
			if c.err != nil {
				c.err.Add(ctx, 1, metric.WithAttributes(attribute.String("error_reason", externalToolErrorReason(ev.Err))))
			}
		}

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
