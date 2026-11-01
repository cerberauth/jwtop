package cmd

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/cerberauth/jwtop/jwt/crack/checkbase"
	"github.com/cerberauth/jwtop/jwt/exploit/external"
	"github.com/cerberauth/x/telemetryx"
	"github.com/spf13/cobra"
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

// roundDuration rounds to a human-friendly precision: whole seconds once the
// duration reaches a second, otherwise milliseconds (a sub-second timeout
// would otherwise always round display to "0s").
func roundDuration(d time.Duration) time.Duration {
	if d >= time.Second {
		return d.Round(time.Second)
	}
	return d.Round(time.Millisecond)
}

// recordExternalToolEvents counts each external tool run by tool and outcome,
// and prints a stderr warning for each that timed out or failed. A timeout gets
// its own message, distinct from a plain error, so a run that quietly gave up
// isn't mistaken for one that simply found nothing.
func recordExternalToolEvents(ctx context.Context, events []checkbase.ExternalToolEvent) {
	for _, ev := range events {
		tool := telemetryx.Vocab(ev.Tool, toolJohn, toolHashcat)
		outcome := telemetryx.Vocab(ev.Outcome, outcomeSuccess, outcomeNotFound, outcomeError, outcomeTimeout)
		telemetryx.Counter(ctx, "crack.external-tool", 1, tool+"."+outcome)
		telemetryx.Duration(ctx, "crack.external-tool", ev.Duration, tool)

		if ev.TimedOut {
			fmt.Fprintf(os.Stderr, "[!] %s timed out after %s without finding the secret — try a larger --crack-timeout or a smaller wordlist\n", ev.Tool, roundDuration(ev.Duration))
		} else if ev.Outcome == outcomeError {
			fmt.Fprintf(os.Stderr, "[!] %s: %v\n", ev.Tool, ev.Err)
		}
	}
}
