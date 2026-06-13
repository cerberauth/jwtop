package cmd

import (
	"fmt"
	"os"

	"github.com/cerberauth/harnessx/reporters"
	"github.com/cerberauth/jwtop/jwt/crack"
	"github.com/cerberauth/jwtop/jwt/exploit"
	"github.com/cerberauth/x/telemetryx"
	cobrareportx "github.com/cerberauth/x/cobrax/reportx"
	"github.com/spf13/cobra"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

var (
	crackURL            string
	crackExpectedStatus int
	crackKey            string
	crackWordlist       string
	crackSecrets        []string
	crackWorkers        int
)

var crackOtelName = "github.com/cerberauth/jwtop/cmd/crack"

var crackCmd = &cobra.Command{
	Use:   "crack <token>",
	Short: "Analyse a JWT for vulnerabilities, optionally probing a live server",
	Long: `Analyse a JWT token for known vulnerabilities.

Without --url (offline mode), the token is analysed cryptographically:
  • alg=none        detect if the token already uses algorithm none
  • blank secret    detect if the token is signed with an empty HMAC secret
  • null signature  detect if the token has an empty signature segment
  • weak secret     dictionary brute-force of the HMAC signing secret

With --url (online mode), a probe is sent to the target URL for each exploit
technique and the server response determines whether the token is vulnerable:

  Authorization: Bearer <exploited-token>

A technique is VULNERABLE when the server responds with a status code that
differs from the baseline (the status returned for an invalid JWT).

--expected-status sets the baseline manually (e.g. 401). When omitted, a
first request is sent with the original token; if the server already rejects
it (non-2xx), --expected-status is required. Otherwise the baseline is
auto-detected by sending a deliberately invalid token.

Additional online-only techniques:
  algnone (×4)    alg=none with four common capitalisations
  hmacconfusion   re-sign using a public key as HMAC secret (requires --key)
  kidinjection    SQL injection and path traversal via the kid header

Use only against systems you own or have explicit written permission to test.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		telemetryMeter := telemetryx.GetMeterProvider().Meter(crackOtelName)
		successCounter, _ := telemetryMeter.Int64Counter("crack.success.counter")
		notFoundCounter, _ := telemetryMeter.Int64Counter("crack.notfound.counter")
		errorCounter, _ := telemetryMeter.Int64Counter("crack.error.counter")

		ctx := cmd.Context()
		tokenString := args[0]
		offline := crackURL == ""

		var pemData []byte
		if crackKey != "" {
			var err error
			pemData, err = readKeyData(crackKey)
			if err != nil {
				errorCounter.Add(ctx, 1, metric.WithAttributes(attribute.String("error_reason", "key read error")))
				return fmt.Errorf("reading key: %w", err)
			}
		}

		candidates := exploit.WeakSecrets()
		if crackWordlist != "" {
			fromFile, err := exploit.SecretsFromFile(crackWordlist)
			if err != nil {
				errorCounter.Add(ctx, 1, metric.WithAttributes(attribute.String("error_reason", "wordlist read error")))
				return fmt.Errorf("reading wordlist: %w", err)
			}
			candidates = append(candidates, fromFile...)
		}
		candidates = append(candidates, crackSecrets...)

		reporter, _ := reporters.NewOTelReporter(
			ctx,
			otel.Tracer(crackOtelName),
			telemetryx.GetMeterProvider().Meter(crackOtelName),
			reporters.WithPrefix("jwt.crack"),
		)

		results, baselineStatus, err := crack.ProbeAll(ctx, tokenString, crack.ProbeOptions{
			URL:            crackURL,
			ExpectedStatus: crackExpectedStatus,
			PublicKeyPEM:   pemData,
			Candidates:     candidates,
			Workers:        crackWorkers,
			Reporter:       reporter,
		})
		if err != nil {
			errorCounter.Add(ctx, 1, metric.WithAttributes(attribute.String("error_reason", "probe error")))
			return fmt.Errorf("probing token: %w", err)
		}

		// Print probe errors to stderr; they are not security findings.
		for _, r := range results {
			if r.Err != nil {
				errorCounter.Add(ctx, 1, metric.WithAttributes(attribute.String("error_reason", r.Name)))
				fmt.Fprintf(os.Stderr, "[!] %s: %v\n", r.Name, r.Err)
			}
		}

		formatter, err := cobrareportx.FormatterFromFlags(cmd)
		if err != nil {
			return err
		}
		writer, cleanup, err := cobrareportx.WriterFromFlags(cmd)
		if err != nil {
			return err
		}
		defer cleanup()

		httpTransport, err := cobrareportx.HTTPTransportFromFlags(cmd)
		if err != nil {
			return err
		}

		rep := &ReportxReporter{
			Formatter: formatter,
			Writer:    writer,
			Transport: httpTransport,
		}
		meta := crack.ScanMeta{
			Target:         crackURL,
			BaselineStatus: baselineStatus,
			Offline:        offline,
			TokenString:    tokenString,
		}
		if err := rep.Report(ctx, results, meta); err != nil {
			return fmt.Errorf("reporting: %w", err)
		}

		vulnerable := 0
		for _, r := range results {
			if r.Vulnerable {
				vulnerable++
			}
		}
		if vulnerable > 0 {
			successCounter.Add(ctx, 1)
		} else {
			notFoundCounter.Add(ctx, 1)
			os.Exit(1)
		}
		return nil
	},
}

func init() {
	crackCmd.Flags().StringVar(&crackURL, "url", "", "Target URL to probe (omit for offline analysis)")
	crackCmd.Flags().IntVar(&crackExpectedStatus, "expected-status", 0, "HTTP status the server returns for an invalid JWT (required when the token is already rejected)")
	crackCmd.Flags().StringVar(&crackKey, "key", "", "Path or URL to PEM public key for hmacconfusion (optional)")
	crackCmd.Flags().StringVar(&crackWordlist, "wordlist", "", "Path to newline-delimited wordlist for secret brute-force")
	crackCmd.Flags().StringArrayVar(&crackSecrets, "secret", nil, "Explicit candidate secret for brute-force (repeatable)")
	crackCmd.Flags().IntVar(&crackWorkers, "workers", 8, "Concurrent workers for secret brute-force")
	cobrareportx.RegisterFormatFlags(crackCmd)
	cobrareportx.RegisterTransportFlags(crackCmd)
}
