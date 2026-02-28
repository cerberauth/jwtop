package cmd

import (
	"fmt"
	"os"

	"github.com/cerberauth/jwtop/jwt/crack"
	"github.com/cerberauth/jwtop/jwt/exploit"
	"github.com/cerberauth/x/telemetryx"
	"github.com/spf13/cobra"
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
	Short: "Test a JWT against every known exploit and report vulnerabilities",
	Long: `Send a probe to --url for each known JWT exploit technique and report
which ones the server accepts.

Each technique produces a modified token sent as:
  Authorization: Bearer <exploited-token>

A technique is VULNERABLE when the server responds with a status code that
differs from the baseline (the status returned for an invalid JWT).

--expected-status sets the baseline manually (e.g. 401). When omitted, a
first request is sent with a deliberately invalid token to detect it
automatically.

Techniques (in order):
  algnone (×4)    alg=none with four common capitalisations
  blanksecret     re-sign with an empty HMAC secret
  nullsig         strip the signature segment entirely
  hmacconfusion   re-sign using a public key as HMAC secret (requires --key)
  kidinjection    SQL injection and path traversal via the kid header
  weaksecret      dictionary brute-force of the HMAC signing secret

Use only against systems you own or have explicit written permission to test.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		telemetryMeter := telemetryx.GetMeterProvider().Meter(crackOtelName)
		successCounter, _ := telemetryMeter.Int64Counter("crack.success.counter")
		notFoundCounter, _ := telemetryMeter.Int64Counter("crack.notfound.counter")
		errorCounter, _ := telemetryMeter.Int64Counter("crack.error.counter")

		ctx := cmd.Context()
		tokenString := args[0]

		var pemData []byte
		if crackKey != "" {
			var err error
			pemData, err = os.ReadFile(crackKey) //nolint:gosec
			if err != nil {
				errorCounter.Add(ctx, 1, metric.WithAttributes(attribute.String("error_reason", "key read error")))
				return fmt.Errorf("reading key file: %w", err)
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

		results, baselineStatus, err := crack.ProbeAll(ctx, tokenString, crack.ProbeOptions{
			URL:            crackURL,
			ExpectedStatus: crackExpectedStatus,
			PublicKeyPEM:   pemData,
			Candidates:     candidates,
			Workers:        crackWorkers,
		})
		if err != nil {
			errorCounter.Add(ctx, 1, metric.WithAttributes(attribute.String("error_reason", "probe error")))
			return fmt.Errorf("probing token: %w", err)
		}

		fmt.Printf("Baseline (invalid JWT): %d\n\n", baselineStatus)

		vulnerable := 0
		for _, r := range results {
			switch {
			case r.Skipped:
				fmt.Printf("[-] %-28s  skipped (%s)\n", r.Name, r.SkipReason)
			case r.Err != nil:
				errorCounter.Add(ctx, 1, metric.WithAttributes(attribute.String("error_reason", r.Name)))
				fmt.Printf("[!] %-28s  error: %v\n", r.Name, r.Err)
			case r.Vulnerable:
				vulnerable++
				extra := ""
				if r.Extra != "" {
					extra = "  (" + r.Extra + ")"
				}
				fmt.Printf("[+] %-28s  %d  VULNERABLE%s\n", r.Name, r.Status, extra)
			default:
				extra := ""
				if r.Extra != "" {
					extra = "  (" + r.Extra + ")"
				}
				fmt.Printf("[ ] %-28s  %d%s\n", r.Name, r.Status, extra)
			}
		}

		if vulnerable > 0 {
			successCounter.Add(ctx, 1)
		} else {
			notFoundCounter.Add(ctx, 1)
			fmt.Fprintln(os.Stderr, "\nNo exploits succeeded.")
			os.Exit(1)
		}
		return nil
	},
}

func init() {
	crackCmd.Flags().StringVar(&crackURL, "url", "", "Target URL to probe (required)")
	_ = crackCmd.MarkFlagRequired("url")
	crackCmd.Flags().IntVar(&crackExpectedStatus, "expected-status", 0, "HTTP status the server returns for an invalid JWT (0 = auto-detect)")
	crackCmd.Flags().StringVar(&crackKey, "key", "", "Path to PEM public key for hmacconfusion (optional)")
	crackCmd.Flags().StringVar(&crackWordlist, "wordlist", "", "Path to newline-delimited wordlist for secret brute-force")
	crackCmd.Flags().StringArrayVar(&crackSecrets, "secret", nil, "Explicit candidate secret for brute-force (repeatable)")
	crackCmd.Flags().IntVar(&crackWorkers, "workers", 8, "Concurrent workers for secret brute-force")
}
