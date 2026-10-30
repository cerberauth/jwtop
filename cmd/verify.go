package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/cerberauth/jwtop/jwt"
	"github.com/cerberauth/x/telemetryx"
	"github.com/spf13/cobra"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

var (
	verifySecret  string
	verifyKeyFile string
	verifyJWKSURI string
)

var verifyOtelName = "github.com/cerberauth/jwtop/cmd/verify"

var verifyCmd = &cobra.Command{
	Use:   "verify [token]",
	Short: "Verify a JWT signature and print its claims",
	Long: `Verify a JWT signature and print its claims.

The token can be supplied as a positional argument or piped via stdin:

  jwtop verify <token> --secret mysecret
  echo <token> | jwtop verify --secret mysecret
  jwtop find --file page.html | jwtop verify --jwks https://example.com/.well-known/jwks.json`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		telemetryMeter := telemetryx.GetMeterProvider().Meter(verifyOtelName)
		verifySuccessCounter, _ := telemetryMeter.Int64Counter("verify.success.counter")
		verifyErrorCounter, _ := telemetryMeter.Int64Counter("verify.error.counter")

		ctx := cmd.Context()

		tokenString, err := readTokenArg(args)
		if err != nil {
			verifyErrorCounter.Add(ctx, 1, metric.WithAttributes(attribute.String("error_reason", "no token")))
			return err
		}

		opts := jwt.VerifyOptions{
			JWKSURI: verifyJWKSURI,
		}

		if verifySecret != "" {
			opts.Secret = []byte(verifySecret)
		}

		if verifyKeyFile != "" {
			pemData, err := readKeyData(verifyKeyFile)
			if err != nil {
				verifyErrorCounter.Add(ctx, 1, metric.WithAttributes(attribute.String("error_reason", "failed to read key file")))
				return fmt.Errorf("reading key file: %w", err)
			}
			opts.KeyPEM = pemData
		}

		result, err := jwt.Verify(tokenString, opts)
		if err != nil {
			verifyErrorCounter.Add(ctx, 1, metric.WithAttributes(attribute.String("error_reason", "verification error")))
			return fmt.Errorf("verification error: %w", err)
		}

		verifySuccessCounter.Add(ctx, 1, metric.WithAttributes(attribute.Bool("valid", result.Valid)))

		if result.Valid {
			fmt.Println("valid")
		} else {
			fmt.Println("invalid")
			if result.Error != nil {
				fmt.Fprintln(os.Stderr, "error:", result.Error)
			}
		}

		if result.Claims != nil {
			claimsJSON, err := json.MarshalIndent(result.Claims, "", "  ")
			if err != nil {
				return err
			}
			fmt.Println("Claims:")
			fmt.Println(string(claimsJSON))
		}

		if !result.Valid {
			if otelShutdown != nil {
				_ = otelShutdown(context.Background())
				otelShutdown = nil
			}
			os.Exit(1)
		}

		return nil
	},
}

func init() {
	verifyCmd.Flags().StringVar(&verifySecret, "secret", "", "HMAC secret for verification")
	verifyCmd.Flags().StringVar(&verifyKeyFile, "key", "", "Path or URL to PEM public key file")
	verifyCmd.Flags().StringVar(&verifyJWKSURI, "jwks", "", "JWKS endpoint URI")
}
