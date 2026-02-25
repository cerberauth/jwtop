package cmd

import (
	"fmt"

	"github.com/cerberauth/jwtop/jwt/editor"
	"github.com/cerberauth/x/telemetryx"
	jwtlib "github.com/golang-jwt/jwt/v5"
	"github.com/spf13/cobra"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

var (
	signAlg    string
	signSecret string
	signKey    string
)

var signOtelName = "github.com/cerberauth/jwtop/cmd/sign"

var signCmd = &cobra.Command{
	Use:   "sign <token>",
	Short: "Re-sign an existing JWT with a new algorithm or key",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		telemetryMeter := telemetryx.GetMeterProvider().Meter(signOtelName)
		signSuccessCounter, _ := telemetryMeter.Int64Counter("sign.success.counter")
		signErrorCounter, _ := telemetryMeter.Int64Counter("sign.error.counter")

		ctx := cmd.Context()

		if signAlg == "" {
			signErrorCounter.Add(ctx, 1, metric.WithAttributes(attribute.String("error_reason", "missing algorithm")))
			return fmt.Errorf("--alg is required")
		}

		algAttr := attribute.String("alg", signAlg)

		writer, err := editor.NewTokenEditor(args[0])
		if err != nil {
			signErrorCounter.Add(ctx, 1, metric.WithAttributes(algAttr, attribute.String("error_reason", "failed to parse token")))
			return fmt.Errorf("parsing token: %w", err)
		}

		if signAlg == "none" {
			tokenString, err := writer.WithAlgNone()
			if err != nil {
				signErrorCounter.Add(ctx, 1, metric.WithAttributes(algAttr, attribute.String("error_reason", "failed to sign with none")))
				return fmt.Errorf("signing with none: %w", err)
			}
			signSuccessCounter.Add(ctx, 1, metric.WithAttributes(algAttr))
			fmt.Println(tokenString)
			return nil
		}

		method, err := ParseSigningMethod(signAlg)
		if err != nil {
			signErrorCounter.Add(ctx, 1, metric.WithAttributes(algAttr, attribute.String("error_reason", "invalid signing method")))
			return err
		}

		var tokenString string

		if signSecret != "" {
			if _, ok := method.(*jwtlib.SigningMethodHMAC); !ok {
				signErrorCounter.Add(ctx, 1, metric.WithAttributes(algAttr, attribute.String("error_reason", "secret used with non-HMAC algorithm")))
				return fmt.Errorf("--secret can only be used with HMAC algorithms")
			}
			tokenString, err = writer.SignWithMethodAndKey(method, []byte(signSecret))
		} else if signKey != "" {
			key, _, keyErr := resolveKey("", signKey, false)
			if keyErr != nil {
				signErrorCounter.Add(ctx, 1, metric.WithAttributes(algAttr, attribute.String("error_reason", "failed to resolve key")))
				return keyErr
			}
			tokenString, err = writer.SignWithMethodAndKey(method, key)
		} else {
			signErrorCounter.Add(ctx, 1, metric.WithAttributes(algAttr, attribute.String("error_reason", "no key provided")))
			return fmt.Errorf("no key provided: use --secret or --key")
		}

		if err != nil {
			signErrorCounter.Add(ctx, 1, metric.WithAttributes(algAttr, attribute.String("error_reason", "failed to sign token")))
			return fmt.Errorf("signing token: %w", err)
		}

		signSuccessCounter.Add(ctx, 1, metric.WithAttributes(algAttr))

		fmt.Println(tokenString)
		return nil
	},
}

func init() {
	signCmd.Flags().StringVar(&signAlg, "alg", "", "Signing algorithm (e.g. HS256, RS256, none)")
	signCmd.Flags().StringVar(&signSecret, "secret", "", "HMAC secret")
	signCmd.Flags().StringVar(&signKey, "key", "", "Path to PEM private key file")
}
