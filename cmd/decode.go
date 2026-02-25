package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/cerberauth/jwtop/jwt"
	"github.com/cerberauth/x/telemetryx"
	"github.com/spf13/cobra"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

var decodeOtelName = "github.com/cerberauth/jwtop/cmd/decode"

var decodeCmd = &cobra.Command{
	Use:   "decode <token>",
	Short: "Decode and pretty-print a JWT",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		telemetryMeter := telemetryx.GetMeterProvider().Meter(decodeOtelName)
		decodeSuccessCounter, _ := telemetryMeter.Int64Counter("decode.success.counter")
		decodeErrorCounter, _ := telemetryMeter.Int64Counter("decode.error.counter")

		ctx := cmd.Context()

		decoded, err := jwt.Decode(args[0])
		if err != nil {
			decodeErrorCounter.Add(ctx, 1, metric.WithAttributes(attribute.String("error_reason", "failed to decode token")))
			return fmt.Errorf("failed to decode token: %w", err)
		}

		headerJSON, err := json.MarshalIndent(decoded.Header, "", "  ")
		if err != nil {
			decodeErrorCounter.Add(ctx, 1, metric.WithAttributes(attribute.String("error_reason", "failed to marshal header")))
			return err
		}

		claimsJSON, err := json.MarshalIndent(decoded.Claims, "", "  ")
		if err != nil {
			decodeErrorCounter.Add(ctx, 1, metric.WithAttributes(attribute.String("error_reason", "failed to marshal claims")))
			return err
		}

		decodeSuccessCounter.Add(ctx, 1)

		fmt.Fprintln(os.Stdout, "Header:")
		fmt.Fprintln(os.Stdout, string(headerJSON))
		fmt.Fprintln(os.Stdout)
		fmt.Fprintln(os.Stdout, "Claims:")
		fmt.Fprintln(os.Stdout, string(claimsJSON))
		fmt.Fprintln(os.Stdout)
		fmt.Fprintln(os.Stdout, "Signature:")
		fmt.Fprintln(os.Stdout, decoded.Signature)

		return nil
	},
}
