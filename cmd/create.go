package cmd

import (
	"fmt"
	"strings"
	"time"

	"github.com/cerberauth/jwtop/jwt"
	"github.com/cerberauth/x/telemetryx"
	"github.com/spf13/cobra"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

var (
	createAlg    string
	createSecret string
	createKey    string
	createClaims []string
	createExp    string
	createSub    string
	createIss    string
	createAud    string
	createIat    bool
)

var createOtelName = "github.com/cerberauth/jwtop/cmd/create"

var createCmd = &cobra.Command{
	Use:   "create",
	Short: "Create and sign a new JWT",
	RunE: func(cmd *cobra.Command, args []string) error {
		telemetryMeter := telemetryx.GetMeterProvider().Meter(createOtelName)
		createSuccessCounter, _ := telemetryMeter.Int64Counter("create.success.counter")
		createErrorCounter, _ := telemetryMeter.Int64Counter("create.error.counter")

		ctx := cmd.Context()

		if createAlg == "" {
			createErrorCounter.Add(ctx, 1, metric.WithAttributes(attribute.String("error_reason", "missing algorithm")))
			return fmt.Errorf("--alg is required")
		}

		algAttr := attribute.String("alg", createAlg)

		claims := make(map[string]string)

		for _, c := range createClaims {
			parts := strings.SplitN(c, "=", 2)
			if len(parts) != 2 {
				createErrorCounter.Add(ctx, 1, metric.WithAttributes(algAttr, attribute.String("error_reason", "invalid claim format")))
				return fmt.Errorf("invalid claim format %q: expected key=value", c)
			}
			claims[parts[0]] = parts[1]
		}

		if createSub != "" {
			claims["sub"] = createSub
		}
		if createIss != "" {
			claims["iss"] = createIss
		}
		if createAud != "" {
			claims["aud"] = createAud
		}

		opts := jwt.CreateOptions{
			Algorithm: createAlg,
			Claims:    claims,
			IssuedAt:  createIat,
		}

		if createExp != "" {
			d, err := time.ParseDuration(createExp)
			if err != nil {
				createErrorCounter.Add(ctx, 1, metric.WithAttributes(algAttr, attribute.String("error_reason", "invalid expiration duration")))
				return fmt.Errorf("invalid --exp duration: %w", err)
			}
			opts.Expiration = d
		}

		var tokenString string
		var err error

		if createSecret != "" {
			tokenString, err = jwt.CreateWithSecret(opts, []byte(createSecret))
		} else if createKey != "" {
			key, _, keyErr := resolveKey("", createKey, false)
			if keyErr != nil {
				createErrorCounter.Add(ctx, 1, metric.WithAttributes(algAttr, attribute.String("error_reason", "failed to resolve key")))
				return keyErr
			}
			tokenString, err = jwt.Create(opts, key)
		} else {
			createErrorCounter.Add(ctx, 1, metric.WithAttributes(algAttr, attribute.String("error_reason", "no key provided")))
			return fmt.Errorf("no key provided: use --secret or --key")
		}

		if err != nil {
			createErrorCounter.Add(ctx, 1, metric.WithAttributes(algAttr, attribute.String("error_reason", "failed to create token")))
			return fmt.Errorf("creating token: %w", err)
		}

		createSuccessCounter.Add(ctx, 1, metric.WithAttributes(algAttr))

		fmt.Println(tokenString)
		return nil
	},
}

func init() {
	createCmd.Flags().StringVar(&createAlg, "alg", "", "Signing algorithm (e.g. HS256, RS256)")
	createCmd.Flags().StringVar(&createSecret, "secret", "", "HMAC secret")
	createCmd.Flags().StringVar(&createKey, "key", "", "Path to PEM private key file")
	createCmd.Flags().StringArrayVar(&createClaims, "claim", nil, "Claim as key=value (repeatable)")
	createCmd.Flags().StringVar(&createExp, "exp", "", "Expiration duration (e.g. 1h, 30m)")
	createCmd.Flags().StringVar(&createSub, "sub", "", "Subject claim")
	createCmd.Flags().StringVar(&createIss, "iss", "", "Issuer claim")
	createCmd.Flags().StringVar(&createAud, "aud", "", "Audience claim")
	createCmd.Flags().BoolVar(&createIat, "iat", false, "Include issued-at claim")
}
