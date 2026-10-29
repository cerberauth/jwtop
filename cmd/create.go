package cmd

import (
	"fmt"
	"strings"
	"time"

	"github.com/cerberauth/jwtop/jwt"
	"github.com/cerberauth/x/telemetryx"
	"github.com/spf13/cobra"
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

var createCmd = &cobra.Command{
	Use:   "create",
	Short: "Create and sign a new JWT",
	RunE: func(cmd *cobra.Command, args []string) error {

		if createAlg == "" {
			return telemetryx.Reason(fmt.Errorf("--alg is required"), "missing-algorithm")
		}

		claims := make(map[string]string)

		for _, c := range createClaims {
			parts := strings.SplitN(c, "=", 2)
			if len(parts) != 2 {
				return telemetryx.Reason(fmt.Errorf("invalid claim format %q: expected key=value", c), "invalid-claim-format")
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
				return telemetryx.Reason(fmt.Errorf("invalid --exp duration: %w", err), "invalid-expiration-duration")
			}
			opts.Expiration = d
		}

		var tokenString string
		var err error

		if cmd.Flags().Changed("secret") {
			tokenString, err = jwt.CreateWithSecret(opts, []byte(createSecret))
		} else if createKey != "" {
			key, _, keyErr := resolveKey("", createKey, false)
			if keyErr != nil {
				return telemetryx.Reason(keyErr, "failed-to-resolve-key")
			}
			tokenString, err = jwt.Create(opts, key)
		} else {
			return telemetryx.Reason(fmt.Errorf("no key provided: use --secret or --key"), "no-key-provided")
		}

		if err != nil {
			return telemetryx.Reason(fmt.Errorf("creating token: %w", err), "failed-to-create-token")
		}

		fmt.Println(tokenString)
		return nil
	},
}

func init() {
	createCmd.Flags().StringVar(&createAlg, "alg", "", "Signing algorithm (e.g. HS256, RS256)")
	createCmd.Flags().StringVar(&createSecret, "secret", "", "HMAC secret")
	createCmd.Flags().StringVar(&createKey, "key", "", "Path or URL to PEM private key file")
	createCmd.Flags().StringArrayVar(&createClaims, "claim", nil, "Claim as key=value (repeatable)")
	createCmd.Flags().StringVar(&createExp, "exp", "", "Expiration duration (e.g. 1h, 30m)")
	createCmd.Flags().StringVar(&createSub, "sub", "", "Subject claim")
	createCmd.Flags().StringVar(&createIss, "iss", "", "Issuer claim")
	createCmd.Flags().StringVar(&createAud, "aud", "", "Audience claim")
	createCmd.Flags().BoolVar(&createIat, "iat", false, "Include issued-at claim")
}
