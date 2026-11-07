package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/cerberauth/jwtop/jwt"
	"github.com/cerberauth/x/telemetryx"
	"github.com/spf13/cobra"
)

var (
	verifySecret  string
	verifyKeyFile string
	verifyJWKSURI string
)

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

		tokenString, err := readTokenArg(args)
		if err != nil {
			return telemetryx.Reason(err, "no-token")
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
				return telemetryx.Reason(fmt.Errorf("reading key file: %w", err), "failed-to-read-key-file")
			}
			opts.KeyPEM = pemData
		}

		result, err := jwt.Verify(tokenString, opts)
		if err != nil {
			return telemetryx.Reason(fmt.Errorf("verification error: %w", err), "verification-error")
		}

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
			telemetryx.Exit(cmd, 1)
		}

		return nil
	},
}

func init() {
	verifyCmd.Flags().StringVar(&verifySecret, "secret", "", "HMAC secret for verification")
	verifyCmd.Flags().StringVar(&verifyKeyFile, "key", "", "Path or URL to PEM public key file")
	verifyCmd.Flags().StringVar(&verifyJWKSURI, "jwks", "", "JWKS endpoint URI")
}
