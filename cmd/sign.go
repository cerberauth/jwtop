package cmd

import (
	"fmt"

	"github.com/cerberauth/jwtop/jwt/editor"
	"github.com/cerberauth/x/telemetryx"
	jwtlib "github.com/golang-jwt/jwt/v5"
	"github.com/spf13/cobra"
)

var (
	signAlg    string
	signSecret string
	signKey    string
)

var signCmd = &cobra.Command{
	Use:   "sign [token]",
	Short: "Re-sign an existing JWT with a new algorithm or key",
	Long: `Re-sign an existing JWT with a new algorithm or key.

The token can be supplied as a positional argument or piped via stdin:

  jwtop sign <token> --alg HS256 --secret mysecret
  echo <token> | jwtop sign --alg none
  jwtop find --file page.html | jwtop sign --alg HS256 --secret mysecret`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {

		inputToken, err := readTokenArg(args)
		if err != nil {
			return telemetryx.Reason(err, "no-token")
		}

		if signAlg == "" {
			return telemetryx.Reason(fmt.Errorf("--alg is required"), "missing-algorithm")
		}

		writer, err := editor.NewTokenEditor(inputToken)
		if err != nil {
			return telemetryx.Reason(fmt.Errorf("parsing token: %w", err), "failed-to-parse-token")
		}

		if signAlg == "none" {
			tokenString, err := writer.WithAlgNone()
			if err != nil {
				return telemetryx.Reason(fmt.Errorf("signing with none: %w", err), "failed-to-sign-with-none")
			}
			fmt.Println(tokenString)
			return nil
		}

		method, err := ParseSigningMethod(signAlg)
		if err != nil {
			return telemetryx.Reason(err, "invalid-signing-method")
		}

		var tokenString string

		if signSecret != "" {
			if _, ok := method.(*jwtlib.SigningMethodHMAC); !ok {
				return telemetryx.Reason(fmt.Errorf("--secret can only be used with HMAC algorithms"), "secret-used-with-non-hmac-algorithm")
			}
			tokenString, err = writer.SignWithMethodAndKey(method, []byte(signSecret))
		} else if signKey != "" {
			key, _, keyErr := resolveKey("", signKey, false)
			if keyErr != nil {
				return telemetryx.Reason(keyErr, "failed-to-resolve-key")
			}
			tokenString, err = writer.SignWithMethodAndKey(method, key)
		} else {
			return telemetryx.Reason(fmt.Errorf("no key provided: use --secret or --key"), "no-key-provided")
		}

		if err != nil {
			return telemetryx.Reason(fmt.Errorf("signing token: %w", err), "failed-to-sign-token")
		}

		fmt.Println(tokenString)
		return nil
	},
}

func init() {
	signCmd.Flags().StringVar(&signAlg, "alg", "", "Signing algorithm (e.g. HS256, RS256, none)")
	signCmd.Flags().StringVar(&signSecret, "secret", "", "HMAC secret")
	signCmd.Flags().StringVar(&signKey, "key", "", "Path or URL to PEM private key file")
}
