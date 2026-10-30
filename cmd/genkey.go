package cmd

import (
	"errors"
	"fmt"
	"os"

	"github.com/cerberauth/jwtop/jwt"
	"github.com/cerberauth/x/telemetryx"
	"github.com/spf13/cobra"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

var (
	genkeyAlg          string
	genkeyRSABits      int
	genkeySecretBytes  int
	genkeySecretFormat string
	genkeyOut          string
	genkeyForce        bool
	genkeyPublicOnly   bool
)

var genkeyOtelName = "github.com/cerberauth/jwtop/cmd/genkey"

var genkeyCmd = &cobra.Command{
	Use:     "genkey",
	Aliases: []string{"generate-key"},
	Short:   "Generate signing key material for a JWT algorithm",
	Long: `Generate cryptographically secure signing key material for a JWT algorithm.

The key size and encoding are yours to choose, but weak parameters are refused:
RSA keys are at least 2048 bits, HMAC secrets are at least the MAC output size,
and every byte comes from the crypto/rand CSPRNG.

Supported algorithms: HS256, HS384, HS512, RS256, RS384, RS512, PS256, PS384,
PS512, ES256, ES384, ES512, EdDSA.

  # Print an HS256 secret (base64url) to stdout
  jwtop genkey --alg HS256

  # 64-byte HS512 secret as hex
  jwtop genkey --alg HS512 --secret-bytes 64 --secret-format hex

  # RSA 3072-bit key pair written to files (private 0600, public 0644)
  jwtop genkey --alg RS256 --rsa-bits 3072 --out ./jwt-key

  # ECDSA P-256 key pair to stdout, then pipe the private key into create
  jwtop genkey --alg ES256 --out ./es256 && jwtop create --alg ES256 --key ./es256`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		telemetryMeter := telemetryx.GetMeterProvider().Meter(genkeyOtelName)
		successCounter, _ := telemetryMeter.Int64Counter("genkey.success.counter")
		errorCounter, _ := telemetryMeter.Int64Counter("genkey.error.counter")

		ctx := cmd.Context()

		if genkeyAlg == "" {
			errorCounter.Add(ctx, 1, metric.WithAttributes(attribute.String("error_reason", "missing algorithm")))
			return fmt.Errorf("--alg is required")
		}

		algAttr := attribute.String("alg", genkeyAlg)

		result, err := jwt.GenerateKeyPair(jwt.GenerateKeyOptions{
			Algorithm:   genkeyAlg,
			RSABits:     genkeyRSABits,
			SecretBytes: genkeySecretBytes,
		})
		if err != nil {
			errorCounter.Add(ctx, 1, metric.WithAttributes(algAttr, attribute.String("error_reason", "failed to generate key")))
			return fmt.Errorf("generating key: %w", err)
		}

		if err := emitGeneratedKey(cmd, result); err != nil {
			errorCounter.Add(ctx, 1, metric.WithAttributes(algAttr, attribute.String("error_reason", "failed to write key")))
			return err
		}

		successCounter.Add(ctx, 1, metric.WithAttributes(algAttr))
		return nil
	},
}

func emitGeneratedKey(cmd *cobra.Command, result *jwt.GeneratedKey) error {
	isHMAC := result.Secret != nil

	if genkeyPublicOnly && isHMAC {
		return errors.New("--public-only is not valid for HMAC algorithms: the secret is symmetric")
	}

	if isHMAC {
		encoded, err := result.EncodeSecret(jwt.SecretFormat(genkeySecretFormat))
		if err != nil {
			return err
		}
		if genkeyOut != "" {
			if err := writeKeyFile(genkeyOut, []byte(encoded+"\n"), 0o600); err != nil {
				return err
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "wrote %s secret to %s (mode 0600)\n", result.Algorithm, genkeyOut)
			return nil
		}
		fmt.Fprintln(cmd.OutOrStdout(), encoded)
		return nil
	}

	if genkeyOut != "" {
		pubPath := genkeyOut + ".pub"
		if !genkeyPublicOnly {
			if err := writeKeyFile(genkeyOut, result.PrivatePEM, 0o600); err != nil {
				return err
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "wrote %s private key to %s (mode 0600)\n", result.Algorithm, genkeyOut)
		}
		if err := writeKeyFile(pubPath, result.PublicPEM, 0o644); err != nil {
			return err
		}
		fmt.Fprintf(cmd.ErrOrStderr(), "wrote %s public key to %s (mode 0644)\n", result.Algorithm, pubPath)
		return nil
	}

	out := cmd.OutOrStdout()
	if !genkeyPublicOnly {
		fmt.Fprint(out, string(result.PrivatePEM))
	}
	fmt.Fprint(out, string(result.PublicPEM))
	return nil
}

func writeKeyFile(path string, data []byte, perm os.FileMode) error {
	flag := os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	if !genkeyForce {
		flag |= os.O_EXCL
	}
	f, err := os.OpenFile(path, flag, perm)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("%s already exists: pass --force to overwrite", path)
		}
		return err
	}
	defer f.Close()

	if _, err := f.Write(data); err != nil {
		return err
	}
	// Re-assert permissions in case the file pre-existed under --force.
	return os.Chmod(path, perm)
}

func init() {
	genkeyCmd.Flags().StringVar(&genkeyAlg, "alg", "", "Target algorithm, e.g. HS256, RS256, ES256, EdDSA (required)")
	genkeyCmd.Flags().IntVar(&genkeyRSABits, "rsa-bits", 0, "RSA key size in bits (RSA algorithms only; default 2048, minimum 2048)")
	genkeyCmd.Flags().IntVar(&genkeySecretBytes, "secret-bytes", 0, "HMAC secret length in bytes (HMAC only; default matches the MAC output size)")
	genkeyCmd.Flags().StringVar(&genkeySecretFormat, "secret-format", "base64url", "HMAC secret encoding: base64url, base64, hex, raw")
	genkeyCmd.Flags().StringVar(&genkeyOut, "out", "", "Write key material to this path instead of stdout (public key goes to <out>.pub)")
	genkeyCmd.Flags().BoolVar(&genkeyForce, "force", false, "Overwrite existing files at the --out path")
	genkeyCmd.Flags().BoolVar(&genkeyPublicOnly, "public-only", false, "Emit only the public key (asymmetric algorithms only)")
}
