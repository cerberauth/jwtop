package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/cerberauth/jwtop/jwt"
	"github.com/cerberauth/x/telemetryx"
	"github.com/spf13/cobra"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

var decodeOtelName = "github.com/cerberauth/jwtop/cmd/decode"

var decodeRaw bool

var decodeCmd = &cobra.Command{
	Use:   "decode [token]",
	Short: "Decode and pretty-print a JWT",
	Long: `Decode and pretty-print a JWT without verifying the signature.

The token can be supplied as a positional argument or piped via stdin:

  jwtop decode <token>
  echo <token> | jwtop decode
  jwtop find --file page.html | jwtop decode`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		telemetryMeter := telemetryx.GetMeterProvider().Meter(decodeOtelName)
		decodeSuccessCounter, _ := telemetryMeter.Int64Counter("decode.success.counter")
		decodeErrorCounter, _ := telemetryMeter.Int64Counter("decode.error.counter")

		ctx := cmd.Context()

		tokenString, err := readTokenArg(args)
		if err != nil {
			decodeErrorCounter.Add(ctx, 1, metric.WithAttributes(attribute.String("error_reason", "no token")))
			return err
		}

		decoded, err := jwt.Decode(tokenString)
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

		headerOut, claimsOut := string(headerJSON), string(claimsJSON)
		if !decodeRaw {
			headerOut = annotateJSON(headerOut, decoded.Header)
			claimsOut = annotateJSON(claimsOut, decoded.Claims)
		}

		fmt.Fprintln(os.Stdout, "Header:")
		fmt.Fprintln(os.Stdout, headerOut)
		fmt.Fprintln(os.Stdout)
		fmt.Fprintln(os.Stdout, "Claims:")
		fmt.Fprintln(os.Stdout, claimsOut)
		fmt.Fprintln(os.Stdout)
		fmt.Fprintln(os.Stdout, "Signature:")
		fmt.Fprintln(os.Stdout, decoded.Signature)

		if !decodeRaw {
			printExpiryStatus(os.Stdout, decoded.Claims)
		}

		return nil
	},
}

// topLevelFieldLine matches a top-level "key": value line in a
// json.MarshalIndent-produced object (exactly one level of "  " indent —
// nested objects/arrays are indented further and won't match).
var topLevelFieldLine = regexp.MustCompile(`^  "([A-Za-z0-9_]+)":\s(.+)$`)

// annotateJSON appends a trailing "// description" comment to each
// top-level line of a MarshalIndent'd JSON object whose key is a
// registered JWT header/claim field, so the explanation sits right next to
// the value instead of in a separate table. Time claims (exp/nbf/iat) get
// their Unix value translated to a date and a relative offset appended to
// the description. Output is JSON-like but no longer strictly valid JSON
// (comments aren't JSON) — use --raw for that.
func annotateJSON(rendered string, fields map[string]interface{}) string {
	lines := strings.Split(rendered, "\n")
	for i, line := range lines {
		m := topLevelFieldLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		key := m[1]
		desc, known := jwt.RegisteredClaimDescriptions[key]
		if !known {
			continue
		}
		if jwt.TimeClaimNames[key] {
			if t, ok := jwt.AsTime(fields[key]); ok {
				desc += fmt.Sprintf(" — %s (%s)", t.Format(time.RFC3339), humanizeRelative(t))
			}
		}
		lines[i] = line + "  // " + desc
	}
	return strings.Join(lines, "\n")
}

// printExpiryStatus prints a one-line summary of whether the token is
// currently expired, not yet valid, or valid, based on the exp/nbf claims.
// This is purely derived from the claim values; the signature is not
// verified.
func printExpiryStatus(w *os.File, claims map[string]interface{}) {
	now := time.Now().UTC()

	if v, ok := claims["exp"]; ok {
		if exp, ok := jwt.AsTime(v); ok && now.After(exp) {
			fmt.Fprintf(w, "\n⚠ Token is EXPIRED (expired %s)\n", humanizeRelative(exp))
			return
		}
	}
	if v, ok := claims["nbf"]; ok {
		if nbf, ok := jwt.AsTime(v); ok && now.Before(nbf) {
			fmt.Fprintf(w, "\n⚠ Token is NOT YET VALID (valid %s)\n", humanizeRelative(nbf))
			return
		}
	}
	if v, ok := claims["exp"]; ok {
		if exp, ok := jwt.AsTime(v); ok {
			fmt.Fprintf(w, "\n✓ Token is currently valid (expires %s)\n", humanizeRelative(exp))
		}
	}
}

// humanizeRelative renders t relative to now, e.g. "2 days ago" or "in 3 hours".
func humanizeRelative(t time.Time) string {
	d := time.Until(t)
	past := d < 0
	if past {
		d = -d
	}

	unit := "second"
	value := d.Seconds()
	switch {
	case d >= 24*time.Hour:
		unit = "day"
		value = d.Hours() / 24
	case d >= time.Hour:
		unit = "hour"
		value = d.Hours()
	case d >= time.Minute:
		unit = "minute"
		value = d.Minutes()
	}

	rounded := int64(value)
	plural := "s"
	if rounded == 1 {
		plural = ""
	}

	if past {
		return fmt.Sprintf("%d %s%s ago", rounded, unit, plural)
	}
	return fmt.Sprintf("in %d %s%s", rounded, unit, plural)
}

func init() {
	decodeCmd.Flags().BoolVar(&decodeRaw, "raw", false, "Only print raw header/claims/signature JSON, without inline field descriptions or expiry status")
}
