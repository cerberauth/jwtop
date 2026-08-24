package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/cerberauth/jwtop/jwt"
	"github.com/cerberauth/x/fsx"
	"github.com/cerberauth/x/telemetryx"
	"github.com/spf13/cobra"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

var findFile string

var findOtelName = "github.com/cerberauth/jwtop/cmd/find"

var findCmd = &cobra.Command{
	Use:   "find [text]",
	Short: "Extract JWT tokens from text, a file, or stdin",
	Long: `Search for and extract all valid JWT tokens embedded in arbitrary text.

JWTs can be hidden anywhere — in URLs (query parameters, path segments),
JSON payloads, HTML pages, HTTP response bodies, Authorization headers,
log files, and more. This command scans the input and prints each
discovered token on its own line, making it easy to pipe into other
jwtop commands.

Input sources (in priority order):
  1. --file <path>  read text from a file
  2. [text] arg     use the inline text argument
  3. stdin          read from stdin when no argument or --file is given

Combine with other commands:

  # Decode the first JWT found in a file
  jwtop find --file response.html | head -1 | jwtop decode

  # Decode a JWT found in a URL passed via stdin
  echo "https://example.com/?token=eyJ..." | jwtop find | jwtop decode

  # Verify every JWT in a log file
  jwtop find --file app.log | while read tok; do
    jwtop verify "$tok" --secret mysecret && echo "OK: $tok"
  done

  # Crack all tokens found in a captured HTTP response
  curl -s https://api.example.com/profile | jwtop find | while read tok; do
    jwtop crack "$tok"
  done`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		telemetryMeter := telemetryx.GetMeterProvider().Meter(findOtelName)
		findSuccessCounter, _ := telemetryMeter.Int64Counter("find.success.counter")
		findErrorCounter, _ := telemetryMeter.Int64Counter("find.error.counter")
		findNotFoundCounter, _ := telemetryMeter.Int64Counter("find.notfound.counter")

		ctx := cmd.Context()

		var text string

		switch {
		case findFile != "":
			// --file flag takes highest priority
			data, err := fsx.ReadFile(findFile)
			if err != nil {
				findErrorCounter.Add(ctx, 1, metric.WithAttributes(attribute.String("error_reason", "failed to read file")))
				return fmt.Errorf("reading file: %w", err)
			}
			text = string(data)

		case len(args) == 1:
			// Inline text argument
			text = args[0]

		default:
			// Fall back to stdin
			tokens, err := jwt.FindAllReader(os.Stdin)
			if err != nil {
				findErrorCounter.Add(ctx, 1, metric.WithAttributes(attribute.String("error_reason", "failed to read stdin")))
				return fmt.Errorf("reading stdin: %w", err)
			}
			if len(tokens) == 0 {
				findNotFoundCounter.Add(ctx, 1)
				return nil
			}
			findSuccessCounter.Add(ctx, 1, metric.WithAttributes(attribute.Int("count", len(tokens))))
			fmt.Println(strings.Join(tokens, "\n"))
			return nil
		}

		tokens := jwt.FindAll(text)
		if len(tokens) == 0 {
			findNotFoundCounter.Add(ctx, 1)
			return nil
		}

		findSuccessCounter.Add(ctx, 1, metric.WithAttributes(attribute.Int("count", len(tokens))))
		fmt.Println(strings.Join(tokens, "\n"))
		return nil
	},
}

func init() {
	findCmd.Flags().StringVar(&findFile, "file", "", "Path to a file to scan for JWTs")
}
