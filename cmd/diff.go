package cmd

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/cerberauth/jwtop/jwt"
	"github.com/cerberauth/x/telemetryx"
	"github.com/spf13/cobra"
)

var diffFormat string

var diffCmd = &cobra.Command{
	Use:   "diff <token> <token>...",
	Short: "Compare two or more JWTs and show header/claims/signature differences",
	Long: `Compare a base JWT against one or more other JWTs and report which
header fields, claims, and the signature differ.

The first token is the base; every subsequent token is diffed against it.
Tokens can be supplied as positional arguments, or piped one per line via
stdin when fewer than two are given as arguments:

  jwtop diff <base-token> <other-token> [<other-token>...]
  jwtop find --file page.html | jwtop diff

Use --format json for a machine-readable report suitable for scripts and
CI, or the default --format text for a human-readable summary.`,
	Args: cobra.ArbitraryArgs,
	RunE: func(cmd *cobra.Command, args []string) error {

		tokens, err := readTokensArg(args)
		if err != nil {
			return telemetryx.Reason(err, "no-tokens")
		}

		result, err := jwt.Diff(tokens[0], tokens[1:]...)
		if err != nil {
			return telemetryx.Reason(fmt.Errorf("failed to diff tokens: %w", err), "failed-to-diff-tokens")
		}

		out := cmd.OutOrStdout()
		switch diffFormat {
		case "json":
			if err := printDiffJSON(out, result); err != nil {
				return telemetryx.Reason(err, "failed-to-marshal-diff")
			}
		case "text", "":
			printDiffText(out, result)
		default:
			return telemetryx.Reason(fmt.Errorf("invalid --format %q: must be \"text\" or \"json\"", diffFormat), "invalid-format")
		}

		anyDifferent := false
		for _, d := range result.Diffs {
			if !d.IdenticalToBase {
				anyDifferent = true
				break
			}
		}

		if anyDifferent {
			telemetryx.Exit(cmd, 1)
		}

		return nil
	},
}

func init() {
	diffCmd.Flags().StringVar(&diffFormat, "format", "text", "Output format: text (human-readable) or json (machine-readable)")
}

// printDiffJSON writes result as indented JSON, suitable for scripts and CI.
func printDiffJSON(w io.Writer, result *jwt.DiffResult) error {
	out, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	fmt.Fprintln(w, string(out))
	return nil
}

// printDiffText writes a human-readable summary of result, one section per
// compared token, using +/-/~ markers for added/removed/changed fields.
func printDiffText(w io.Writer, result *jwt.DiffResult) {
	fmt.Fprintf(w, "Base: %s\n", result.Base)

	for i, d := range result.Diffs {
		fmt.Fprintf(w, "\n--- Token %d: %s\n", i+1, d.Token)

		if d.IdenticalToBase {
			fmt.Fprintln(w, "  (identical)")
			continue
		}

		printFieldChanges(w, "Header", d.Header)
		printFieldChanges(w, "Claims", d.Claims)

		if d.SignatureChanged {
			fmt.Fprintln(w, "  Signature: changed")
		}
	}
}

func printFieldChanges(w io.Writer, label string, changes []jwt.FieldChange) {
	if len(changes) == 0 {
		return
	}
	fmt.Fprintf(w, "  %s:\n", label)
	for _, c := range changes {
		switch c.Status {
		case "added":
			fmt.Fprintf(w, "    + %s: %s\n", c.Key, formatDiffValue(c.Other))
		case "removed":
			fmt.Fprintf(w, "    - %s: %s\n", c.Key, formatDiffValue(c.Base))
		case "changed":
			fmt.Fprintf(w, "    ~ %s: %s -> %s\n", c.Key, formatDiffValue(c.Base), formatDiffValue(c.Other))
		}
	}
}

// formatDiffValue renders a decoded JSON value (string, number, bool, nested
// object/array) for display in the text diff.
func formatDiffValue(v interface{}) string {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprintf("%v", v)
	}
	return string(b)
}
