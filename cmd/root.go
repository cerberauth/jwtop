package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/cerberauth/x/telemetryx"
	"github.com/spf13/cobra"
)

// argvioAPIKey is jwtop's public_ingest-scoped Argvio API key, selecting the
// "jwtop" tenant its usage analytics land in. It is not committed: the release
// build injects it with -ldflags -X from the ARGVIO_API_KEY secret, and a build
// without one reports nothing.
var argvioAPIKey string

var (
	sqaOptOut    bool
	otelShutdown func(context.Context) error
	toolVersion  string
)

var name = "jwtop"

func NewRootCmd(projectVersion, commit, date string) (cmd *cobra.Command) {
	toolVersion = projectVersion
	var rootCmd = &cobra.Command{
		Use:     name,
		Version: projectVersion + " (commit=" + commit + ", built=" + date + ")",
		Short:   "JWT operations CLI",
		Long:    `JWTop is a command-line tool for decoding, verifying, creating, and signing JWTs.`,
		// OpenTelemetry stays for observability (crack scan and check spans,
		// timings and external tool runs); usage analytics go to Argvio, see
		// telemetryx.Instrument.
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			if !sqaOptOut {
				otelShutdown, _ = telemetryx.New(cmd.Context(), name, projectVersion, telemetryx.WithCommit(commit), telemetryx.WithBuildDate(date))
			}
		},
		PersistentPostRun: func(cmd *cobra.Command, args []string) {
			shutdownOTel(cmd.Context())
		},
	}

	rootCmd.AddCommand(findCmd)
	rootCmd.AddCommand(genkeyCmd)
	rootCmd.AddCommand(decodeCmd)
	rootCmd.AddCommand(diffCmd)
	rootCmd.AddCommand(verifyCmd)
	rootCmd.AddCommand(createCmd)
	rootCmd.AddCommand(signCmd)
	rootCmd.AddCommand(crackCmd)
	rootCmd.AddCommand(exploitCmd)

	rootCmd.PersistentFlags().BoolVarP(&sqaOptOut, "sqa-opt-out", "", false, "Opt out of sending anonymous usage statistics and crash reports to help improve the tool")

	return rootCmd
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the RootCmd.
func Execute(projectVersion, commit, date string) {
	c := NewRootCmd(projectVersion, commit, date)
	argvioShutdown := telemetryx.Instrument(c, projectVersion, argvioAPIKey)
	defer func() {
		_ = argvioShutdown(context.Background())
		shutdownOTel(context.Background())
	}()

	if err := telemetryx.Execute(c); err != nil {
		_ = argvioShutdown(context.Background())
		shutdownOTel(context.Background())

		fmt.Fprintln(os.Stderr, err)
		// nolint: gocritic // false positive
		os.Exit(1)
	}
}

// shutdownOTel flushes the OpenTelemetry pipeline once, if one was started.
func shutdownOTel(ctx context.Context) {
	if otelShutdown != nil {
		_ = otelShutdown(ctx)
		otelShutdown = nil
	}
}
