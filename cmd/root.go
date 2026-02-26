package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/cerberauth/x/telemetryx"
	"github.com/spf13/cobra"
)

var (
	version      string
	sqaOptOut    bool
	otelShutdown func(context.Context) error
)

var name = "jwtop"

var rootCmd = &cobra.Command{
	Use:   name,
	Short: "JWT operations CLI",
	Long:  `JWTop is a command-line tool for decoding, verifying, creating, and signing JWTs.`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		if !sqaOptOut {
			otelShutdown, _ = telemetryx.New(cmd.Context(), name, version)
		}
	},
	PersistentPostRun: func(cmd *cobra.Command, args []string) {
		if otelShutdown != nil {
			_ = otelShutdown(cmd.Context())
			otelShutdown = nil
		}
	},
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println(version)
	},
}

// Execute runs the root command with the given version string.
func Execute(v string) {
	version = v
	rootCmd.AddCommand(versionCmd)

	defer func() {
		if otelShutdown != nil {
			_ = otelShutdown(context.Background())
			otelShutdown = nil
		}
	}()

	if err := rootCmd.Execute(); err != nil {
		if otelShutdown != nil {
			_ = otelShutdown(context.Background())
			otelShutdown = nil
		}

		fmt.Fprintln(os.Stderr, err)
		// nolint: gocritic // false positive
		os.Exit(1)
	}
}

func init() {
	rootCmd.AddCommand(decodeCmd)
	rootCmd.AddCommand(verifyCmd)
	rootCmd.AddCommand(createCmd)
	rootCmd.AddCommand(signCmd)

	rootCmd.PersistentFlags().BoolVarP(&sqaOptOut, "sqa-opt-out", "", false, "Opt out of sending anonymous usage statistics and crash reports to help improve the tool")
}
