package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/cerberauth/x/telemetryx"
	"github.com/spf13/cobra"
)

// argvioAPIKey is jwtop's public_ingest-scoped Argvio API key, selecting the
// "jwtop" tenant its usage analytics land in. It only allows sending usage
// data, so it is safe to embed.
const argvioAPIKey = "argv_live_pub_be5GbbL89N0OzMuqmKqn82uhNZzKJmPb" //nolint:gosec // ingest-only key, not a secret

var (
	sqaOptOut   bool
	toolVersion string
)

var name = "jwtop"

func NewRootCmd(projectVersion, commit, date string) (cmd *cobra.Command) {
	toolVersion = projectVersion
	var rootCmd = &cobra.Command{
		Use:     name,
		Version: projectVersion + " (commit=" + commit + ", built=" + date + ")",
		Short:   "JWT operations CLI",
		Long:    `JWTop is a command-line tool for decoding, verifying, creating, and signing JWTs.`,
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
	defer func() { _ = argvioShutdown(context.Background()) }()

	if err := c.Execute(); err != nil {
		_ = argvioShutdown(context.Background())

		fmt.Fprintln(os.Stderr, err)
		// nolint: gocritic // false positive
		os.Exit(1)
	}
}
