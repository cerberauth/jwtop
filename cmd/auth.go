package cmd

import (
	"fmt"
	"time"

	"github.com/cerberauth/x/authx"
	"github.com/spf13/cobra"
)

func newAuthCmd(clientID string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "auth",
		Short: "Manage cerberauth authentication",
	}

	var deviceCode bool
	loginCmd := &cobra.Command{
		Use:   "login",
		Short: "Log in to cerberauth (opens browser)",
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := authx.New(cmd.Context(), clientID)
			if err != nil {
				return err
			}
			if deviceCode {
				return a.LoginDeviceCode(cmd.Context())
			}
			return a.LoginAuthCode(cmd.Context())
		},
	}
	loginCmd.Flags().BoolVar(&deviceCode, "device-code", false, "use device code flow for headless environments")

	logoutCmd := &cobra.Command{
		Use:   "logout",
		Short: "Clear stored credentials",
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := authx.New(cmd.Context(), clientID)
			if err != nil {
				return err
			}
			if err := a.Logout(cmd.Context()); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), "Logged out.")
			return nil
		},
	}

	statusCmd := &cobra.Command{
		Use:   "status",
		Short: "Show authentication status",
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := authx.New(cmd.Context(), clientID)
			if err != nil {
				return err
			}
			info, err := a.Status(cmd.Context())
			if err != nil {
				fmt.Fprintln(cmd.OutOrStdout(), "Not logged in.")
				return nil
			}
			if info.Expiry.IsZero() {
				fmt.Fprintln(cmd.OutOrStdout(), "Logged in.")
			} else {
				fmt.Fprintf(cmd.OutOrStdout(), "Logged in. Token expires: %s\n",
					info.Expiry.Format(time.RFC3339))
			}
			return nil
		},
	}

	cmd.AddCommand(loginCmd, logoutCmd, statusCmd)
	return cmd
}
