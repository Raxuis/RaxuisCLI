package redteam

import (
	"fmt"

	"github.com/Raxuis/RaxuisCLI/cmd"
	"github.com/Raxuis/RaxuisCLI/internal/redteam/smb"

	"github.com/Raxuis/RaxuisCLI/internal/shared/output"
	"github.com/spf13/cobra"
)

var smbPort int
var smbUser string
var smbPass string
var smbDomain string
var smbTimeout int

var smbCmd = &cobra.Command{
	Use:   "smb",
	Short: "SMB enumeration and analysis",
	Long: `SMB reconnaissance toolkit for Windows network analysis.

Scan SMB negotiation and signing settings. Share enumeration and null-session
authentication are not implemented and return explicit errors without connecting.

Examples:
  raxuiscli smb scan 10.0.0.1              # Scan SMB service
  raxuiscli smb shares 10.0.0.1            # Returns unsupported error
  raxuiscli smb null 10.0.0.1              # Returns unsupported error`,
	RunE: func(cmd *cobra.Command, args []string) error {
		_ = cmd.Help()
		return nil
	},
}

var smbScanCmd = &cobra.Command{
	Use:   "scan [host]",
	Short: "Scan SMB service",
	Long:  `Scan an SMB service to gather information about the host.`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		host := args[0]

		opts := smb.SMBOptions{
			Host:     host,
			Port:     smbPort,
			Username: smbUser,
			Password: smbPass,
			Domain:   smbDomain,
			Timeout:  smbTimeout,
		}

		fmt.Fprintf(output.Std, "Scanning %s:%d...\n", host, smbPort)

		result, err := smb.Connect(opts)
		if err != nil {
			return err
		}

		if result.Error != nil {
			return result.Error
		}
		smb.DisplayScanResult(result)
		return nil
	},
}

var smbSharesCmd = &cobra.Command{
	Use:   "shares [host]",
	Short: "Enumerate SMB shares",
	Long:  `Share enumeration is not implemented. This command returns an explicit error without connecting.`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		host := args[0]

		opts := smb.SMBOptions{
			Host:     host,
			Port:     smbPort,
			Username: smbUser,
			Password: smbPass,
			Domain:   smbDomain,
			Timeout:  smbTimeout,
		}

		_, err := smb.EnumerateShares(opts)
		return err
	},
}

var smbNullCmd = &cobra.Command{
	Use:   "null [host]",
	Short: "Test null session",
	Long:  `Null-session authentication is not implemented. Negotiation alone does not prove anonymous access; this command returns an explicit error without connecting.`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		host := args[0]

		_, err := smb.CheckNullSession(host, smbPort, smbTimeout)
		return err
	},
}

func init() {
	cmd.RootCmd.AddCommand(smbCmd)

	// Global flags
	smbCmd.PersistentFlags().IntVarP(&smbPort, "port", "P", 445, "SMB port")
	smbCmd.PersistentFlags().StringVarP(&smbUser, "user", "u", "", "Username")
	smbCmd.PersistentFlags().StringVarP(&smbPass, "pass", "p", "", "Password")
	smbCmd.PersistentFlags().StringVarP(&smbDomain, "domain", "d", "", "Domain")
	smbCmd.PersistentFlags().IntVarP(&smbTimeout, "timeout", "t", 10, "Timeout in seconds")

	// Subcommands
	smbCmd.AddCommand(smbScanCmd)
	smbCmd.AddCommand(smbSharesCmd)
	smbCmd.AddCommand(smbNullCmd)
}
