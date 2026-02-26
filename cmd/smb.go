package cmd

import (
	"fmt"
	"os"
	"raxuiscli/internal/smb"

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

Enumerate shares, check for vulnerabilities, and gather information
about SMB services.

Examples:
  raxuiscli smb scan 10.0.0.1              # Scan SMB service
  raxuiscli smb shares //10.0.0.1          # List shares
  raxuiscli smb null 10.0.0.1              # Test null session`,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

var smbScanCmd = &cobra.Command{
	Use:   "scan [host]",
	Short: "Scan SMB service",
	Long:  `Scan an SMB service to gather information about the host.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		host := args[0]

		opts := smb.SMBOptions{
			Host:     host,
			Port:     smbPort,
			Username: smbUser,
			Password: smbPass,
			Domain:   smbDomain,
			Timeout:  smbTimeout,
		}

		fmt.Printf("Scanning %s:%d...\n", host, smbPort)

		result, err := smb.Connect(opts)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		smb.DisplayScanResult(result)
	},
}

var smbSharesCmd = &cobra.Command{
	Use:   "shares [host]",
	Short: "Enumerate SMB shares",
	Long:  `Enumerate available SMB shares on a host.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		host := args[0]

		opts := smb.SMBOptions{
			Host:     host,
			Port:     smbPort,
			Username: smbUser,
			Password: smbPass,
			Domain:   smbDomain,
			Timeout:  smbTimeout,
		}

		shares, err := smb.EnumerateShares(opts)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		smb.DisplayShares(shares, host)
	},
}

var smbNullCmd = &cobra.Command{
	Use:   "null [host]",
	Short: "Test null session",
	Long:  `Test if null session (anonymous) access is allowed.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		host := args[0]

		fmt.Printf("Testing null session on %s:%d...\n", host, smbPort)

		allowed, err := smb.CheckNullSession(host, smbPort, smbTimeout)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		if allowed {
			fmt.Println("[!] NULL SESSION ALLOWED - Potential vulnerability")
			fmt.Println("    Anonymous access may be possible")
		} else {
			fmt.Println("[-] Null session not allowed")
		}
	},
}

func init() {
	rootCmd.AddCommand(smbCmd)

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
