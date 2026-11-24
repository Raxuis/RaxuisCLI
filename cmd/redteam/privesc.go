package redteam

import (
	"fmt"

	"github.com/Raxuis/RaxuisCLI/cmd"
	"github.com/Raxuis/RaxuisCLI/internal/redteam/privesc"

	"github.com/Raxuis/RaxuisCLI/internal/shared/output"
	"github.com/spf13/cobra"
)

var privescThorough bool
var privescShowAll bool

var privescCmd = &cobra.Command{
	Use:   "privesc",
	Short: "Privilege escalation enumeration",
	Long: `Local privilege escalation enumeration tool.

Checks for common privilege escalation vectors on Linux and macOS:
- SUID/SGID binaries
- Sudo misconfigurations
- Linux capabilities
- Cron jobs
- Writable paths
- Password files
- SSH keys
- Docker socket
- Kernel exploits

Examples:
  raxuiscli privesc check              # Run all checks
  raxuiscli privesc suid               # Check SUID binaries only
  raxuiscli privesc sudo               # Check sudo config only
  raxuiscli privesc check --thorough   # Thorough scan`,
	RunE: func(cmd *cobra.Command, args []string) error {
		_ = cmd.Help()
		return nil
	},
}

var privescCheckCmd = &cobra.Command{
	Use:   "check",
	Short: "Run all privilege escalation checks",
	Long:  `Run comprehensive privilege escalation checks.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Show system info first
		info := privesc.GetSystemInfo()
		privesc.DisplaySystemInfo(info)

		// Run all checks
		opts := privesc.Options{
			Thorough: privescThorough,
			Category: "all",
		}

		results := privesc.RunAllChecks(opts)
		privesc.DisplayResults(results, privescShowAll)
		return nil
	},
}

var privescSuidCmd = &cobra.Command{
	Use:   "suid",
	Short: "Check SUID/SGID binaries",
	Long:  `Find SUID/SGID binaries that may be exploitable for privilege escalation.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		results := privesc.CheckSUID()
		privesc.DisplayResults(results, privescShowAll)
		return nil
	},
}

var privescSudoCmd = &cobra.Command{
	Use:   "sudo",
	Short: "Check sudo configuration",
	Long:  `Check sudo configuration for misconfigurations and dangerous permissions.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		results := privesc.CheckSudo()
		privesc.DisplayResults(results, privescShowAll)
		return nil
	},
}

var privescCapabilitiesCmd = &cobra.Command{
	Use:   "capabilities",
	Short: "Check Linux capabilities",
	Long:  `Find binaries with dangerous Linux capabilities.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		results := privesc.CheckCapabilities()
		privesc.DisplayResults(results, privescShowAll)
		return nil
	},
}

var privescCronCmd = &cobra.Command{
	Use:   "cron",
	Short: "Check cron jobs",
	Long:  `Check cron jobs for misconfigurations and writable scripts.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		results := privesc.CheckCron()
		privesc.DisplayResults(results, privescShowAll)
		return nil
	},
}

var privescWritableCmd = &cobra.Command{
	Use:   "writable",
	Short: "Check writable paths",
	Long:  `Check for writable directories in PATH for path hijacking.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		results := privesc.CheckWritablePaths()
		privesc.DisplayResults(results, privescShowAll)
		return nil
	},
}

var privescPasswordsCmd = &cobra.Command{
	Use:   "passwords",
	Short: "Check password files",
	Long:  `Check for readable password files and credentials.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		results := privesc.CheckPasswordFiles()
		privesc.DisplayResults(results, privescShowAll)
		return nil
	},
}

var privescInfoCmd = &cobra.Command{
	Use:   "info",
	Short: "Display system information",
	Long:  `Display system information useful for privilege escalation.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		info := privesc.GetSystemInfo()
		privesc.DisplaySystemInfo(info)
		return nil
	},
}

func init() {
	cmd.RootCmd.AddCommand(privescCmd)

	// Global flags
	privescCmd.PersistentFlags().BoolVar(&privescThorough, "thorough", false, "Perform thorough checks")
	privescCmd.PersistentFlags().BoolVar(&privescShowAll, "all", false, "Show all details")

	// Subcommands
	privescCmd.AddCommand(privescCheckCmd)
	privescCmd.AddCommand(privescSuidCmd)
	privescCmd.AddCommand(privescSudoCmd)
	privescCmd.AddCommand(privescCapabilitiesCmd)
	privescCmd.AddCommand(privescCronCmd)
	privescCmd.AddCommand(privescWritableCmd)
	privescCmd.AddCommand(privescPasswordsCmd)
	privescCmd.AddCommand(privescInfoCmd)

	fmt.Fprint(output. // Prevent unused import
				Std, "")
}
