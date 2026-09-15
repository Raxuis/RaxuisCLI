package redteam

import (
	"fmt"

	"github.com/Raxuis/RaxuisCLI/cmd"
	"github.com/Raxuis/RaxuisCLI/internal/redteam/privesc"

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
	Run: func(cmd *cobra.Command, args []string) {
		_ = cmd.Help()
	},
}

var privescCheckCmd = &cobra.Command{
	Use:   "check",
	Short: "Run all privilege escalation checks",
	Long:  `Run comprehensive privilege escalation checks.`,
	Run: func(cmd *cobra.Command, args []string) {
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
	},
}

var privescSuidCmd = &cobra.Command{
	Use:   "suid",
	Short: "Check SUID/SGID binaries",
	Long:  `Find SUID/SGID binaries that may be exploitable for privilege escalation.`,
	Run: func(cmd *cobra.Command, args []string) {
		results := privesc.CheckSUID()
		privesc.DisplayResults(results, privescShowAll)
	},
}

var privescSudoCmd = &cobra.Command{
	Use:   "sudo",
	Short: "Check sudo configuration",
	Long:  `Check sudo configuration for misconfigurations and dangerous permissions.`,
	Run: func(cmd *cobra.Command, args []string) {
		results := privesc.CheckSudo()
		privesc.DisplayResults(results, privescShowAll)
	},
}

var privescCapabilitiesCmd = &cobra.Command{
	Use:   "capabilities",
	Short: "Check Linux capabilities",
	Long:  `Find binaries with dangerous Linux capabilities.`,
	Run: func(cmd *cobra.Command, args []string) {
		results := privesc.CheckCapabilities()
		privesc.DisplayResults(results, privescShowAll)
	},
}

var privescCronCmd = &cobra.Command{
	Use:   "cron",
	Short: "Check cron jobs",
	Long:  `Check cron jobs for misconfigurations and writable scripts.`,
	Run: func(cmd *cobra.Command, args []string) {
		results := privesc.CheckCron()
		privesc.DisplayResults(results, privescShowAll)
	},
}

var privescWritableCmd = &cobra.Command{
	Use:   "writable",
	Short: "Check writable paths",
	Long:  `Check for writable directories in PATH for path hijacking.`,
	Run: func(cmd *cobra.Command, args []string) {
		results := privesc.CheckWritablePaths()
		privesc.DisplayResults(results, privescShowAll)
	},
}

var privescPasswordsCmd = &cobra.Command{
	Use:   "passwords",
	Short: "Check password files",
	Long:  `Check for readable password files and credentials.`,
	Run: func(cmd *cobra.Command, args []string) {
		results := privesc.CheckPasswordFiles()
		privesc.DisplayResults(results, privescShowAll)
	},
}

var privescInfoCmd = &cobra.Command{
	Use:   "info",
	Short: "Display system information",
	Long:  `Display system information useful for privilege escalation.`,
	Run: func(cmd *cobra.Command, args []string) {
		info := privesc.GetSystemInfo()
		privesc.DisplaySystemInfo(info)
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

	fmt.Print("") // Prevent unused import
}
