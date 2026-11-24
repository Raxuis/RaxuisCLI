package redteam

import (
	"fmt"

	"runtime"

	"github.com/Raxuis/RaxuisCLI/cmd"
	"github.com/Raxuis/RaxuisCLI/internal/redteam/persist"

	"github.com/Raxuis/RaxuisCLI/internal/shared/output"
	"github.com/spf13/cobra"
)

var persistOS string
var persistDetailed bool

var persistCmd = &cobra.Command{
	Use:   "persist",
	Short: "Persistence mechanism helpers",
	Long: `Persistence mechanism reference and generators.

List persistence techniques, generate configuration files, and check
for existing persistence on a system.

Examples:
  raxuiscli persist list                     # List techniques for current OS
  raxuiscli persist list --os linux          # List Linux techniques
  raxuiscli persist cron "*/5 * * * * /tmp/beacon.sh"
  raxuiscli persist systemd --name backdoor --command /tmp/beacon
  raxuiscli persist check                    # Check existing persistence`,
	RunE: func(cmd *cobra.Command, args []string) error {
		_ = cmd.Help()
		return nil
	},
}

var persistListCmd = &cobra.Command{
	Use:   "list",
	Short: "List persistence techniques",
	Long:  `List available persistence techniques for the specified OS.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if persistOS == "" {
			persistOS = runtime.GOOS
		}

		var techniques []persist.TechniqueInfo

		switch persistOS {
		case "linux":
			techniques = persist.LinuxTechniques
		case "darwin", "macos":
			techniques = persist.MacOSTechniques
		case "windows":
			techniques = persist.WindowsTechniques
		case "all":
			fmt.Fprintln(output.Std, "\n=== LINUX ===")
			persist.DisplayTechniques(persist.LinuxTechniques, persistDetailed)
			fmt.Fprintln(output.Std, "\n=== macOS ===")
			persist.DisplayTechniques(persist.MacOSTechniques, persistDetailed)
			fmt.Fprintln(output.Std, "\n=== WINDOWS ===")
			persist.DisplayTechniques(persist.WindowsTechniques, persistDetailed)
			return nil
		default:
			techniques = persist.ListTechniques()
		}

		persist.DisplayTechniques(techniques, persistDetailed)
		return nil
	},
}

var persistCheckCmd = &cobra.Command{
	Use:   "check",
	Short: "Check existing persistence",
	Long:  `Check for existing persistence mechanisms on the system.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		findings := persist.CheckExistingPersistence()
		persist.DisplayExistingPersistence(findings)
		return nil
	},
}

var persistCronCmd = &cobra.Command{
	Use:   "cron [entry]",
	Short: "Generate cron persistence",
	Long:  `Generate cron entry for persistence.`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		entry := args[0]

		fmt.Fprintln(output.Std, "\n[CRON PERSISTENCE]")
		fmt.Fprintln(output.Std, "==================")
		fmt.Fprintln(output.Std, "\nAdd to user crontab:")
		fmt.Fprintf(output.Std, "  crontab -e\n")
		fmt.Fprintf(output.Std, "  %s\n", entry)

		fmt.Fprintln(output.Std, "\nOr add to system crontab (requires root):")
		fmt.Fprintf(output.Std, "  echo '%s' >> /etc/crontab\n", entry)

		fmt.Fprintln(output.Std, "\nOr create a file in /etc/cron.d/:")
		fmt.Fprintf(output.Std, "  echo '%s' > /etc/cron.d/backdoor\n", entry)
		return nil
	},
}

var persistSystemdName string
var persistSystemdCommand string
var persistSystemdDescription string

var persistSystemdCmd = &cobra.Command{
	Use:   "systemd",
	Short: "Generate systemd service",
	Long:  `Generate a systemd service file for persistence.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if persistSystemdName == "" || persistSystemdCommand == "" {
			return fmt.Errorf("--name and --command are required")
		}

		service := persist.GenerateSystemdService(
			persistSystemdName,
			persistSystemdCommand,
			persistSystemdDescription,
		)

		fmt.Fprintln(output.Std, "\n[SYSTEMD PERSISTENCE]")
		fmt.Fprintln(output.Std, "=====================")
		fmt.Fprintf(output.Std, "\nService file: /etc/systemd/system/%s.service\n\n", persistSystemdName)
		fmt.Fprintln(output.Std, service)

		fmt.Fprintln(output.Std, "\nInstallation commands:")
		fmt.Fprintf(output.Std, "  sudo tee /etc/systemd/system/%s.service << 'EOF'\n", persistSystemdName)
		fmt.Fprintln(output.Std, "  [paste service content]")
		fmt.Fprintln(output.Std, "  EOF")
		fmt.Fprintln(output.Std, "  sudo systemctl daemon-reload")
		fmt.Fprintf(output.Std, "  sudo systemctl enable %s\n", persistSystemdName)
		fmt.Fprintf(output.Std, "  sudo systemctl start %s\n", persistSystemdName)
		return nil
	},
}

var persistLaunchdLabel string
var persistLaunchdCommand string

var persistLaunchdCmd = &cobra.Command{
	Use:   "launchd",
	Short: "Generate launchd plist (macOS)",
	Long:  `Generate a macOS launchd plist for persistence.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if persistLaunchdLabel == "" || persistLaunchdCommand == "" {
			return fmt.Errorf("--label and --command are required")
		}

		plist := persist.GenerateLaunchdPlist(persistLaunchdLabel, persistLaunchdCommand, true)

		fmt.Fprintln(output.Std, "\n[LAUNCHD PERSISTENCE]")
		fmt.Fprintln(output.Std, "=====================")
		fmt.Fprintf(output.Std, "\nUser LaunchAgent: ~/Library/LaunchAgents/%s.plist\n", persistLaunchdLabel)
		fmt.Fprintf(output.Std, "System LaunchDaemon: /Library/LaunchDaemons/%s.plist\n\n", persistLaunchdLabel)
		fmt.Fprintln(output.Std, plist)

		fmt.Fprintln(output.Std, "\nInstallation:")
		fmt.Fprintf(output.Std, "  # User level\n")
		fmt.Fprintf(output.Std, "  tee ~/Library/LaunchAgents/%s.plist << 'EOF'\n", persistLaunchdLabel)
		fmt.Fprintln(output.Std, "  [paste plist]")
		fmt.Fprintln(output.Std, "  EOF")
		fmt.Fprintf(output.Std, "  launchctl load ~/Library/LaunchAgents/%s.plist\n", persistLaunchdLabel)
		return nil
	},
}

func init() {
	cmd.RootCmd.AddCommand(persistCmd)

	// List subcommand
	persistCmd.AddCommand(persistListCmd)
	persistListCmd.Flags().StringVar(&persistOS, "os", "", "Target OS (linux, darwin, windows, all)")
	persistListCmd.Flags().BoolVar(&persistDetailed, "detailed", false, "Show detailed information")

	// Check subcommand
	persistCmd.AddCommand(persistCheckCmd)

	// Cron subcommand
	persistCmd.AddCommand(persistCronCmd)

	// Systemd subcommand
	persistCmd.AddCommand(persistSystemdCmd)
	persistSystemdCmd.Flags().StringVar(&persistSystemdName, "name", "", "Service name")
	persistSystemdCmd.Flags().StringVar(&persistSystemdCommand, "command", "", "Command to execute")
	persistSystemdCmd.Flags().StringVar(&persistSystemdDescription, "desc", "", "Service description")

	// Launchd subcommand
	persistCmd.AddCommand(persistLaunchdCmd)
	persistLaunchdCmd.Flags().StringVar(&persistLaunchdLabel, "label", "", "Plist label")
	persistLaunchdCmd.Flags().StringVar(&persistLaunchdCommand, "command", "", "Command to execute")
}
