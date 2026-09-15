package redteam

import (
	"fmt"
	"os"
	"runtime"

	"github.com/Raxuis/RaxuisCLI/cmd"
	"github.com/Raxuis/RaxuisCLI/internal/redteam/persist"

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
	Run: func(cmd *cobra.Command, args []string) {
		_ = cmd.Help()
	},
}

var persistListCmd = &cobra.Command{
	Use:   "list",
	Short: "List persistence techniques",
	Long:  `List available persistence techniques for the specified OS.`,
	Run: func(cmd *cobra.Command, args []string) {
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
			fmt.Println("\n=== LINUX ===")
			persist.DisplayTechniques(persist.LinuxTechniques, persistDetailed)
			fmt.Println("\n=== macOS ===")
			persist.DisplayTechniques(persist.MacOSTechniques, persistDetailed)
			fmt.Println("\n=== WINDOWS ===")
			persist.DisplayTechniques(persist.WindowsTechniques, persistDetailed)
			return
		default:
			techniques = persist.ListTechniques()
		}

		persist.DisplayTechniques(techniques, persistDetailed)
	},
}

var persistCheckCmd = &cobra.Command{
	Use:   "check",
	Short: "Check existing persistence",
	Long:  `Check for existing persistence mechanisms on the system.`,
	Run: func(cmd *cobra.Command, args []string) {
		findings := persist.CheckExistingPersistence()
		persist.DisplayExistingPersistence(findings)
	},
}

var persistCronCmd = &cobra.Command{
	Use:   "cron [entry]",
	Short: "Generate cron persistence",
	Long:  `Generate cron entry for persistence.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		entry := args[0]

		fmt.Println("\n[CRON PERSISTENCE]")
		fmt.Println("==================")
		fmt.Println("\nAdd to user crontab:")
		fmt.Printf("  crontab -e\n")
		fmt.Printf("  %s\n", entry)

		fmt.Println("\nOr add to system crontab (requires root):")
		fmt.Printf("  echo '%s' >> /etc/crontab\n", entry)

		fmt.Println("\nOr create a file in /etc/cron.d/:")
		fmt.Printf("  echo '%s' > /etc/cron.d/backdoor\n", entry)
	},
}

var persistSystemdName string
var persistSystemdCommand string
var persistSystemdDescription string

var persistSystemdCmd = &cobra.Command{
	Use:   "systemd",
	Short: "Generate systemd service",
	Long:  `Generate a systemd service file for persistence.`,
	Run: func(cmd *cobra.Command, args []string) {
		if persistSystemdName == "" || persistSystemdCommand == "" {
			fmt.Fprintln(os.Stderr, "Error: --name and --command are required")
			os.Exit(1)
		}

		service := persist.GenerateSystemdService(
			persistSystemdName,
			persistSystemdCommand,
			persistSystemdDescription,
		)

		fmt.Println("\n[SYSTEMD PERSISTENCE]")
		fmt.Println("=====================")
		fmt.Printf("\nService file: /etc/systemd/system/%s.service\n\n", persistSystemdName)
		fmt.Println(service)

		fmt.Println("\nInstallation commands:")
		fmt.Printf("  sudo tee /etc/systemd/system/%s.service << 'EOF'\n", persistSystemdName)
		fmt.Println("  [paste service content]")
		fmt.Println("  EOF")
		fmt.Println("  sudo systemctl daemon-reload")
		fmt.Printf("  sudo systemctl enable %s\n", persistSystemdName)
		fmt.Printf("  sudo systemctl start %s\n", persistSystemdName)
	},
}

var persistLaunchdLabel string
var persistLaunchdCommand string

var persistLaunchdCmd = &cobra.Command{
	Use:   "launchd",
	Short: "Generate launchd plist (macOS)",
	Long:  `Generate a macOS launchd plist for persistence.`,
	Run: func(cmd *cobra.Command, args []string) {
		if persistLaunchdLabel == "" || persistLaunchdCommand == "" {
			fmt.Fprintln(os.Stderr, "Error: --label and --command are required")
			os.Exit(1)
		}

		plist := persist.GenerateLaunchdPlist(persistLaunchdLabel, persistLaunchdCommand, true)

		fmt.Println("\n[LAUNCHD PERSISTENCE]")
		fmt.Println("=====================")
		fmt.Printf("\nUser LaunchAgent: ~/Library/LaunchAgents/%s.plist\n", persistLaunchdLabel)
		fmt.Printf("System LaunchDaemon: /Library/LaunchDaemons/%s.plist\n\n", persistLaunchdLabel)
		fmt.Println(plist)

		fmt.Println("\nInstallation:")
		fmt.Printf("  # User level\n")
		fmt.Printf("  tee ~/Library/LaunchAgents/%s.plist << 'EOF'\n", persistLaunchdLabel)
		fmt.Println("  [paste plist]")
		fmt.Println("  EOF")
		fmt.Printf("  launchctl load ~/Library/LaunchAgents/%s.plist\n", persistLaunchdLabel)
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
