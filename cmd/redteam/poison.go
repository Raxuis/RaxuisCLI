package redteam

import (
	"fmt"

	"github.com/Raxuis/RaxuisCLI/cmd"
	"github.com/Raxuis/RaxuisCLI/internal/redteam/poison"

	"github.com/Raxuis/RaxuisCLI/internal/shared/output"
	"github.com/spf13/cobra"
)

var poisonInterface string
var poisonDuration int

var poisonCmd = &cobra.Command{
	Use:   "poison",
	Short: "Network poisoning helpers",
	Long: `Network poisoning toolkit for credential capture.

Generate commands and analyze networks for LLMNR, mDNS, NBT-NS,
ARP, and DHCP poisoning attacks.

Examples:
  raxuiscli poison protocols                 # List poisoning protocols
  raxuiscli poison analyze -i eth0           # Analyze network traffic
  raxuiscli poison llmnr -i eth0             # LLMNR poisoning commands
  raxuiscli poison arp -i eth0               # ARP poisoning commands`,
	RunE: func(cmd *cobra.Command, args []string) error {
		_ = cmd.Help()
		return nil
	},
}

var poisonProtocolsCmd = &cobra.Command{
	Use:   "protocols",
	Short: "List poisoning protocols",
	Long:  `List available network poisoning protocols and information.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		poison.DisplayProtocols()
		return nil
	},
}

var poisonAnalyzeCmd = &cobra.Command{
	Use:   "analyze",
	Short: "Analyze network for poisoning opportunities",
	Long:  `Analyze network traffic for potential poisoning targets.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if poisonInterface == "" {
			poisonInterface = "eth0"
		}

		if poisonDuration <= 0 {
			poisonDuration = 10
		}

		fmt.Fprintf(output.Std, "Analyzing network on %s for %d seconds...\n", poisonInterface, poisonDuration)

		findings := poison.AnalyzeNetwork(poisonInterface, poisonDuration)
		poison.DisplayAnalysis(findings)
		return nil
	},
}

var poisonLLMNRCmd = &cobra.Command{
	Use:   "llmnr",
	Short: "LLMNR poisoning commands",
	Long:  `Generate commands for LLMNR poisoning attacks.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if poisonInterface == "" {
			poisonInterface = "eth0"
		}

		poison.DisplayCommands(poison.LLMNR, poisonInterface)
		return nil
	},
}

var poisonMDNSCmd = &cobra.Command{
	Use:   "mdns",
	Short: "mDNS poisoning commands",
	Long:  `Generate commands for mDNS poisoning attacks.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if poisonInterface == "" {
			poisonInterface = "eth0"
		}

		poison.DisplayCommands(poison.MDNS, poisonInterface)
		return nil
	},
}

var poisonNBTNSCmd = &cobra.Command{
	Use:   "nbtns",
	Short: "NBT-NS poisoning commands",
	Long:  `Generate commands for NetBIOS Name Service poisoning attacks.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if poisonInterface == "" {
			poisonInterface = "eth0"
		}

		poison.DisplayCommands(poison.NBT_NS, poisonInterface)
		return nil
	},
}

var poisonARPCmd = &cobra.Command{
	Use:   "arp",
	Short: "ARP poisoning commands",
	Long:  `Generate commands for ARP poisoning/spoofing attacks.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if poisonInterface == "" {
			poisonInterface = "eth0"
		}

		poison.DisplayCommands(poison.ARP, poisonInterface)
		return nil
	},
}

var poisonDHCPCmd = &cobra.Command{
	Use:   "dhcp",
	Short: "DHCP poisoning information",
	Long:  `Generate commands and information for DHCP poisoning attacks.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		poison.DisplayCommands(poison.DHCP, poisonInterface)
		return nil
	},
}

var poisonResponderCmd = &cobra.Command{
	Use:   "responder",
	Short: "Responder command generator",
	Long:  `Generate Responder commands with various options.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if poisonInterface == "" {
			poisonInterface = "eth0"
		}

		fmt.Fprintln(output.Std, "\n[RESPONDER COMMANDS]")
		fmt.Fprintln(output.Std, "====================")

		fmt.Fprintln(output.Std, "\n# Basic usage")
		fmt.Fprintln(output.Std, poison.GenerateResponderCommand(poisonInterface, map[string]bool{}))

		fmt.Fprintln(output.Std, "\n# With WPAD proxy")
		fmt.Fprintln(output.Std, poison.GenerateResponderCommand(poisonInterface, map[string]bool{
			"wpad": true,
		}))

		fmt.Fprintln(output.Std, "\n# Analyze mode only (no poisoning)")
		fmt.Fprintln(output.Std, poison.GenerateResponderCommand(poisonInterface, map[string]bool{
			"analyze": true,
		}))

		fmt.Fprintln(output.Std, "\n# With fingerprinting")
		fmt.Fprintln(output.Std, poison.GenerateResponderCommand(poisonInterface, map[string]bool{
			"fingerprint": true,
		}))

		fmt.Fprintln(output.Std)
		return nil
	},
}

func init() {
	cmd.RootCmd.AddCommand(poisonCmd)

	// Global flags
	poisonCmd.PersistentFlags().StringVarP(&poisonInterface, "interface", "i", "eth0", "Network interface")

	// Subcommands
	poisonCmd.AddCommand(poisonProtocolsCmd)

	poisonCmd.AddCommand(poisonAnalyzeCmd)
	poisonAnalyzeCmd.Flags().IntVarP(&poisonDuration, "duration", "d", 10, "Analysis duration in seconds")

	poisonCmd.AddCommand(poisonLLMNRCmd)
	poisonCmd.AddCommand(poisonMDNSCmd)
	poisonCmd.AddCommand(poisonNBTNSCmd)
	poisonCmd.AddCommand(poisonARPCmd)
	poisonCmd.AddCommand(poisonDHCPCmd)
	poisonCmd.AddCommand(poisonResponderCmd)
}
