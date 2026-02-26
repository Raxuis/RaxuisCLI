package cmd

import (
	"fmt"
	"raxuiscli/internal/redteam/poison"

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
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

var poisonProtocolsCmd = &cobra.Command{
	Use:   "protocols",
	Short: "List poisoning protocols",
	Long:  `List available network poisoning protocols and information.`,
	Run: func(cmd *cobra.Command, args []string) {
		poison.DisplayProtocols()
	},
}

var poisonAnalyzeCmd = &cobra.Command{
	Use:   "analyze",
	Short: "Analyze network for poisoning opportunities",
	Long:  `Analyze network traffic for potential poisoning targets.`,
	Run: func(cmd *cobra.Command, args []string) {
		if poisonInterface == "" {
			poisonInterface = "eth0"
		}

		if poisonDuration <= 0 {
			poisonDuration = 10
		}

		fmt.Printf("Analyzing network on %s for %d seconds...\n", poisonInterface, poisonDuration)

		findings := poison.AnalyzeNetwork(poisonInterface, poisonDuration)
		poison.DisplayAnalysis(findings)
	},
}

var poisonLLMNRCmd = &cobra.Command{
	Use:   "llmnr",
	Short: "LLMNR poisoning commands",
	Long:  `Generate commands for LLMNR poisoning attacks.`,
	Run: func(cmd *cobra.Command, args []string) {
		if poisonInterface == "" {
			poisonInterface = "eth0"
		}

		poison.DisplayCommands(poison.LLMNR, poisonInterface)
	},
}

var poisonMDNSCmd = &cobra.Command{
	Use:   "mdns",
	Short: "mDNS poisoning commands",
	Long:  `Generate commands for mDNS poisoning attacks.`,
	Run: func(cmd *cobra.Command, args []string) {
		if poisonInterface == "" {
			poisonInterface = "eth0"
		}

		poison.DisplayCommands(poison.MDNS, poisonInterface)
	},
}

var poisonNBTNSCmd = &cobra.Command{
	Use:   "nbtns",
	Short: "NBT-NS poisoning commands",
	Long:  `Generate commands for NetBIOS Name Service poisoning attacks.`,
	Run: func(cmd *cobra.Command, args []string) {
		if poisonInterface == "" {
			poisonInterface = "eth0"
		}

		poison.DisplayCommands(poison.NBT_NS, poisonInterface)
	},
}

var poisonARPCmd = &cobra.Command{
	Use:   "arp",
	Short: "ARP poisoning commands",
	Long:  `Generate commands for ARP poisoning/spoofing attacks.`,
	Run: func(cmd *cobra.Command, args []string) {
		if poisonInterface == "" {
			poisonInterface = "eth0"
		}

		poison.DisplayCommands(poison.ARP, poisonInterface)
	},
}

var poisonDHCPCmd = &cobra.Command{
	Use:   "dhcp",
	Short: "DHCP poisoning information",
	Long:  `Generate commands and information for DHCP poisoning attacks.`,
	Run: func(cmd *cobra.Command, args []string) {
		poison.DisplayCommands(poison.DHCP, poisonInterface)
	},
}

var poisonResponderCmd = &cobra.Command{
	Use:   "responder",
	Short: "Responder command generator",
	Long:  `Generate Responder commands with various options.`,
	Run: func(cmd *cobra.Command, args []string) {
		if poisonInterface == "" {
			poisonInterface = "eth0"
		}

		fmt.Println("\n[RESPONDER COMMANDS]")
		fmt.Println("====================")

		fmt.Println("\n# Basic usage")
		fmt.Println(poison.GenerateResponderCommand(poisonInterface, map[string]bool{}))

		fmt.Println("\n# With WPAD proxy")
		fmt.Println(poison.GenerateResponderCommand(poisonInterface, map[string]bool{
			"wpad": true,
		}))

		fmt.Println("\n# Analyze mode only (no poisoning)")
		fmt.Println(poison.GenerateResponderCommand(poisonInterface, map[string]bool{
			"analyze": true,
		}))

		fmt.Println("\n# With fingerprinting")
		fmt.Println(poison.GenerateResponderCommand(poisonInterface, map[string]bool{
			"fingerprint": true,
		}))

		fmt.Println()
	},
}

func init() {
	rootCmd.AddCommand(poisonCmd)

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
