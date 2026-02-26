package cmd

import (
	"fmt"
	"os"
	"raxuiscli/internal/redteam/ntlm"

	"github.com/spf13/cobra"
)

var ntlmWordlist string

var ntlmCmd = &cobra.Command{
	Use:   "ntlm",
	Short: "NTLM hash operations",
	Long: `NTLM hash toolkit for Windows credential operations.

Generate, crack, and use NTLM hashes for pass-the-hash attacks.

Examples:
  raxuiscli ntlm hash "password"              # Generate NT hash
  raxuiscli ntlm crack <hash> -w wordlist.txt # Crack hash
  raxuiscli ntlm parse "user:1001:lm:nt:::"   # Parse dump format
  raxuiscli ntlm pth -u admin -H <hash> -t 10.0.0.1`,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

var ntlmHashCmd = &cobra.Command{
	Use:   "hash [password]",
	Short: "Generate NTLM hash",
	Long:  `Generate NT hash from a password.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		password := args[0]

		ntHash := ntlm.ComputeNTHash(password)

		fmt.Println("\n[NTLM HASH GENERATION]")
		fmt.Printf("Password: %s\n", password)
		fmt.Printf("NT Hash:  %s\n", ntHash)
		fmt.Printf("\nHashcat format: %s\n", ntHash)
		fmt.Printf("John format:    $NT$%s\n", ntHash)
	},
}

var ntlmCrackCmd = &cobra.Command{
	Use:   "crack [hash]",
	Short: "Crack NTLM hash",
	Long:  `Crack an NTLM hash using a wordlist.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		hash := args[0]

		if ntlmWordlist == "" {
			fmt.Fprintln(os.Stderr, "Error: --wordlist is required")
			os.Exit(1)
		}

		// Validate hash
		if !ntlm.ValidateHash(hash) {
			fmt.Fprintln(os.Stderr, "Error: invalid hash format (expected 32 hex chars)")
			os.Exit(1)
		}

		fmt.Printf("Cracking hash: %s\n", hash)
		fmt.Printf("Wordlist: %s\n", ntlmWordlist)

		result, err := ntlm.CrackNTHash(hash, ntlmWordlist)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		ntlm.DisplayCrackResult(result)
	},
}

var ntlmParseCmd = &cobra.Command{
	Use:   "parse [line]",
	Short: "Parse NTLM dump format",
	Long:  `Parse NTLM hash dump format (user:uid:lmhash:nthash:::).`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		line := args[0]

		hash, err := ntlm.ParseNTLMDump(line)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing: %v\n", err)
			os.Exit(1)
		}

		ntlm.DisplayHash(hash)

		fmt.Println("Export formats:")
		fmt.Printf("  Hashcat: %s\n", ntlm.FormatHashcat(hash))
		fmt.Printf("  John:    %s\n", ntlm.FormatJohn(hash))
	},
}

var ntlmIdentifyCmd = &cobra.Command{
	Use:   "identify [hash]",
	Short: "Identify hash type",
	Long:  `Identify the type of a hash.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		hash := args[0]

		hashType := ntlm.IdentifyHashType(hash)

		fmt.Printf("\nHash: %s\n", hash)
		fmt.Printf("Type: %s\n", hashType)
	},
}

var ntlmPTHUser string
var ntlmPTHHash string
var ntlmPTHDomain string
var ntlmPTHTarget string

var ntlmPTHCmd = &cobra.Command{
	Use:   "pth",
	Short: "Generate pass-the-hash commands",
	Long: `Generate commands for pass-the-hash attacks.

Generates commands for various tools to perform PTH attacks.`,
	Run: func(cmd *cobra.Command, args []string) {
		if ntlmPTHUser == "" || ntlmPTHHash == "" || ntlmPTHTarget == "" {
			fmt.Fprintln(os.Stderr, "Error: --user, --hash, and --target are required")
			os.Exit(1)
		}

		ntlm.DisplayPTHCommands(ntlmPTHUser, ntlmPTHDomain, ntlmPTHHash, ntlmPTHTarget)
	},
}

func init() {
	rootCmd.AddCommand(ntlmCmd)

	// Hash subcommand
	ntlmCmd.AddCommand(ntlmHashCmd)

	// Crack subcommand
	ntlmCmd.AddCommand(ntlmCrackCmd)
	ntlmCrackCmd.Flags().StringVarP(&ntlmWordlist, "wordlist", "w", "", "Wordlist file")

	// Parse subcommand
	ntlmCmd.AddCommand(ntlmParseCmd)

	// Identify subcommand
	ntlmCmd.AddCommand(ntlmIdentifyCmd)

	// PTH subcommand
	ntlmCmd.AddCommand(ntlmPTHCmd)
	ntlmPTHCmd.Flags().StringVarP(&ntlmPTHUser, "user", "u", "", "Username")
	ntlmPTHCmd.Flags().StringVarP(&ntlmPTHHash, "hash", "H", "", "NT hash")
	ntlmPTHCmd.Flags().StringVarP(&ntlmPTHDomain, "domain", "d", "", "Domain (optional)")
	ntlmPTHCmd.Flags().StringVarP(&ntlmPTHTarget, "target", "t", "", "Target host")
}
