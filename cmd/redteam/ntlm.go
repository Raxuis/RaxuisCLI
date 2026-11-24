package redteam

import (
	"fmt"

	"github.com/Raxuis/RaxuisCLI/cmd"
	"github.com/Raxuis/RaxuisCLI/internal/redteam/ntlm"

	"github.com/Raxuis/RaxuisCLI/internal/shared/output"
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
	RunE: func(cmd *cobra.Command, args []string) error {
		_ = cmd.Help()
		return nil
	},
}

var ntlmHashCmd = &cobra.Command{
	Use:   "hash [password]",
	Short: "Generate NTLM hash",
	Long:  `Generate NT hash from a password.`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		password := args[0]

		ntHash := ntlm.ComputeNTHash(password)

		fmt.Fprintln(output.Std, "\n[NTLM HASH GENERATION]")
		fmt.Fprintf(output.Std, "Password: %s\n", password)
		fmt.Fprintf(output.Std, "NT Hash:  %s\n", ntHash)
		fmt.Fprintf(output.Std, "\nHashcat format: %s\n", ntHash)
		fmt.Fprintf(output.Std, "John format:    $NT$%s\n", ntHash)
		return nil
	},
}

var ntlmCrackCmd = &cobra.Command{
	Use:   "crack [hash]",
	Short: "Crack NTLM hash",
	Long:  `Crack an NTLM hash using a wordlist.`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		hash := args[0]

		if ntlmWordlist == "" {
			return fmt.Errorf("--wordlist is required")
		}

		// Validate hash
		if !ntlm.ValidateHash(hash) {
			return fmt.Errorf("invalid hash format (expected 32 hex chars)")
		}

		fmt.Fprintf(output.Std, "Cracking hash: %s\n", hash)
		fmt.Fprintf(output.Std, "Wordlist: %s\n", ntlmWordlist)

		result, err := ntlm.CrackNTHash(hash, ntlmWordlist)
		if err != nil {
			return err
		}

		ntlm.DisplayCrackResult(result)
		return nil
	},
}

var ntlmParseCmd = &cobra.Command{
	Use:   "parse [line]",
	Short: "Parse NTLM dump format",
	Long:  `Parse NTLM hash dump format (user:uid:lmhash:nthash:::).`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		line := args[0]

		hash, err := ntlm.ParseNTLMDump(line)
		if err != nil {
			return fmt.Errorf("error parsing: %v", err)
		}

		ntlm.DisplayHash(hash)

		fmt.Fprintln(output.Std, "Export formats:")
		fmt.Fprintf(output.Std, "  Hashcat: %s\n", ntlm.FormatHashcat(hash))
		fmt.Fprintf(output.Std, "  John:    %s\n", ntlm.FormatJohn(hash))
		return nil
	},
}

var ntlmIdentifyCmd = &cobra.Command{
	Use:   "identify [hash]",
	Short: "Identify hash type",
	Long:  `Identify the type of a hash.`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		hash := args[0]

		hashType := ntlm.IdentifyHashType(hash)

		fmt.Fprintf(output.Std, "\nHash: %s\n", hash)
		fmt.Fprintf(output.Std, "Type: %s\n", hashType)
		return nil
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
	RunE: func(cmd *cobra.Command, args []string) error {
		if ntlmPTHUser == "" || ntlmPTHHash == "" || ntlmPTHTarget == "" {
			return fmt.Errorf("--user, --hash, and --target are required")
		}

		ntlm.DisplayPTHCommands(ntlmPTHUser, ntlmPTHDomain, ntlmPTHHash, ntlmPTHTarget)
		return nil
	},
}

func init() {
	cmd.RootCmd.AddCommand(ntlmCmd)

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
