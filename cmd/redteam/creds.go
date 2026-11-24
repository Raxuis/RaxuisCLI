package redteam

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/Raxuis/RaxuisCLI/cmd"
	"github.com/Raxuis/RaxuisCLI/internal/redteam/creds"

	"github.com/Raxuis/RaxuisCLI/internal/shared/output"
	"github.com/spf13/cobra"
)

var credsShowAll bool
var credsFormat string
var credsOutput string
var credsDomain string

var credsCmd = &cobra.Command{
	Use:   "creds",
	Short: "Credential extraction and manipulation",
	Long: `Credential extraction, parsing, and manipulation toolkit.

Extract credentials from dumps, convert formats, and prepare wordlists.

Examples:
  raxuiscli creds extract dump.txt           # Extract credentials
  raxuiscli creds extract dump.txt --all     # Show all details
  raxuiscli creds convert dump.txt -f userpass -o clean.txt
  raxuiscli creds decode "YWRtaW46cGFzc3dvcmQ="
  raxuiscli creds combo -u users.txt -p passwords.txt`,
	RunE: func(cmd *cobra.Command, args []string) error {
		_ = cmd.Help()
		return nil
	},
}

var credsExtractCmd = &cobra.Command{
	Use:   "extract [file]",
	Short: "Extract credentials from file",
	Long: `Extract credentials, hashes, emails, and URLs from a file.

Supports various formats:
- user:pass
- email:pass
- domain\user:pass
- NTLM hash dumps
- /etc/shadow format`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		filePath := args[0]

		result, err := creds.ExtractFromFile(filePath)
		if err != nil {
			return err
		}

		creds.DisplayResult(result, credsShowAll)

		// Export if output specified
		if credsOutput != "" {
			var lines []string
			for _, c := range result.Credentials {
				if c.Password != "" {
					lines = append(lines, fmt.Sprintf("%s:%s", c.Username, c.Password))
				} else if c.Hash != "" {
					lines = append(lines, fmt.Sprintf("%s:%s", c.Username, c.Hash))
				}
			}
			if err := creds.WriteToFile(lines, credsOutput); err != nil {
				return fmt.Errorf("error writing output: %v", err)
			}
			fmt.Fprintf(output.Std, "Exported %d credentials to %s\n", len(lines), credsOutput)
		}
		return nil
	},
}

var credsConvertCmd = &cobra.Command{
	Use:   "convert [file]",
	Short: "Convert credential format",
	Long: `Convert credentials to different formats.

Available formats:
- userpass    : user:pass
- user        : usernames only
- pass        : passwords only
- email       : emails only
- emailpass   : email:pass
- domain      : domain\user:pass
- hash        : user:hash
- hashcat     : hash only (for hashcat)
- john        : user:hash (for John)`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		filePath := args[0]

		result, err := creds.ExtractFromFile(filePath)
		if err != nil {
			return err
		}

		if len(result.Credentials) == 0 {
			fmt.Fprintln(output.Std, "No credentials found")
			return nil
		}

		lines := creds.ConvertFormat(result.Credentials, credsFormat)

		if credsOutput != "" {
			if err := creds.WriteToFile(lines, credsOutput); err != nil {
				return fmt.Errorf("error writing output: %v", err)
			}
			fmt.Fprintf(output.Std, "Exported %d lines to %s\n", len(lines), credsOutput)
		} else {
			for _, line := range lines {
				fmt.Fprintln(output.Std, line)
			}
		}
		return nil
	},
}

var credsDecodeCmd = &cobra.Command{
	Use:   "decode [encoded]",
	Short: "Decode encoded credentials",
	Long: `Attempt to decode encoded credentials.

Tries various encoding methods:
- Base64
- Base64-URL
- URL encoding
- Hex`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		encoded := args[0]

		fmt.Fprintf(output.Std, "Input: %s\n\n", encoded)
		fmt.Fprintln(output.Std, "Decoded results:")
		fmt.Fprintln(output.Std, strings.Repeat("-", 40))

		results := creds.DecodeCredential(encoded)

		if len(results) == 0 {
			fmt.Fprintln(output.Std, "No valid decoding found")
			return nil
		}

		for _, r := range results {
			fmt.Fprintf(output.Std, "[%s] %s\n", r.Method, r.Value)
		}
		return nil
	},
}

var credsUsersFile string
var credsPassFile string

var credsComboCmd = &cobra.Command{
	Use:   "combo",
	Short: "Generate credential combinations",
	Long: `Generate credential combinations from user and password lists.

Creates all possible user:password combinations.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if credsUsersFile == "" || credsPassFile == "" {
			return fmt.Errorf("both --users and --passwords are required")
		}

		// Read users
		users, err := readLines(credsUsersFile)
		if err != nil {
			return fmt.Errorf("error reading users file: %v", err)
		}

		// Read passwords
		passwords, err := readLines(credsPassFile)
		if err != nil {
			return fmt.Errorf("error reading passwords file: %v", err)
		}

		fmt.Fprintf(output.Std, "Generating combinations: %d users x %d passwords = %d combos\n",
			len(users), len(passwords), len(users)*len(passwords))

		combos := creds.GenerateCombo(users, passwords, credsDomain)

		if credsOutput != "" {
			var lines []string
			for _, c := range combos {
				if credsDomain != "" {
					lines = append(lines, fmt.Sprintf("%s\\%s:%s", c.Domain, c.Username, c.Password))
				} else {
					lines = append(lines, fmt.Sprintf("%s:%s", c.Username, c.Password))
				}
			}
			if err := creds.WriteToFile(lines, credsOutput); err != nil {
				return fmt.Errorf("error writing output: %v", err)
			}
			fmt.Fprintf(output.Std, "Exported %d combinations to %s\n", len(lines), credsOutput)
		} else {
			for _, c := range combos {
				if credsDomain != "" {
					fmt.Fprintf(output.Std, "%s\\%s:%s\n", c.Domain, c.Username, c.Password)
				} else {
					fmt.Fprintf(output.Std, "%s:%s\n", c.Username, c.Password)
				}
			}
		}
		return nil
	},
}

var credsMergeCmd = &cobra.Command{
	Use:   "merge [files...]",
	Short: "Merge and deduplicate credential files",
	Long:  `Merge multiple credential files and remove duplicates.`,
	Args:  cobra.MinimumNArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		var allCreds []creds.Credential

		for _, filePath := range args {
			result, err := creds.ExtractFromFile(filePath)
			if err != nil {
				return fmt.Errorf("reading %s: %w", filePath, err)
			}
			allCreds = append(allCreds, result.Credentials...)
			fmt.Fprintf(output.Std, "Loaded %d credentials from %s\n", len(result.Credentials), filePath)
		}

		merged := creds.MergeDedupe(allCreds)
		fmt.Fprintf(output.Std, "\nMerged: %d unique credentials\n", len(merged))

		if credsOutput != "" {
			lines := creds.ConvertFormat(merged, "userpass")
			if err := creds.WriteToFile(lines, credsOutput); err != nil {
				return fmt.Errorf("error writing output: %v", err)
			}
			fmt.Fprintf(output.Std, "Exported to %s\n", credsOutput)
		}
		return nil
	},
}

func readLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}

	return lines, scanner.Err()
}

func init() {
	cmd.RootCmd.AddCommand(credsCmd)

	// Global flags
	credsCmd.PersistentFlags().BoolVar(&credsShowAll, "all", false, "Show all details")
	credsCmd.PersistentFlags().StringVarP(&credsOutput, "out", "o", "", "Output file")

	// Extract command
	credsCmd.AddCommand(credsExtractCmd)

	// Convert command
	credsCmd.AddCommand(credsConvertCmd)
	credsConvertCmd.Flags().StringVarP(&credsFormat, "format", "f", "userpass", "Output format")

	// Decode command
	credsCmd.AddCommand(credsDecodeCmd)

	// Combo command
	credsCmd.AddCommand(credsComboCmd)
	credsComboCmd.Flags().StringVarP(&credsUsersFile, "users", "u", "", "Users file")
	credsComboCmd.Flags().StringVarP(&credsPassFile, "passwords", "p", "", "Passwords file")
	credsComboCmd.Flags().StringVarP(&credsDomain, "domain", "d", "", "Domain to prepend")

	// Merge command
	credsCmd.AddCommand(credsMergeCmd)
}
