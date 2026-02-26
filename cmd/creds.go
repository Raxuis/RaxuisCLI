package cmd

import (
	"bufio"
	"fmt"
	"os"
	"raxuiscli/internal/creds"
	"strings"

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
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
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
	Run: func(cmd *cobra.Command, args []string) {
		filePath := args[0]

		result, err := creds.ExtractFromFile(filePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
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
				fmt.Fprintf(os.Stderr, "Error writing output: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("Exported %d credentials to %s\n", len(lines), credsOutput)
		}
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
	Run: func(cmd *cobra.Command, args []string) {
		filePath := args[0]

		result, err := creds.ExtractFromFile(filePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		if len(result.Credentials) == 0 {
			fmt.Println("No credentials found")
			return
		}

		lines := creds.ConvertFormat(result.Credentials, credsFormat)

		if credsOutput != "" {
			if err := creds.WriteToFile(lines, credsOutput); err != nil {
				fmt.Fprintf(os.Stderr, "Error writing output: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("Exported %d lines to %s\n", len(lines), credsOutput)
		} else {
			for _, line := range lines {
				fmt.Println(line)
			}
		}
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
	Run: func(cmd *cobra.Command, args []string) {
		encoded := args[0]

		fmt.Printf("Input: %s\n\n", encoded)
		fmt.Println("Decoded results:")
		fmt.Println(strings.Repeat("-", 40))

		results := creds.DecodeCredential(encoded)

		if len(results) == 0 {
			fmt.Println("No valid decoding found")
			return
		}

		for _, r := range results {
			fmt.Printf("[%s] %s\n", r.Method, r.Value)
		}
	},
}

var credsUsersFile string
var credsPassFile string

var credsComboCmd = &cobra.Command{
	Use:   "combo",
	Short: "Generate credential combinations",
	Long: `Generate credential combinations from user and password lists.

Creates all possible user:password combinations.`,
	Run: func(cmd *cobra.Command, args []string) {
		if credsUsersFile == "" || credsPassFile == "" {
			fmt.Fprintln(os.Stderr, "Error: both --users and --passwords are required")
			os.Exit(1)
		}

		// Read users
		users, err := readLines(credsUsersFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading users file: %v\n", err)
			os.Exit(1)
		}

		// Read passwords
		passwords, err := readLines(credsPassFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading passwords file: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("Generating combinations: %d users x %d passwords = %d combos\n",
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
				fmt.Fprintf(os.Stderr, "Error writing output: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("Exported %d combinations to %s\n", len(lines), credsOutput)
		} else {
			for _, c := range combos {
				if credsDomain != "" {
					fmt.Printf("%s\\%s:%s\n", c.Domain, c.Username, c.Password)
				} else {
					fmt.Printf("%s:%s\n", c.Username, c.Password)
				}
			}
		}
	},
}

var credsMergeCmd = &cobra.Command{
	Use:   "merge [files...]",
	Short: "Merge and deduplicate credential files",
	Long:  `Merge multiple credential files and remove duplicates.`,
	Args:  cobra.MinimumNArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		var allCreds []creds.Credential

		for _, filePath := range args {
			result, err := creds.ExtractFromFile(filePath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error reading %s: %v\n", filePath, err)
				continue
			}
			allCreds = append(allCreds, result.Credentials...)
			fmt.Printf("Loaded %d credentials from %s\n", len(result.Credentials), filePath)
		}

		merged := creds.MergeDedupe(allCreds)
		fmt.Printf("\nMerged: %d unique credentials\n", len(merged))

		if credsOutput != "" {
			lines := creds.ConvertFormat(merged, "userpass")
			if err := creds.WriteToFile(lines, credsOutput); err != nil {
				fmt.Fprintf(os.Stderr, "Error writing output: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("Exported to %s\n", credsOutput)
		}
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
	rootCmd.AddCommand(credsCmd)

	// Global flags
	credsCmd.PersistentFlags().BoolVar(&credsShowAll, "all", false, "Show all details")
	credsCmd.PersistentFlags().StringVarP(&credsOutput, "output", "o", "", "Output file")

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
