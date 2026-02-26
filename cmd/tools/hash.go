package cmd

import (
	"fmt"
	"os"
	"raxuiscli/internal/tools/hash"
	"strings"

	"github.com/spf13/cobra"
)

var hashAlgo string
var hashFile bool

var hashCmd = &cobra.Command{
	Use:   "hash [text|file]",
	Short: "Hash text or files",
	Long: `Compute hash of text or files using various algorithms.

Supported algorithms:
  md5     - MD5 (128-bit)
  sha1    - SHA-1 (160-bit)
  sha256  - SHA-256 (256-bit)
  sha512  - SHA-512 (512-bit)
  blake2  - BLAKE2b-256 (256-bit)

Examples:
  raxuiscli hash "password"
  raxuiscli hash "password" --algo md5
  raxuiscli hash /path/to/file --file
  raxuiscli hash /path/to/file --file --algo sha256`,
	Args: cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		input := strings.Join(args, " ")

		// If no algorithm specified, show all hashes
		if hashAlgo == "" {
			results, err := hash.HashAll(input, hashFile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}

			fmt.Println("Hash results:")
			fmt.Println(strings.Repeat("-", 80))
			for algo, hashStr := range results {
				fmt.Printf("%-8s: %s\n", algo, hashStr)
			}
			return
		}

		result, err := hash.Hash(input, hash.Algorithm(hashAlgo), hashFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		fmt.Println(result.Hash)
	},
}

var hashIdentifyCmd = &cobra.Command{
	Use:   "identify [hash]",
	Short: "Identify hash type",
	Long: `Attempt to identify the type of a hash based on its length and format.

Examples:
  raxuiscli hash identify "5d41402abc4b2a76b9719d911017c592"
  raxuiscli hash identify "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		hashStr := args[0]

		result := hash.Identify(hashStr)

		fmt.Println("Hash Analysis:")
		fmt.Println(strings.Repeat("-", 50))
		fmt.Printf("Hash:   %s\n", result.Hash)
		fmt.Printf("Length: %d characters\n", result.Length)

		if len(result.Algorithms) == 0 {
			fmt.Println("Type:   Unknown or invalid hash format")
		} else if len(result.Algorithms) == 1 {
			fmt.Printf("Type:   %s\n", result.Algorithms[0])
		} else {
			algos := make([]string, len(result.Algorithms))
			for i, a := range result.Algorithms {
				algos[i] = string(a)
			}
			fmt.Printf("Type:   %s (possible matches)\n", strings.Join(algos, " or "))
		}
	},
}

var hashWordlist string

var hashCrackCmd = &cobra.Command{
	Use:   "crack [hash]",
	Short: "Crack hash using wordlist",
	Long: `Attempt to crack a hash using a wordlist attack.

Examples:
  raxuiscli hash crack "5d41402abc4b2a76b9719d911017c592" --algo md5 --wordlist /usr/share/wordlists/rockyou.txt
  raxuiscli hash crack "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8" --algo sha1 --wordlist wordlist.txt`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		hashStr := args[0]

		if hashWordlist == "" {
			fmt.Fprintf(os.Stderr, "Error: --wordlist is required\n")
			os.Exit(1)
		}

		// If no algorithm specified, try to identify
		algo := hash.Algorithm(hashAlgo)
		if hashAlgo == "" {
			identified := hash.Identify(hashStr)
			if len(identified.Algorithms) == 0 {
				fmt.Fprintf(os.Stderr, "Error: Could not identify hash type. Please specify --algo\n")
				os.Exit(1)
			}
			algo = identified.Algorithms[0]
			fmt.Printf("Detected hash type: %s\n", algo)
		}

		fmt.Printf("Cracking %s hash...\n", algo)
		fmt.Printf("Wordlist: %s\n", hashWordlist)
		fmt.Println(strings.Repeat("-", 50))

		result, err := hash.CrackWithProgress(hashStr, algo, hashWordlist, func(attempts int) {
			fmt.Printf("\rAttempts: %d", attempts)
		})

		fmt.Println() // New line after progress

		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		if result.Found {
			fmt.Println(strings.Repeat("-", 50))
			fmt.Printf("FOUND!\n")
			fmt.Printf("Hash:      %s\n", result.Hash)
			fmt.Printf("Plaintext: %s\n", result.Plaintext)
			fmt.Printf("Attempts:  %d\n", result.Attempts)
		} else {
			fmt.Println(strings.Repeat("-", 50))
			fmt.Printf("NOT FOUND\n")
			fmt.Printf("Total attempts: %d\n", result.Attempts)
		}
	},
}

func init() {
	rootCmd.AddCommand(hashCmd)
	hashCmd.AddCommand(hashIdentifyCmd)
	hashCmd.AddCommand(hashCrackCmd)

	// Flags for hash command
	hashCmd.PersistentFlags().StringVarP(&hashAlgo, "algo", "a", "", "Hash algorithm (md5|sha1|sha256|sha512|blake2)")
	hashCmd.Flags().BoolVarP(&hashFile, "file", "f", false, "Treat input as a file path")

	// Flags for crack command
	hashCrackCmd.Flags().StringVarP(&hashWordlist, "wordlist", "w", "", "Path to wordlist file")
}
