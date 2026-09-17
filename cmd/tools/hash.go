package tools

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Raxuis/RaxuisCLI/cmd"
	"github.com/Raxuis/RaxuisCLI/internal/shared/output"
	"github.com/Raxuis/RaxuisCLI/internal/tools/hash"

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
	Run: func(_ *cobra.Command, args []string) {
		input := strings.Join(args, " ")

		// If no algorithm specified, show all hashes
		if hashAlgo == "" {
			results, err := hash.HashAll(input, hashFile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}

			hashes := make(map[string]string, len(results))
			for algo, hashStr := range results {
				hashes[string(algo)] = hashStr
			}

			payload := map[string]any{
				"input":  input,
				"file":   hashFile,
				"hashes": hashes,
			}
			_ = output.Emit(payload, func(w io.Writer) {
				fmt.Fprintln(w, "Hash results:")
				fmt.Fprintln(w, strings.Repeat("-", 80))
				for _, algo := range hash.GetSupportedAlgorithms() {
					if h, ok := hashes[string(algo)]; ok {
						fmt.Fprintf(w, "%-8s: %s\n", algo, h)
					}
				}
			})
			return
		}

		result, err := hash.Hash(input, hash.Algorithm(hashAlgo), hashFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		payload := map[string]any{
			"input":     result.Input,
			"file":      result.IsFile,
			"algorithm": string(result.Algorithm),
			"hash":      result.Hash,
		}
		_ = output.Emit(payload, func(w io.Writer) {
			fmt.Fprintln(w, result.Hash)
		})
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
	Run: func(_ *cobra.Command, args []string) {
		result := hash.Identify(args[0])

		algos := make([]string, len(result.Algorithms))
		for i, a := range result.Algorithms {
			algos[i] = string(a)
		}

		payload := map[string]any{
			"hash":       result.Hash,
			"length":     result.Length,
			"algorithms": algos,
		}
		_ = output.Emit(payload, func(w io.Writer) {
			fmt.Fprintln(w, "Hash Analysis:")
			fmt.Fprintln(w, strings.Repeat("-", 50))
			fmt.Fprintf(w, "Hash:   %s\n", result.Hash)
			fmt.Fprintf(w, "Length: %d characters\n", result.Length)
			switch len(result.Algorithms) {
			case 0:
				fmt.Fprintln(w, "Type:   Unknown or invalid hash format")
			case 1:
				fmt.Fprintf(w, "Type:   %s\n", result.Algorithms[0])
			default:
				fmt.Fprintf(w, "Type:   %s (possible matches)\n", strings.Join(algos, " or "))
			}
		})
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
	Run: func(_ *cobra.Command, args []string) {
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
			if !output.JSON() {
				fmt.Printf("Detected hash type: %s\n", algo)
			}
		}

		// Progress and status lines are noise for machine consumers.
		progress := func(attempts int) { fmt.Printf("\rAttempts: %d", attempts) }
		if output.JSON() {
			progress = nil
		} else {
			fmt.Printf("Cracking %s hash...\n", algo)
			fmt.Printf("Wordlist: %s\n", hashWordlist)
			fmt.Println(strings.Repeat("-", 50))
		}

		result, err := hash.CrackWithProgress(hashStr, algo, hashWordlist, progress)
		if !output.JSON() {
			fmt.Println() // New line after progress
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		payload := map[string]any{
			"hash":      result.Hash,
			"algorithm": string(result.Algorithm),
			"found":     result.Found,
			"attempts":  result.Attempts,
		}
		if result.Found {
			payload["plaintext"] = result.Plaintext
		}
		_ = output.Emit(payload, func(w io.Writer) {
			fmt.Fprintln(w, strings.Repeat("-", 50))
			if result.Found {
				fmt.Fprintln(w, "FOUND!")
				fmt.Fprintf(w, "Hash:      %s\n", result.Hash)
				fmt.Fprintf(w, "Plaintext: %s\n", result.Plaintext)
				fmt.Fprintf(w, "Attempts:  %d\n", result.Attempts)
			} else {
				fmt.Fprintln(w, "NOT FOUND")
				fmt.Fprintf(w, "Total attempts: %d\n", result.Attempts)
			}
		})
	},
}

func init() {
	cmd.RootCmd.AddCommand(hashCmd)
	hashCmd.AddCommand(hashIdentifyCmd)
	hashCmd.AddCommand(hashCrackCmd)

	// Flags for hash command
	hashCmd.PersistentFlags().StringVarP(&hashAlgo, "algo", "a", "", "Hash algorithm (md5|sha1|sha256|sha512|blake2)")
	hashCmd.Flags().BoolVarP(&hashFile, "file", "f", false, "Treat input as a file path")

	// Flags for crack command
	hashCrackCmd.Flags().StringVarP(&hashWordlist, "wordlist", "w", "", "Path to wordlist file")
}
