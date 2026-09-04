package tools

import (
	"fmt"
	"os"
	"strings"

	"raxuiscli/cmd"
	"raxuiscli/internal/tools/encode"

	"github.com/spf13/cobra"
)

var encodeFormat string
var encodeShift int

var encodeCmd = &cobra.Command{
	Use:   "encode [text]",
	Short: "Encode text in various formats",
	Long: `Encode text using various encoding formats.

Supported formats:
  base64  - Base64 encoding
  base32  - Base32 encoding
  hex     - Hexadecimal encoding
  url     - URL encoding (percent-encoding)
  html    - HTML entities encoding
  rot13   - ROT13 cipher
  rotn    - ROT-N cipher (use --shift to specify N)

Examples:
  raxuiscli encode "Hello World" --format base64
  raxuiscli encode "Hello World" --format hex
  raxuiscli encode "secret" --format rot13
  raxuiscli encode "secret" --format rotn --shift 5
  raxuiscli encode "Hello World"  # Shows all encodings`,
	Args: cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		input := strings.Join(args, " ")

		// If no format specified, show all encodings
		if encodeFormat == "" {
			results := encode.EncodeAll(input)
			fmt.Println("Encoded results:")
			fmt.Println(strings.Repeat("-", 50))
			for format, result := range results {
				fmt.Printf("%-10s: %s\n", format, result)
			}
			return
		}

		opts := encode.Options{
			Format: encode.Format(encodeFormat),
			Shift:  encodeShift,
		}

		result, err := encode.Encode(input, opts)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		fmt.Println(result)
	},
}

var decodeCmd = &cobra.Command{
	Use:   "decode [text]",
	Short: "Decode text from various formats",
	Long: `Decode text from various encoding formats.

Supported formats:
  base64  - Base64 decoding
  base32  - Base32 decoding
  hex     - Hexadecimal decoding
  url     - URL decoding (percent-decoding)
  html    - HTML entities decoding
  rot13   - ROT13 cipher (self-inverse)
  rotn    - ROT-N cipher (use --shift to specify N)

Examples:
  raxuiscli encode decode "SGVsbG8gV29ybGQ=" --format base64
  raxuiscli encode decode "48656c6c6f" --format hex
  raxuiscli encode decode "frperg" --format rot13`,
	Args: cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		input := strings.Join(args, " ")

		if encodeFormat == "" {
			fmt.Fprintf(os.Stderr, "Error: --format is required for decoding\n")
			os.Exit(1)
		}

		opts := encode.Options{
			Format: encode.Format(encodeFormat),
			Shift:  encodeShift,
		}

		result, err := encode.Decode(input, opts)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		fmt.Println(result)
	},
}

var rotBruteCmd = &cobra.Command{
	Use:   "rot-brute [text]",
	Short: "Brute force all ROT-N values",
	Long: `Try all 25 ROT-N cipher variations on the input text.
Useful for decoding unknown Caesar cipher shifts.

Example:
  raxuiscli encode rot-brute "frperg"`,
	Args: cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		input := strings.Join(args, " ")

		results := encode.BruteForceROT(input)

		fmt.Println("ROT-N Brute Force Results:")
		fmt.Println(strings.Repeat("-", 50))
		for i := 1; i < 26; i++ {
			fmt.Printf("ROT%-2d: %s\n", i, results[i])
		}
	},
}

func init() {
	cmd.RootCmd.AddCommand(encodeCmd)
	encodeCmd.AddCommand(decodeCmd)
	encodeCmd.AddCommand(rotBruteCmd)

	// Flags for encode command
	encodeCmd.PersistentFlags().StringVarP(&encodeFormat, "format", "f", "", "Encoding format (base64|base32|hex|url|html|rot13|rotn)")
	encodeCmd.PersistentFlags().IntVarP(&encodeShift, "shift", "s", 13, "Shift value for ROT-N cipher")
}
