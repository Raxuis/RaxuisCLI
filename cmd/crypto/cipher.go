package crypto

import (
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Raxuis/RaxuisCLI/cmd"

	"github.com/spf13/cobra"

	"github.com/Raxuis/RaxuisCLI/internal/crypto/cipher"
	"github.com/Raxuis/RaxuisCLI/internal/shared/output"
)

var cipherCmd = &cobra.Command{
	Use:   "cipher",
	Short: "Classical cipher operations (XOR, Vigenere, frequency analysis)",
	Long: `Encrypt, decrypt, and crack classical ciphers.

Supports XOR, Vigenere, Caesar, and frequency analysis.`,
}

var cipherXORCmd = &cobra.Command{
	Use:   "xor [text]",
	Short: "XOR encrypt/decrypt with key",
	Long: `XOR encrypt or decrypt text with a given key.

Examples:
  raxuiscli cipher xor "hello" --key "secret"
  raxuiscli cipher xor "48656c6c6f" --key "key" --hex
  raxuiscli cipher xor -f encrypted.bin --key "password"`,
	Run: func(cmd *cobra.Command, args []string) {
		key, _ := cmd.Flags().GetString("key")
		hexInput, _ := cmd.Flags().GetBool("hex")
		hexKey, _ := cmd.Flags().GetBool("hex-key")
		file, _ := cmd.Flags().GetString("file")
		outputHex, _ := cmd.Flags().GetBool("output-hex")

		var data []byte
		var err error

		if file != "" {
			data, err = os.ReadFile(file)
			if err != nil {
				fmt.Printf("Error reading file: %v\n", err)
				return
			}
		} else if len(args) > 0 {
			if hexInput {
				data, err = hex.DecodeString(strings.ReplaceAll(args[0], " ", ""))
				if err != nil {
					fmt.Printf("Invalid hex input: %v\n", err)
					return
				}
			} else {
				data = []byte(args[0])
			}
		} else {
			fmt.Println("Please provide text or use -f for file input")
			return
		}

		var keyBytes []byte
		if hexKey {
			keyBytes, err = hex.DecodeString(strings.ReplaceAll(key, " ", ""))
			if err != nil {
				fmt.Printf("Invalid hex key: %v\n", err)
				return
			}
		} else {
			keyBytes = []byte(key)
		}

		if len(keyBytes) == 0 {
			fmt.Println("Please provide a key with --key")
			return
		}

		result := cipher.XOREncrypt(data, keyBytes)
		printable := cipher.IsPrintable(result)

		payload := map[string]any{
			"hex":       hex.EncodeToString(result),
			"printable": printable,
		}
		if printable {
			payload["text"] = string(result)
		}
		_ = output.Emit(payload, func(_ io.Writer) {
			fmt.Println("\n[XOR RESULT]")
			fmt.Println(strings.Repeat("=", 50))
			if outputHex {
				fmt.Printf("Hex: %s\n", hex.EncodeToString(result))
			}
			if printable {
				fmt.Printf("Text: %s\n", string(result))
			} else if !outputHex {
				fmt.Printf("Hex: %s\n", hex.EncodeToString(result))
				fmt.Println("(Result contains non-printable characters)")
			}
		})
	},
}

var cipherXORBruteCmd = &cobra.Command{
	Use:   "xor-brute [text]",
	Short: "Brute force XOR encryption",
	Long: `Attempt to brute force XOR encrypted data.

For single-byte keys, tries all 256 possibilities.
For multi-byte keys, uses frequency analysis.

Examples:
  raxuiscli cipher xor-brute "encrypted_text"
  raxuiscli cipher xor-brute "1b37373331" --hex
  raxuiscli cipher xor-brute -f encrypted.bin --max-key-len 8`,
	Run: func(cmd *cobra.Command, args []string) {
		hexInput, _ := cmd.Flags().GetBool("hex")
		file, _ := cmd.Flags().GetString("file")
		maxKeyLen, _ := cmd.Flags().GetInt("max-key-len")
		topResults, _ := cmd.Flags().GetInt("top")

		var data []byte
		var err error

		if file != "" {
			data, err = os.ReadFile(file)
			if err != nil {
				fmt.Printf("Error reading file: %v\n", err)
				return
			}
		} else if len(args) > 0 {
			if hexInput {
				data, err = hex.DecodeString(strings.ReplaceAll(args[0], " ", ""))
				if err != nil {
					fmt.Printf("Invalid hex input: %v\n", err)
					return
				}
			} else {
				data = []byte(args[0])
			}
		} else {
			fmt.Println("Please provide text or use -f for file input")
			return
		}

		if maxKeyLen == 1 {
			results := cipher.XORBruteForce(data)
			cipher.DisplayXORResults(results, topResults)
		} else {
			results := cipher.XORBruteForceMultiByte(data, maxKeyLen)
			cipher.DisplayXORResults(results, topResults)
		}
	},
}

var cipherVigenereCmd = &cobra.Command{
	Use:   "vigenere [text]",
	Short: "Vigenere cipher encrypt/decrypt",
	Long: `Encrypt or decrypt using Vigenere cipher.

Examples:
  raxuiscli cipher vigenere "hello world" --key "KEY"
  raxuiscli cipher vigenere "RIJVS UYVJN" --key "KEY" --decrypt`,
	Run: func(cmd *cobra.Command, args []string) {
		key, _ := cmd.Flags().GetString("key")
		decrypt, _ := cmd.Flags().GetBool("decrypt")

		if len(args) == 0 {
			fmt.Println("Please provide text to encrypt/decrypt")
			return
		}

		if key == "" {
			fmt.Println("Please provide a key with --key")
			return
		}

		var result string
		if decrypt {
			result = cipher.VigenereDecrypt(args[0], key)
		} else {
			result = cipher.VigenereEncrypt(args[0], key)
		}

		operation := "Encrypted"
		if decrypt {
			operation = "Decrypted"
		}

		_ = output.Emit(map[string]any{
			"operation": strings.ToLower(operation),
			"key":       key,
			"result":    result,
		}, func(_ io.Writer) {
			fmt.Printf("\n[VIGENERE %s]\n", strings.ToUpper(operation))
			fmt.Println(strings.Repeat("=", 50))
			fmt.Printf("Key: %s\n", key)
			fmt.Printf("Result: %s\n", result)
		})
	},
}

var cipherVigenereCrackCmd = &cobra.Command{
	Use:   "vigenere-crack [ciphertext]",
	Short: "Crack Vigenere cipher using Kasiski examination",
	Long: `Attempt to crack Vigenere cipher using frequency analysis.

Uses Kasiski examination to determine likely key lengths,
then frequency analysis to recover the key.

Examples:
  raxuiscli cipher vigenere-crack "LXFOPVEFRNHR..."
  raxuiscli cipher vigenere-crack -f encrypted.txt`,
	Run: func(cmd *cobra.Command, args []string) {
		file, _ := cmd.Flags().GetString("file")
		topResults, _ := cmd.Flags().GetInt("top")

		var text string

		if file != "" {
			data, err := os.ReadFile(file)
			if err != nil {
				fmt.Printf("Error reading file: %v\n", err)
				return
			}
			text = string(data)
		} else if len(args) > 0 {
			text = args[0]
		} else {
			fmt.Println("Please provide ciphertext or use -f for file input")
			return
		}

		results := cipher.VigenereCrack(text)
		cipher.DisplayVigenereResults(results, topResults)
	},
}

var cipherFreqCmd = &cobra.Command{
	Use:   "freq [text]",
	Short: "Frequency analysis of text",
	Long: `Perform frequency analysis on text.

Shows character frequencies compared to English averages.

Examples:
  raxuiscli cipher freq "encrypted text here"
  raxuiscli cipher freq -f ciphertext.txt`,
	Run: func(cmd *cobra.Command, args []string) {
		file, _ := cmd.Flags().GetString("file")

		var text string

		if file != "" {
			data, err := os.ReadFile(file)
			if err != nil {
				fmt.Printf("Error reading file: %v\n", err)
				return
			}
			text = string(data)
		} else if len(args) > 0 {
			text = args[0]
		} else {
			fmt.Println("Please provide text or use -f for file input")
			return
		}

		results := cipher.AnalyzeFrequency(text)
		cipher.DisplayFrequencyAnalysis(results)

		// Also try to detect cipher type
		cipherType := cipher.DetectCipherType(text)
		fmt.Printf("Cipher detection: %s\n", cipherType)
	},
}

var cipherCaesarCmd = &cobra.Command{
	Use:   "caesar [text]",
	Short: "Caesar cipher encrypt/decrypt/brute-force",
	Long: `Caesar cipher (shift cipher) operations.

Examples:
  raxuiscli cipher caesar "hello" --shift 3
  raxuiscli cipher caesar "khoor" --shift 3 --decrypt
  raxuiscli cipher caesar "khoor" --brute`,
	Run: func(cmd *cobra.Command, args []string) {
		shift, _ := cmd.Flags().GetInt("shift")
		decrypt, _ := cmd.Flags().GetBool("decrypt")
		brute, _ := cmd.Flags().GetBool("brute")
		topResults, _ := cmd.Flags().GetInt("top")

		if len(args) == 0 {
			fmt.Println("Please provide text")
			return
		}

		text := args[0]

		if brute {
			results := cipher.CaesarBruteForce(text)
			cipher.DisplayCaesarResults(results, topResults)
			return
		}

		var result string
		if decrypt {
			result = cipher.CaesarDecrypt(text, shift)
		} else {
			// Encrypt is same as decrypt with negative shift
			result = cipher.CaesarDecrypt(text, -shift)
		}

		operation := "Encrypted"
		if decrypt {
			operation = "Decrypted"
		}

		_ = output.Emit(map[string]any{
			"operation": strings.ToLower(operation),
			"shift":     shift,
			"result":    result,
		}, func(_ io.Writer) {
			fmt.Printf("\n[CAESAR %s]\n", strings.ToUpper(operation))
			fmt.Println(strings.Repeat("=", 50))
			fmt.Printf("Shift: %d\n", shift)
			fmt.Printf("Result: %s\n", result)
		})
	},
}

var cipherROT13Cmd = &cobra.Command{
	Use:   "rot13 [text]",
	Short: "ROT13 encode/decode",
	Long: `Apply ROT13 transformation (Caesar with shift 13).

ROT13 is self-inverting: applying it twice returns the original.

Examples:
  raxuiscli cipher rot13 "hello"
  raxuiscli cipher rot13 "uryyb"`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			fmt.Println("Please provide text")
			return
		}

		result := cipher.ROT13(args[0])

		_ = output.Emit(map[string]any{"result": result}, func(_ io.Writer) {
			fmt.Println("\n[ROT13]")
			fmt.Println(strings.Repeat("=", 50))
			fmt.Printf("Result: %s\n", result)
		})
	},
}

var cipherAtbashCmd = &cobra.Command{
	Use:   "atbash [text]",
	Short: "Atbash cipher (A=Z, B=Y, ...)",
	Long: `Apply Atbash cipher transformation.

Atbash is a substitution cipher where A=Z, B=Y, etc.
It is self-inverting.

Examples:
  raxuiscli cipher atbash "hello"
  raxuiscli cipher atbash "svool"`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			fmt.Println("Please provide text")
			return
		}

		result := cipher.AtbashDecrypt(args[0])

		_ = output.Emit(map[string]any{"result": result}, func(_ io.Writer) {
			fmt.Println("\n[ATBASH]")
			fmt.Println(strings.Repeat("=", 50))
			fmt.Printf("Result: %s\n", result)
		})
	},
}

var cipherDetectCmd = &cobra.Command{
	Use:   "detect [text]",
	Short: "Detect cipher type",
	Long: `Attempt to detect the type of cipher used.

Analyzes the text using various heuristics including:
- Frequency analysis
- Index of Coincidence
- Pattern detection

Examples:
  raxuiscli cipher detect "khoor zruog"
  raxuiscli cipher detect -f ciphertext.txt`,
	Run: func(cmd *cobra.Command, args []string) {
		file, _ := cmd.Flags().GetString("file")

		var text string

		if file != "" {
			data, err := os.ReadFile(file)
			if err != nil {
				fmt.Printf("Error reading file: %v\n", err)
				return
			}
			text = string(data)
		} else if len(args) > 0 {
			text = args[0]
		} else {
			fmt.Println("Please provide text or use -f for file input")
			return
		}

		cipherType := cipher.DetectCipherType(text)
		freq := cipher.AnalyzeFrequency(text)

		type charFreq struct {
			Char      string  `json:"char"`
			Frequency float64 `json:"frequency"`
		}
		top := make([]charFreq, 0, 5)
		for i := 0; i < min(5, len(freq)); i++ {
			top = append(top, charFreq{Char: string(freq[i].Char), Frequency: freq[i].Frequency})
		}

		_ = output.Emit(map[string]any{
			"detection": fmt.Sprintf("%v", cipherType),
			"top_chars": top,
		}, func(_ io.Writer) {
			fmt.Println("\n[CIPHER DETECTION]")
			fmt.Println(strings.Repeat("=", 50))
			fmt.Printf("Detection: %s\n", cipherType)
			if len(freq) > 0 {
				fmt.Printf("\nTop 5 characters: ")
				for i := 0; i < min(5, len(freq)); i++ {
					fmt.Printf("%c(%.1f%%) ", freq[i].Char, freq[i].Frequency)
				}
				fmt.Println()
			}
		})
	},
}

func init() {
	cmd.RootCmd.AddCommand(cipherCmd)

	// XOR command
	cipherCmd.AddCommand(cipherXORCmd)
	cipherXORCmd.Flags().StringP("key", "k", "", "XOR key")
	cipherXORCmd.Flags().Bool("hex", false, "Input is hex encoded")
	cipherXORCmd.Flags().Bool("hex-key", false, "Key is hex encoded")
	cipherXORCmd.Flags().StringP("file", "f", "", "Input file")
	cipherXORCmd.Flags().Bool("output-hex", false, "Output as hex")

	// XOR brute force command
	cipherCmd.AddCommand(cipherXORBruteCmd)
	cipherXORBruteCmd.Flags().Bool("hex", false, "Input is hex encoded")
	cipherXORBruteCmd.Flags().StringP("file", "f", "", "Input file")
	cipherXORBruteCmd.Flags().Int("max-key-len", 1, "Maximum key length to try")
	cipherXORBruteCmd.Flags().Int("top", 10, "Number of top results to show")

	// Vigenere command
	cipherCmd.AddCommand(cipherVigenereCmd)
	cipherVigenereCmd.Flags().StringP("key", "k", "", "Vigenere key")
	cipherVigenereCmd.Flags().BoolP("decrypt", "d", false, "Decrypt instead of encrypt")

	// Vigenere crack command
	cipherCmd.AddCommand(cipherVigenereCrackCmd)
	cipherVigenereCrackCmd.Flags().StringP("file", "f", "", "Input file")
	cipherVigenereCrackCmd.Flags().Int("top", 5, "Number of top results to show")

	// Frequency analysis command
	cipherCmd.AddCommand(cipherFreqCmd)
	cipherFreqCmd.Flags().StringP("file", "f", "", "Input file")

	// Caesar command
	cipherCmd.AddCommand(cipherCaesarCmd)
	cipherCaesarCmd.Flags().IntP("shift", "s", 3, "Shift value (default 3)")
	cipherCaesarCmd.Flags().BoolP("decrypt", "d", false, "Decrypt instead of encrypt")
	cipherCaesarCmd.Flags().BoolP("brute", "b", false, "Brute force all shifts")
	cipherCaesarCmd.Flags().Int("top", 10, "Number of top results for brute force")

	// ROT13 command
	cipherCmd.AddCommand(cipherROT13Cmd)

	// Atbash command
	cipherCmd.AddCommand(cipherAtbashCmd)

	// Detect command
	cipherCmd.AddCommand(cipherDetectCmd)
	cipherDetectCmd.Flags().StringP("file", "f", "", "Input file")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
