package cmd

import (
	"fmt"
	"os"
	"raxuiscli/internal/entropy"
	"strings"

	"github.com/spf13/cobra"
)

var entropyBlockSize int
var entropyNoColor bool

var entropyCmd = &cobra.Command{
	Use:   "entropy [file]",
	Short: "Calculate file entropy",
	Long: `Calculate Shannon entropy of a file to analyze its randomness.

Entropy is measured in bits per byte (0-8):
  0-1  - Very low (uniform or sparse data)
  1-3  - Low (plain text, structured data)
  3-5  - Medium (text with some binary)
  5-7  - High (binary data, compiled code)
  7-7.5 - Very high (compressed data)
  7.5-8 - Maximum (encrypted or random data)

Use --block-size to analyze entropy across different sections of the file.
This helps identify encrypted or compressed regions.

Examples:
  raxuiscli entropy document.txt
  raxuiscli entropy binary.exe
  raxuiscli entropy encrypted.bin --block-size 4096
  raxuiscli entropy archive.zip --no-color`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		path := args[0]

		opts := entropy.Options{
			BlockSize: entropyBlockSize,
			Visual:    true,
		}

		result, err := entropy.Calculate(path, opts)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		// Display results
		fmt.Printf("File: %s\n", path)
		fmt.Printf("Size: %d bytes\n", result.FileSize)
		fmt.Println(strings.Repeat("-", 60))

		// Global entropy with visualization
		bar := entropy.VisualizeEntropy(result.GlobalEntropy, 40)
		interpretation := entropy.InterpretEntropy(result.GlobalEntropy)

		if !entropyNoColor {
			color := entropy.GetEntropyColor(result.GlobalEntropy)
			fmt.Printf("Global Entropy: %s%.4f%s bits/byte\n", color, result.GlobalEntropy, entropy.ColorReset)
			fmt.Printf("Visualization:  %s%s%s\n", color, bar, entropy.ColorReset)
		} else {
			fmt.Printf("Global Entropy: %.4f bits/byte\n", result.GlobalEntropy)
			fmt.Printf("Visualization:  %s\n", bar)
		}
		fmt.Printf("Interpretation: %s\n", interpretation)

		// Block entropies if requested
		if entropyBlockSize > 0 && len(result.BlockEntropies) > 0 {
			fmt.Println()
			fmt.Printf("Block Analysis (block size: %d bytes):\n", entropyBlockSize)
			fmt.Println(strings.Repeat("-", 60))
			fmt.Println("Offset   │        Entropy Bar        │ Value")
			fmt.Println(strings.Repeat("-", 60))

			for _, block := range result.BlockEntropies {
				bar := entropy.VisualizeEntropy(block.Entropy, 30)

				if !entropyNoColor {
					color := entropy.GetEntropyColor(block.Entropy)
					fmt.Printf("%08x │%s%s%s│ %.4f\n",
						block.Offset, color, bar, entropy.ColorReset, block.Entropy)
				} else {
					fmt.Printf("%08x │%s│ %.4f\n", block.Offset, bar, block.Entropy)
				}
			}

			// Statistics
			fmt.Println(strings.Repeat("-", 60))
			var minE, maxE, sumE float64
			minE = 8.0
			for _, block := range result.BlockEntropies {
				if block.Entropy < minE {
					minE = block.Entropy
				}
				if block.Entropy > maxE {
					maxE = block.Entropy
				}
				sumE += block.Entropy
			}
			avgE := sumE / float64(len(result.BlockEntropies))

			fmt.Printf("Blocks: %d | Min: %.4f | Max: %.4f | Avg: %.4f\n",
				len(result.BlockEntropies), minE, maxE, avgE)
		}
	},
}

func init() {
	rootCmd.AddCommand(entropyCmd)

	entropyCmd.Flags().IntVarP(&entropyBlockSize, "block-size", "b", 0, "Block size for per-block analysis (0 = global only)")
	entropyCmd.Flags().BoolVar(&entropyNoColor, "no-color", false, "Disable colorized output")
}
