package tools

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Raxuis/RaxuisCLI/cmd"
	"github.com/Raxuis/RaxuisCLI/internal/shared/output"
	"github.com/Raxuis/RaxuisCLI/internal/tools/entropy"

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
	Run: func(_ *cobra.Command, args []string) {
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

		hasBlocks := entropyBlockSize > 0 && len(result.BlockEntropies) > 0

		type blockOut struct {
			Offset  int64   `json:"offset"`
			Size    int     `json:"size"`
			Entropy float64 `json:"entropy"`
		}

		payload := map[string]any{
			"file":           path,
			"size":           result.FileSize,
			"global_entropy": result.GlobalEntropy,
			"interpretation": entropy.InterpretEntropy(result.GlobalEntropy),
		}

		if hasBlocks {
			blocks := make([]blockOut, 0, len(result.BlockEntropies))
			minE, maxE, sumE := 8.0, 0.0, 0.0
			for _, b := range result.BlockEntropies {
				blocks = append(blocks, blockOut{Offset: b.Offset, Size: b.Size, Entropy: b.Entropy})
				if b.Entropy < minE {
					minE = b.Entropy
				}
				if b.Entropy > maxE {
					maxE = b.Entropy
				}
				sumE += b.Entropy
			}
			payload["block_size"] = entropyBlockSize
			payload["blocks"] = blocks
			payload["block_stats"] = map[string]any{
				"count": len(blocks),
				"min":   minE,
				"max":   maxE,
				"avg":   sumE / float64(len(blocks)),
			}
		}

		_ = output.Emit(payload, func(w io.Writer) {
			fmt.Fprintf(w, "File: %s\n", path)
			fmt.Fprintf(w, "Size: %d bytes\n", result.FileSize)
			fmt.Fprintln(w, strings.Repeat("-", 60))

			bar := entropy.VisualizeEntropy(result.GlobalEntropy, 40)
			interpretation := entropy.InterpretEntropy(result.GlobalEntropy)

			if !entropyNoColor {
				color := entropy.GetEntropyColor(result.GlobalEntropy)
				fmt.Fprintf(w, "Global Entropy: %s%.4f%s bits/byte\n", color, result.GlobalEntropy, entropy.ColorReset)
				fmt.Fprintf(w, "Visualization:  %s%s%s\n", color, bar, entropy.ColorReset)
			} else {
				fmt.Fprintf(w, "Global Entropy: %.4f bits/byte\n", result.GlobalEntropy)
				fmt.Fprintf(w, "Visualization:  %s\n", bar)
			}
			fmt.Fprintf(w, "Interpretation: %s\n", interpretation)

			if !hasBlocks {
				return
			}

			fmt.Fprintln(w)
			fmt.Fprintf(w, "Block Analysis (block size: %d bytes):\n", entropyBlockSize)
			fmt.Fprintln(w, strings.Repeat("-", 60))
			fmt.Fprintln(w, "Offset   │        Entropy Bar        │ Value")
			fmt.Fprintln(w, strings.Repeat("-", 60))

			minE, maxE, sumE := 8.0, 0.0, 0.0
			for _, block := range result.BlockEntropies {
				bar := entropy.VisualizeEntropy(block.Entropy, 30)
				if !entropyNoColor {
					color := entropy.GetEntropyColor(block.Entropy)
					fmt.Fprintf(w, "%08x │%s%s%s│ %.4f\n", block.Offset, color, bar, entropy.ColorReset, block.Entropy)
				} else {
					fmt.Fprintf(w, "%08x │%s│ %.4f\n", block.Offset, bar, block.Entropy)
				}
				if block.Entropy < minE {
					minE = block.Entropy
				}
				if block.Entropy > maxE {
					maxE = block.Entropy
				}
				sumE += block.Entropy
			}

			fmt.Fprintln(w, strings.Repeat("-", 60))
			fmt.Fprintf(w, "Blocks: %d | Min: %.4f | Max: %.4f | Avg: %.4f\n",
				len(result.BlockEntropies), minE, maxE, sumE/float64(len(result.BlockEntropies)))
		})
	},
}

func init() {
	cmd.RootCmd.AddCommand(entropyCmd)

	entropyCmd.Flags().IntVarP(&entropyBlockSize, "block-size", "b", 0, "Block size for per-block analysis (0 = global only)")
	entropyCmd.Flags().BoolVar(&entropyNoColor, "no-color", false, "Disable colorized output")
}
