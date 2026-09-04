package tools

import (
	"fmt"
	"os"
	"raxuiscli/cmd"
	"raxuiscli/internal/tools/metadata"
	"sort"
	"strings"

	"github.com/spf13/cobra"
)

var metadataCmd = &cobra.Command{
	Use:   "metadata [file]",
	Short: "Extract file metadata",
	Long: `Extract metadata from various file types.

Supported file types:
  Images: JPEG (EXIF), PNG
  Documents: PDF
  Office: DOCX, XLSX, PPTX

Examples:
  raxuiscli metadata photo.jpg
  raxuiscli metadata document.pdf
  raxuiscli metadata report.docx`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		path := args[0]

		meta, err := metadata.Extract(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		// Display results
		fmt.Printf("File: %s\n", meta.FileName)
		fmt.Printf("Type: %s\n", meta.FileType)
		fmt.Printf("Size: %d bytes\n", meta.FileSize)
		fmt.Println(strings.Repeat("-", 60))

		// Display properties in sorted order
		fmt.Println("Properties:")

		// Sort keys for consistent output
		keys := make([]string, 0, len(meta.Properties))
		for k := range meta.Properties {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		for _, key := range keys {
			value := meta.Properties[key]
			// Truncate long values
			if len(value) > 100 {
				value = value[:100] + "..."
			}
			fmt.Printf("  %-20s: %s\n", key, value)
		}

		// Display EXIF data if present
		if len(meta.ExifData) > 0 {
			fmt.Println()
			fmt.Println("EXIF Data:")

			keys := make([]string, 0, len(meta.ExifData))
			for k := range meta.ExifData {
				keys = append(keys, k)
			}
			sort.Strings(keys)

			for _, key := range keys {
				value := meta.ExifData[key]
				fmt.Printf("  %-20s: %s\n", key, value)
			}
		}

		// Display errors if any
		if len(meta.Errors) > 0 {
			fmt.Println()
			fmt.Println("Warnings:")
			for _, err := range meta.Errors {
				fmt.Printf("  - %s\n", err)
			}
		}
	},
}

var metadataStripOutputPath string

var metadataStripCmd = &cobra.Command{
	Use:   "strip [file]",
	Short: "Strip metadata from a file",
	Long: `Remove metadata from a file and save a clean copy.

Note: This creates a new file without metadata. The original file is not modified.

Examples:
  raxuiscli metadata strip photo.jpg --out photo_clean.jpg
  raxuiscli metadata strip document.pdf --out document_clean.pdf`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		inputPath := args[0]

		if metadataStripOutputPath == "" {
			// Generate default output path
			ext := ""
			base := inputPath
			if idx := strings.LastIndex(inputPath, "."); idx != -1 {
				ext = inputPath[idx:]
				base = inputPath[:idx]
			}
			metadataStripOutputPath = base + "_stripped" + ext
		}

		fmt.Printf("Stripping metadata from: %s\n", inputPath)
		fmt.Printf("Output: %s\n", metadataStripOutputPath)

		err := metadata.Strip(inputPath, metadataStripOutputPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		fmt.Println()
		fmt.Println("Note: Basic metadata stripping applied.")
		fmt.Println("For complete metadata removal, consider using specialized tools like exiftool or mat2.")
		fmt.Println()
		fmt.Printf("Stripped file saved to: %s\n", metadataStripOutputPath)
	},
}

func init() {
	cmd.RootCmd.AddCommand(metadataCmd)
	metadataCmd.AddCommand(metadataStripCmd)

	metadataStripCmd.Flags().StringVarP(&metadataStripOutputPath, "out", "o", "", "Output file path")
}
