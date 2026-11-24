package tools

import (
	"fmt"
	"io"

	"sort"
	"strings"

	"github.com/Raxuis/RaxuisCLI/cmd"
	"github.com/Raxuis/RaxuisCLI/internal/shared/output"
	"github.com/Raxuis/RaxuisCLI/internal/tools/metadata"

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
	RunE: func(cmd *cobra.Command, args []string) error {
		path := args[0]

		meta, err := metadata.Extract(path)
		if err != nil {
			return err
		}

		payload := map[string]any{
			"file":       meta.FileName,
			"type":       string(meta.FileType),
			"size":       meta.FileSize,
			"properties": meta.Properties,
		}
		if len(meta.ExifData) > 0 {
			payload["exif"] = meta.ExifData
		}
		if len(meta.Errors) > 0 {
			payload["warnings"] = meta.Errors
		}

		return output.Emit(payload, func(w io.Writer) {
			fmt.Fprintf(w, "File: %s\n", meta.FileName)
			fmt.Fprintf(w, "Type: %s\n", meta.FileType)
			fmt.Fprintf(w, "Size: %d bytes\n", meta.FileSize)
			fmt.Fprintln(w, strings.Repeat("-", 60))
			fmt.Fprintln(w, "Properties:")

			keys := make([]string, 0, len(meta.Properties))
			for k := range meta.Properties {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, key := range keys {
				value := meta.Properties[key]
				if len(value) > 100 {
					value = value[:100] + "..."
				}
				fmt.Fprintf(w, "  %-20s: %s\n", key, value)
			}

			if len(meta.ExifData) > 0 {
				fmt.Fprintln(w)
				fmt.Fprintln(w, "EXIF Data:")
				keys := make([]string, 0, len(meta.ExifData))
				for k := range meta.ExifData {
					keys = append(keys, k)
				}
				sort.Strings(keys)
				for _, key := range keys {
					fmt.Fprintf(w, "  %-20s: %s\n", key, meta.ExifData[key])
				}
			}

			if len(meta.Errors) > 0 {
				fmt.Fprintln(w)
				fmt.Fprintln(w, "Warnings:")
				for _, err := range meta.Errors {
					fmt.Fprintf(w, "  - %s\n", err)
				}
			}
		})

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
	RunE: func(cmd *cobra.Command, args []string) error {
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

		fmt.Fprintf(output.Std, "Stripping metadata from: %s\n", inputPath)
		fmt.Fprintf(output.Std, "Output: %s\n", metadataStripOutputPath)

		err := metadata.Strip(inputPath, metadataStripOutputPath)
		if err != nil {
			return err
		}

		fmt.Fprintln(output.Std)
		fmt.Fprintln(output.Std, "Note: Basic metadata stripping applied.")
		fmt.Fprintln(output.Std, "For complete metadata removal, consider using specialized tools like exiftool or mat2.")
		fmt.Fprintln(output.Std)
		fmt.Fprintf(output.Std, "Stripped file saved to: %s\n", metadataStripOutputPath)
		return nil
	},
}

func init() {
	cmd.RootCmd.AddCommand(metadataCmd)
	metadataCmd.AddCommand(metadataStripCmd)

	metadataStripCmd.Flags().StringVarP(&metadataStripOutputPath, "out", "o", "", "Output file path")
}
