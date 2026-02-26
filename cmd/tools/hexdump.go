package cmd

import (
	"fmt"
	"os"
	"raxuiscli/internal/tools/hexdump"

	"github.com/spf13/cobra"
)

var hexdumpOffset int64
var hexdumpLength int64
var hexdumpNoColor bool
var hexdumpColumns int

var hexdumpCmd = &cobra.Command{
	Use:   "hexdump [file]",
	Short: "Display file contents in hex and ASCII",
	Long: `Display file contents in hexadecimal format with ASCII representation.
Similar to the Unix xxd command with colorization support.

Color legend (when enabled):
  Gray    - Null bytes (0x00)
  Green   - Printable ASCII (0x20-0x7E)
  Yellow  - Whitespace (TAB, LF, CR)
  Magenta - High bytes (0x80+)
  Red     - Other non-printable

Examples:
  raxuiscli hexdump /bin/ls
  raxuiscli hexdump /bin/ls --length 256
  raxuiscli hexdump /bin/ls --offset 1024 --length 512
  raxuiscli hexdump file.bin --no-color
  raxuiscli hexdump file.bin --columns 32`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		path := args[0]

		// Get file info
		size, err := hexdump.GetFileInfo(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		// Display file info
		fmt.Printf("File: %s\n", path)
		fmt.Printf("Size: %d bytes\n", size)
		if hexdumpOffset > 0 {
			fmt.Printf("Offset: %d (0x%x)\n", hexdumpOffset, hexdumpOffset)
		}
		if hexdumpLength > 0 {
			fmt.Printf("Length: %d bytes\n", hexdumpLength)
		}
		fmt.Println()

		opts := hexdump.Options{
			Offset:   hexdumpOffset,
			Length:   hexdumpLength,
			Colorize: !hexdumpNoColor,
			Columns:  hexdumpColumns,
		}

		if err := hexdump.Dump(path, opts); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	},
}

func init() {
	rootCmd.AddCommand(hexdumpCmd)

	hexdumpCmd.Flags().Int64VarP(&hexdumpOffset, "offset", "o", 0, "Starting offset in bytes")
	hexdumpCmd.Flags().Int64VarP(&hexdumpLength, "length", "l", 0, "Number of bytes to display (0 = all)")
	hexdumpCmd.Flags().BoolVar(&hexdumpNoColor, "no-color", false, "Disable colorized output")
	hexdumpCmd.Flags().IntVarP(&hexdumpColumns, "columns", "c", 16, "Bytes per line")
}
