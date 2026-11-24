package tools

import (
	"fmt"

	"github.com/Raxuis/RaxuisCLI/cmd"
	"github.com/Raxuis/RaxuisCLI/internal/tools/hexdump"

	"github.com/Raxuis/RaxuisCLI/internal/shared/output"
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
	RunE: func(cmd *cobra.Command, args []string) error {
		hexdumpNoColor, _ = cmd.Flags().GetBool("no-color")
		path := args[0]
		if hexdumpOffset < 0 || hexdumpLength < 0 {
			return fmt.Errorf("offset and length must be nonnegative")
		}
		if hexdumpColumns <= 0 || hexdumpColumns > 4096 {
			return fmt.Errorf("columns must be between 1 and 4096")
		}

		// Get file info
		size, err := hexdump.GetFileInfo(path)
		if err != nil {
			return err
		}

		// Display file info
		fmt.Fprintf(output.Std, "File: %s\n", path)
		fmt.Fprintf(output.Std, "Size: %d bytes\n", size)
		if hexdumpOffset > 0 {
			fmt.Fprintf(output.Std, "Offset: %d (0x%x)\n", hexdumpOffset, hexdumpOffset)
		}
		if hexdumpLength > 0 {
			fmt.Fprintf(output.Std, "Length: %d bytes\n", hexdumpLength)
		}
		fmt.Fprintln(output.Std)

		opts := hexdump.Options{
			Offset:   hexdumpOffset,
			Length:   hexdumpLength,
			Colorize: !hexdumpNoColor,
			Columns:  hexdumpColumns,
		}

		if err := hexdump.Dump(path, opts); err != nil {
			return err
		}
		return nil
	},
}

func init() {
	cmd.RootCmd.AddCommand(hexdumpCmd)

	hexdumpCmd.Flags().Int64VarP(&hexdumpOffset, "offset", "o", 0, "Starting offset in bytes")
	hexdumpCmd.Flags().Int64VarP(&hexdumpLength, "length", "l", 0, "Number of bytes to display (0 = all)")
	hexdumpCmd.Flags().IntVarP(&hexdumpColumns, "columns", "c", 16, "Bytes per line")
}
