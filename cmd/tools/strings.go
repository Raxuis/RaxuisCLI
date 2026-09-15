package tools

import (
	"fmt"
	"os"

	"github.com/Raxuis/RaxuisCLI/cmd"
	"github.com/Raxuis/RaxuisCLI/internal/tools/strings"

	"github.com/spf13/cobra"
)

var stringsMinLength int
var stringsEncoding string
var stringsShowOffset bool
var stringsShowEncoding bool

var stringsCmd = &cobra.Command{
	Use:   "strings [file]",
	Short: "Extract printable strings from files",
	Long: `Extract printable strings from binary files.
Similar to the Unix strings command with Unicode support.

Supported encodings:
  ascii   - ASCII printable characters (default)
  unicode - UTF-16 Little Endian strings
  utf16le - UTF-16 Little Endian (same as unicode)
  utf16be - UTF-16 Big Endian
  all     - Both ASCII and Unicode

Examples:
  raxuiscli strings /bin/ls
  raxuiscli strings /bin/ls --min 8
  raxuiscli strings binary.exe --encoding unicode
  raxuiscli strings file.bin --offset
  raxuiscli strings file.bin --encoding all --show-encoding`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		path := args[0]

		opts := strings.Options{
			MinLength:    stringsMinLength,
			Encoding:     strings.Encoding(stringsEncoding),
			ShowOffset:   stringsShowOffset,
			ShowEncoding: stringsShowEncoding,
		}

		if err := strings.StreamExtract(path, opts, os.Stdout); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	},
}

func init() {
	cmd.RootCmd.AddCommand(stringsCmd)

	stringsCmd.Flags().IntVarP(&stringsMinLength, "min", "n", 4, "Minimum string length")
	stringsCmd.Flags().StringVarP(&stringsEncoding, "encoding", "e", "ascii", "String encoding (ascii|unicode|utf16le|utf16be|all)")
	stringsCmd.Flags().BoolVarP(&stringsShowOffset, "offset", "o", false, "Show file offset for each string")
	stringsCmd.Flags().BoolVar(&stringsShowEncoding, "show-encoding", false, "Show detected encoding for each string")
}
