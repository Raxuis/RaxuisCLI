package hexdump

import (
	"fmt"
	"io"
	"os"
	"strings"
)

// ANSI color codes
const (
	ColorReset   = "\033[0m"
	ColorRed     = "\033[31m"
	ColorGreen   = "\033[32m"
	ColorYellow  = "\033[33m"
	ColorBlue    = "\033[34m"
	ColorMagenta = "\033[35m"
	ColorCyan    = "\033[36m"
	ColorGray    = "\033[90m"
)

// Options holds hexdump options
type Options struct {
	Offset   int64 // Starting offset
	Length   int64 // Number of bytes to read (0 = all)
	Colorize bool  // Enable colorization
	Columns  int   // Bytes per line (default 16)
}

// Dump performs a hexdump of a file
func Dump(path string, opts Options) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("error opening file: %w", err)
	}
	defer file.Close()

	// Seek to offset if specified
	if opts.Offset > 0 {
		_, err := file.Seek(opts.Offset, io.SeekStart)
		if err != nil {
			return fmt.Errorf("error seeking to offset: %w", err)
		}
	}

	// Set default columns
	if opts.Columns <= 0 {
		opts.Columns = 16
	}

	buffer := make([]byte, opts.Columns)
	currentOffset := opts.Offset
	bytesRead := int64(0)

	for {
		// Check if we've reached the length limit
		if opts.Length > 0 && bytesRead >= opts.Length {
			break
		}

		// Calculate how many bytes to read
		toRead := opts.Columns
		if opts.Length > 0 {
			remaining := opts.Length - bytesRead
			if int64(toRead) > remaining {
				toRead = int(remaining)
			}
		}

		n, err := file.Read(buffer[:toRead])
		if err != nil {
			if err == io.EOF {
				break
			}
			return fmt.Errorf("error reading file: %w", err)
		}

		if n == 0 {
			break
		}

		printLine(currentOffset, buffer[:n], opts)
		currentOffset += int64(n)
		bytesRead += int64(n)
	}

	return nil
}

// DumpBytes performs a hexdump of a byte slice
func DumpBytes(data []byte, opts Options) string {
	var sb strings.Builder

	// Set default columns
	if opts.Columns <= 0 {
		opts.Columns = 16
	}

	// Apply offset and length
	start := int(opts.Offset)
	if start > len(data) {
		return ""
	}

	end := len(data)
	if opts.Length > 0 && start+int(opts.Length) < end {
		end = start + int(opts.Length)
	}

	data = data[start:end]
	offset := opts.Offset

	for i := 0; i < len(data); i += opts.Columns {
		endIdx := i + opts.Columns
		if endIdx > len(data) {
			endIdx = len(data)
		}

		line := formatLine(offset, data[i:endIdx], opts)
		sb.WriteString(line)
		sb.WriteString("\n")

		offset += int64(opts.Columns)
	}

	return sb.String()
}

// printLine prints a single hexdump line
func printLine(offset int64, data []byte, opts Options) {
	fmt.Print(formatLine(offset, data, opts))
	fmt.Println()
}

// formatLine formats a single hexdump line
func formatLine(offset int64, data []byte, opts Options) string {
	var sb strings.Builder

	// Print offset
	if opts.Colorize {
		sb.WriteString(ColorCyan)
	}
	sb.WriteString(fmt.Sprintf("%08x  ", offset))
	if opts.Colorize {
		sb.WriteString(ColorReset)
	}

	// Print hex values
	for i := 0; i < opts.Columns; i++ {
		if i == opts.Columns/2 {
			sb.WriteString(" ")
		}

		if i < len(data) {
			b := data[i]
			if opts.Colorize {
				sb.WriteString(getByteColor(b))
			}
			sb.WriteString(fmt.Sprintf("%02x ", b))
			if opts.Colorize {
				sb.WriteString(ColorReset)
			}
		} else {
			sb.WriteString("   ")
		}
	}

	sb.WriteString(" |")

	// Print ASCII representation
	for i := 0; i < len(data); i++ {
		b := data[i]
		if opts.Colorize {
			sb.WriteString(getByteColor(b))
		}
		if b >= 32 && b < 127 {
			sb.WriteByte(b)
		} else {
			sb.WriteByte('.')
		}
		if opts.Colorize {
			sb.WriteString(ColorReset)
		}
	}

	// Pad ASCII section if needed
	for i := len(data); i < opts.Columns; i++ {
		sb.WriteByte(' ')
	}

	sb.WriteString("|")

	return sb.String()
}

// getByteColor returns the ANSI color code for a byte
func getByteColor(b byte) string {
	switch {
	case b == 0x00:
		return ColorGray // Null bytes
	case b >= 0x20 && b < 0x7F:
		return ColorGreen // Printable ASCII
	case b == 0x0A || b == 0x0D || b == 0x09:
		return ColorYellow // Whitespace (LF, CR, TAB)
	case b >= 0x80:
		return ColorMagenta // High bytes
	default:
		return ColorRed // Other non-printable
	}
}

// GetFileInfo returns basic file information for hexdump header
func GetFileInfo(path string) (int64, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	return info.Size(), nil
}
