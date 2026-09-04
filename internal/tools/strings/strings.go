package strings

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"unicode/utf16"
)

// Encoding represents the string encoding type
type Encoding string

const (
	EncodingASCII   Encoding = "ascii"
	EncodingUnicode Encoding = "unicode"
	EncodingUTF16LE Encoding = "utf16le"
	EncodingUTF16BE Encoding = "utf16be"
	EncodingAll     Encoding = "all"
)

// Options holds strings extraction options
type Options struct {
	MinLength    int      // Minimum string length
	Encoding     Encoding // String encoding to look for
	ShowOffset   bool     // Show file offset
	ShowEncoding bool     // Show detected encoding
}

// StringResult holds an extracted string with metadata
type StringResult struct {
	Offset   int64
	String   string
	Encoding Encoding
}

// Extract extracts printable strings from a file
func Extract(path string, opts Options) ([]StringResult, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("error opening file: %w", err)
	}
	defer file.Close()

	var results []StringResult

	switch opts.Encoding {
	case EncodingASCII:
		results, err = extractASCII(file, opts.MinLength)
	case EncodingUnicode, EncodingUTF16LE:
		results, err = extractUTF16(file, opts.MinLength, binary.LittleEndian)
	case EncodingUTF16BE:
		results, err = extractUTF16(file, opts.MinLength, binary.BigEndian)
	case EncodingAll:
		// Extract both ASCII and Unicode
		asciiResults, err1 := extractASCII(file, opts.MinLength)
		if err1 != nil {
			return nil, err1
		}

		// Reset file position
		_, err = file.Seek(0, io.SeekStart)
		if err != nil {
			return nil, err
		}

		unicodeResults, err2 := extractUTF16(file, opts.MinLength, binary.LittleEndian)
		if err2 != nil {
			return nil, err2
		}

		results = append(asciiResults, unicodeResults...)
	default:
		results, err = extractASCII(file, opts.MinLength)
	}

	if err != nil {
		return nil, err
	}

	return results, nil
}

// extractASCII extracts ASCII printable strings
func extractASCII(file *os.File, minLength int) ([]StringResult, error) {
	var results []StringResult
	reader := bufio.NewReader(file)

	var currentString []byte
	var startOffset int64
	offset := int64(0)

	for {
		b, err := reader.ReadByte()
		if err != nil {
			if err == io.EOF {
				// Check if we have a pending string
				if len(currentString) >= minLength {
					results = append(results, StringResult{
						Offset:   startOffset,
						String:   string(currentString),
						Encoding: EncodingASCII,
					})
				}
				break
			}
			return nil, err
		}

		if isPrintableASCII(b) {
			if len(currentString) == 0 {
				startOffset = offset
			}
			currentString = append(currentString, b)
		} else {
			if len(currentString) >= minLength {
				results = append(results, StringResult{
					Offset:   startOffset,
					String:   string(currentString),
					Encoding: EncodingASCII,
				})
			}
			currentString = currentString[:0]
		}

		offset++
	}

	return results, nil
}

// extractUTF16 extracts UTF-16 encoded strings
func extractUTF16(file *os.File, minLength int, order binary.ByteOrder) ([]StringResult, error) {
	var results []StringResult
	reader := bufio.NewReader(file)

	var currentRunes []rune
	var startOffset int64
	offset := int64(0)

	encoding := EncodingUTF16LE
	if order == binary.BigEndian {
		encoding = EncodingUTF16BE
	}

	for {
		var codeUnit uint16
		err := binary.Read(reader, order, &codeUnit)
		if err != nil {
			if err == io.EOF {
				// Check if we have a pending string
				if len(currentRunes) >= minLength {
					results = append(results, StringResult{
						Offset:   startOffset,
						String:   string(currentRunes),
						Encoding: encoding,
					})
				}
				break
			}
			return nil, err
		}

		// Handle surrogate pairs for characters outside BMP
		var r rune
		if utf16.IsSurrogate(rune(codeUnit)) {
			var lowSurrogate uint16
			err := binary.Read(reader, order, &lowSurrogate)
			if err != nil {
				break
			}
			r = utf16.DecodeRune(rune(codeUnit), rune(lowSurrogate))
			offset += 2
		} else {
			r = rune(codeUnit)
		}

		if isPrintableRune(r) {
			if len(currentRunes) == 0 {
				startOffset = offset
			}
			currentRunes = append(currentRunes, r)
		} else {
			if len(currentRunes) >= minLength {
				results = append(results, StringResult{
					Offset:   startOffset,
					String:   string(currentRunes),
					Encoding: encoding,
				})
			}
			currentRunes = currentRunes[:0]
		}

		offset += 2
	}

	return results, nil
}

// isPrintableASCII checks if a byte is a printable ASCII character
func isPrintableASCII(b byte) bool {
	// Include standard printable ASCII (32-126) and tab (9)
	return (b >= 32 && b <= 126) || b == 9
}

// isPrintableRune checks if a rune is printable
func isPrintableRune(r rune) bool {
	// Basic Latin and common characters
	if r >= 32 && r <= 126 {
		return true
	}
	// Tab
	if r == 9 {
		return true
	}
	// Extended Latin and other common Unicode ranges
	if r >= 0x00A0 && r <= 0x00FF {
		return true // Latin-1 Supplement
	}
	if r >= 0x0100 && r <= 0x024F {
		return true // Latin Extended A/B
	}
	return false
}

// StreamExtract extracts strings and writes to a writer as they're found
func StreamExtract(path string, opts Options, w io.Writer) error {
	results, err := Extract(path, opts)
	if err != nil {
		return err
	}

	for _, result := range results {
		if opts.ShowOffset && opts.ShowEncoding {
			fmt.Fprintf(w, "%08x [%s] %s\n", result.Offset, result.Encoding, result.String)
		} else if opts.ShowOffset {
			fmt.Fprintf(w, "%08x  %s\n", result.Offset, result.String)
		} else if opts.ShowEncoding {
			fmt.Fprintf(w, "[%s] %s\n", result.Encoding, result.String)
		} else {
			fmt.Fprintln(w, result.String)
		}
	}

	return nil
}
