package encode

import (
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"html"
	"net/url"
	"strings"
)

// Format represents the encoding format
type Format string

const (
	FormatBase64 Format = "base64"
	FormatBase32 Format = "base32"
	FormatHex    Format = "hex"
	FormatURL    Format = "url"
	FormatHTML   Format = "html"
	FormatROT13  Format = "rot13"
	FormatROTN   Format = "rotn"
)

// Options holds encoding/decoding options
type Options struct {
	Format Format
	Shift  int // For ROT-N encoding
}

// Encode encodes the input string using the specified format
func Encode(input string, opts Options) (string, error) {
	switch opts.Format {
	case FormatBase64:
		return encodeBase64(input), nil
	case FormatBase32:
		return encodeBase32(input), nil
	case FormatHex:
		return encodeHex(input), nil
	case FormatURL:
		return encodeURL(input), nil
	case FormatHTML:
		return encodeHTML(input), nil
	case FormatROT13:
		return encodeROTN(input, 13), nil
	case FormatROTN:
		return encodeROTN(input, opts.Shift), nil
	default:
		return "", fmt.Errorf("unsupported encoding format: %s", opts.Format)
	}
}

// Decode decodes the input string using the specified format
func Decode(input string, opts Options) (string, error) {
	switch opts.Format {
	case FormatBase64:
		return decodeBase64(input)
	case FormatBase32:
		return decodeBase32(input)
	case FormatHex:
		return decodeHex(input)
	case FormatURL:
		return decodeURL(input)
	case FormatHTML:
		return decodeHTML(input), nil
	case FormatROT13:
		return encodeROTN(input, 13), nil // ROT13 is self-inverse
	case FormatROTN:
		return encodeROTN(input, 26-opts.Shift), nil // Reverse rotation
	default:
		return "", fmt.Errorf("unsupported decoding format: %s", opts.Format)
	}
}

// GetSupportedFormats returns a list of supported encoding formats
func GetSupportedFormats() []string {
	return []string{
		string(FormatBase64),
		string(FormatBase32),
		string(FormatHex),
		string(FormatURL),
		string(FormatHTML),
		string(FormatROT13),
		string(FormatROTN),
	}
}

// Base64 encoding/decoding
func encodeBase64(input string) string {
	return base64.StdEncoding.EncodeToString([]byte(input))
}

func decodeBase64(input string) (string, error) {
	// Try standard base64 first
	decoded, err := base64.StdEncoding.DecodeString(input)
	if err != nil {
		// Try URL-safe base64
		decoded, err = base64.URLEncoding.DecodeString(input)
		if err != nil {
			// Try raw standard (no padding)
			decoded, err = base64.RawStdEncoding.DecodeString(input)
			if err != nil {
				return "", fmt.Errorf("invalid base64 encoding: %w", err)
			}
		}
	}
	return string(decoded), nil
}

// Base32 encoding/decoding
func encodeBase32(input string) string {
	return base32.StdEncoding.EncodeToString([]byte(input))
}

func decodeBase32(input string) (string, error) {
	// Normalize input (uppercase, handle padding)
	input = strings.ToUpper(strings.TrimSpace(input))
	decoded, err := base32.StdEncoding.DecodeString(input)
	if err != nil {
		// Try without padding
		decoded, err = base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(input)
		if err != nil {
			return "", fmt.Errorf("invalid base32 encoding: %w", err)
		}
	}
	return string(decoded), nil
}

// Hex encoding/decoding
func encodeHex(input string) string {
	return hex.EncodeToString([]byte(input))
}

func decodeHex(input string) (string, error) {
	// Remove common hex prefixes and spaces
	input = strings.TrimPrefix(input, "0x")
	input = strings.TrimPrefix(input, "0X")
	input = strings.ReplaceAll(input, " ", "")
	input = strings.ReplaceAll(input, ":", "")

	decoded, err := hex.DecodeString(input)
	if err != nil {
		return "", fmt.Errorf("invalid hex encoding: %w", err)
	}
	return string(decoded), nil
}

// URL encoding/decoding
func encodeURL(input string) string {
	return url.QueryEscape(input)
}

func decodeURL(input string) (string, error) {
	decoded, err := url.QueryUnescape(input)
	if err != nil {
		return "", fmt.Errorf("invalid URL encoding: %w", err)
	}
	return decoded, nil
}

// HTML encoding/decoding
func encodeHTML(input string) string {
	return html.EscapeString(input)
}

func decodeHTML(input string) string {
	return html.UnescapeString(input)
}

// ROT-N encoding (Caesar cipher)
func encodeROTN(input string, shift int) string {
	// Normalize shift to 0-25 range
	shift = ((shift % 26) + 26) % 26

	result := make([]rune, len(input))
	for i, r := range input {
		if r >= 'a' && r <= 'z' {
			result[i] = 'a' + (r-'a'+rune(shift))%26
		} else if r >= 'A' && r <= 'Z' {
			result[i] = 'A' + (r-'A'+rune(shift))%26
		} else {
			result[i] = r
		}
	}
	return string(result)
}

// EncodeAll encodes with all supported formats and returns results
func EncodeAll(input string) map[string]string {
	results := make(map[string]string)

	results["base64"] = encodeBase64(input)
	results["base32"] = encodeBase32(input)
	results["hex"] = encodeHex(input)
	results["url"] = encodeURL(input)
	results["html"] = encodeHTML(input)
	results["rot13"] = encodeROTN(input, 13)

	return results
}

// BruteForceROT tries all ROT-N values and returns results
func BruteForceROT(input string) map[int]string {
	results := make(map[int]string)
	for i := 1; i < 26; i++ {
		results[i] = encodeROTN(input, i)
	}
	return results
}
