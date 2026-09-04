package entropy

import (
	"fmt"
	"io"
	"math"
	"os"
	"strings"
)

// Options holds entropy calculation options
type Options struct {
	BlockSize int  // Block size for per-block entropy (0 = global only)
	Visual    bool // Show ASCII visualization
}

// Result holds entropy calculation results
type Result struct {
	GlobalEntropy  float64
	FileSize       int64
	BlockEntropies []BlockResult
}

// BlockResult holds entropy for a single block
type BlockResult struct {
	Offset  int64
	Size    int
	Entropy float64
}

// Calculate computes the entropy of a file
func Calculate(path string, opts Options) (*Result, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("error opening file: %w", err)
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("error getting file info: %w", err)
	}

	result := &Result{
		FileSize: info.Size(),
	}

	// Calculate global entropy
	globalEntropy, err := calculateEntropy(file)
	if err != nil {
		return nil, err
	}
	result.GlobalEntropy = globalEntropy

	// Calculate per-block entropy if block size is specified
	if opts.BlockSize > 0 {
		_, err = file.Seek(0, io.SeekStart)
		if err != nil {
			return nil, err
		}

		blockEntropies, err := calculateBlockEntropies(file, opts.BlockSize)
		if err != nil {
			return nil, err
		}
		result.BlockEntropies = blockEntropies
	}

	return result, nil
}

// calculateEntropy computes Shannon entropy of data
func calculateEntropy(r io.Reader) (float64, error) {
	// Count byte frequencies
	freq := make([]int, 256)
	total := 0

	buf := make([]byte, 32*1024) // 32KB buffer
	for {
		n, err := r.Read(buf)
		if err != nil && err != io.EOF {
			return 0, err
		}
		if n == 0 {
			break
		}

		for i := 0; i < n; i++ {
			freq[buf[i]]++
			total++
		}

		if err == io.EOF {
			break
		}
	}

	if total == 0 {
		return 0, nil
	}

	// Calculate Shannon entropy
	entropy := 0.0
	for _, count := range freq {
		if count > 0 {
			p := float64(count) / float64(total)
			entropy -= p * math.Log2(p)
		}
	}

	return entropy, nil
}

// calculateBlockEntropies calculates entropy for each block
func calculateBlockEntropies(file *os.File, blockSize int) ([]BlockResult, error) {
	var results []BlockResult
	offset := int64(0)

	buf := make([]byte, blockSize)

	for {
		n, err := file.Read(buf)
		if err != nil && err != io.EOF {
			return nil, err
		}
		if n == 0 {
			break
		}

		// Calculate entropy for this block
		entropy := calculateByteSliceEntropy(buf[:n])

		results = append(results, BlockResult{
			Offset:  offset,
			Size:    n,
			Entropy: entropy,
		})

		offset += int64(n)

		if err == io.EOF {
			break
		}
	}

	return results, nil
}

// calculateByteSliceEntropy computes entropy of a byte slice
func calculateByteSliceEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}

	// Count byte frequencies
	freq := make([]int, 256)
	for _, b := range data {
		freq[b]++
	}

	// Calculate Shannon entropy
	entropy := 0.0
	total := float64(len(data))
	for _, count := range freq {
		if count > 0 {
			p := float64(count) / total
			entropy -= p * math.Log2(p)
		}
	}

	return entropy
}

// InterpretEntropy provides a human-readable interpretation of entropy
func InterpretEntropy(entropy float64) string {
	switch {
	case entropy < 1.0:
		return "Very low (likely uniform or sparse data)"
	case entropy < 3.0:
		return "Low (plain text, structured data)"
	case entropy < 5.0:
		return "Medium (text with some binary)"
	case entropy < 7.0:
		return "High (binary data, compiled code)"
	case entropy < 7.5:
		return "Very high (compressed data)"
	default:
		return "Maximum (encrypted or random data)"
	}
}

// VisualizeEntropy creates an ASCII bar chart visualization
func VisualizeEntropy(entropy float64, width int) string {
	// Entropy ranges from 0 to 8 (log2(256))
	maxEntropy := 8.0
	normalized := entropy / maxEntropy
	filled := int(normalized * float64(width))

	bar := strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
	return bar
}

// VisualizeBlockEntropies creates an ASCII visualization of block entropies
func VisualizeBlockEntropies(blocks []BlockResult, width int) string {
	var sb strings.Builder

	for _, block := range blocks {
		bar := VisualizeEntropy(block.Entropy, width)
		sb.WriteString(fmt.Sprintf("%08x │%s│ %.4f\n", block.Offset, bar, block.Entropy))
	}

	return sb.String()
}

// GetEntropyColor returns ANSI color based on entropy level
func GetEntropyColor(entropy float64) string {
	switch {
	case entropy < 3.0:
		return "\033[32m" // Green - low entropy
	case entropy < 5.0:
		return "\033[33m" // Yellow - medium
	case entropy < 7.0:
		return "\033[35m" // Magenta - high
	default:
		return "\033[31m" // Red - very high
	}
}

// ColorReset is the ANSI reset code
const ColorReset = "\033[0m"
