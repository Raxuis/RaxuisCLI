package entropy

import (
	"math"
	"os"
	"path/filepath"
	"testing"
)

func TestCalculateByteSliceEntropyUniformByte(t *testing.T) {
	data := []byte{0x41, 0x41, 0x41, 0x41}
	got := calculateByteSliceEntropy(data)
	if got != 0 {
		t.Errorf("entropy of uniform byte data = %f, want 0", got)
	}
}

func TestCalculateByteSliceEntropyMaximal(t *testing.T) {
	// 256 distinct bytes, each occurring once => maximum entropy of 8 bits
	data := make([]byte, 256)
	for i := range data {
		data[i] = byte(i)
	}
	got := calculateByteSliceEntropy(data)
	if math.Abs(got-8.0) > 1e-9 {
		t.Errorf("entropy of fully uniform 256-byte alphabet = %f, want 8.0", got)
	}
}

func TestCalculateByteSliceEntropyTwoSymbols(t *testing.T) {
	// Equal split between two byte values => entropy of exactly 1 bit
	data := []byte{0x00, 0x00, 0x01, 0x01}
	got := calculateByteSliceEntropy(data)
	if math.Abs(got-1.0) > 1e-9 {
		t.Errorf("entropy of 50/50 two-symbol data = %f, want 1.0", got)
	}
}

func TestCalculateByteSliceEntropyEmpty(t *testing.T) {
	got := calculateByteSliceEntropy([]byte{})
	if got != 0 {
		t.Errorf("entropy of empty data = %f, want 0", got)
	}
}

func TestCalculateOnFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "uniform.bin")

	if err := os.WriteFile(path, []byte("aaaaaaaaaa"), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	result, err := Calculate(path, Options{})
	if err != nil {
		t.Fatalf("Calculate returned error: %v", err)
	}

	if result.GlobalEntropy != 0 {
		t.Errorf("GlobalEntropy for uniform file = %f, want 0", result.GlobalEntropy)
	}
	if result.FileSize != 10 {
		t.Errorf("FileSize = %d, want 10", result.FileSize)
	}
}

func TestCalculateMissingFile(t *testing.T) {
	_, err := Calculate("/nonexistent/path", Options{})
	if err == nil {
		t.Error("Calculate on missing file should return an error")
	}
}

func TestInterpretEntropy(t *testing.T) {
	tests := []struct {
		entropy float64
		want    string
	}{
		{0.5, "Very low (likely uniform or sparse data)"},
		{2.0, "Low (plain text, structured data)"},
		{4.0, "Medium (text with some binary)"},
		{6.0, "High (binary data, compiled code)"},
		{7.2, "Very high (compressed data)"},
		{7.9, "Maximum (encrypted or random data)"},
	}

	for _, tt := range tests {
		if got := InterpretEntropy(tt.entropy); got != tt.want {
			t.Errorf("InterpretEntropy(%f) = %q, want %q", tt.entropy, got, tt.want)
		}
	}
}

func TestVisualizeEntropyWidth(t *testing.T) {
	bar := VisualizeEntropy(4.0, 10)
	// runes in the bar (filled + empty blocks) should equal the requested width
	runeCount := 0
	for range bar {
		runeCount++
	}
	if runeCount != 10 {
		t.Errorf("VisualizeEntropy bar rune count = %d, want 10", runeCount)
	}
}

func TestVisualizeEntropyFullyFilled(t *testing.T) {
	bar := VisualizeEntropy(8.0, 10)
	want := "██████████"
	if bar != want {
		t.Errorf("VisualizeEntropy(8.0, 10) = %q, want %q", bar, want)
	}
}
