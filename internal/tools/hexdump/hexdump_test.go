package hexdump

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDumpBytesBasic(t *testing.T) {
	out := DumpBytes([]byte("Hello, World!"), Options{})
	if !strings.Contains(out, "48 65 6c") { // hex for "Hel"
		t.Errorf("DumpBytes output missing expected hex bytes; got:\n%s", out)
	}
	if !strings.Contains(out, "|Hello, World!") {
		t.Errorf("DumpBytes output missing ASCII column; got:\n%s", out)
	}
	if !strings.Contains(out, "00000000") {
		t.Errorf("DumpBytes output missing offset; got:\n%s", out)
	}
}

func TestDumpBytesEmpty(t *testing.T) {
	out := DumpBytes([]byte{}, Options{})
	if out != "" {
		t.Errorf("DumpBytes([]) = %q, want empty string", out)
	}
}

func TestDumpBytesOffsetBeyondData(t *testing.T) {
	out := DumpBytes([]byte("short"), Options{Offset: 100})
	if out != "" {
		t.Errorf("DumpBytes with offset beyond data length = %q, want empty string", out)
	}
}

func TestDumpBytesWithLength(t *testing.T) {
	out := DumpBytes([]byte("0123456789"), Options{Length: 4})
	if !strings.Contains(out, "30 31 32 33") { // hex for "0123"
		t.Errorf("DumpBytes with Length=4 should only include first 4 bytes; got:\n%s", out)
	}
	if strings.Contains(out, "34 35") { // hex for "45" - should be excluded
		t.Errorf("DumpBytes with Length=4 should not include byte 4+; got:\n%s", out)
	}
}

func TestDumpBytesMultipleLines(t *testing.T) {
	data := make([]byte, 20)
	for i := range data {
		data[i] = byte('a' + i%26)
	}
	out := DumpBytes(data, Options{Columns: 8})
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 3 { // 20 bytes / 8 columns = 3 lines (8, 8, 4)
		t.Errorf("expected 3 lines for 20 bytes at 8 columns, got %d:\n%s", len(lines), out)
	}
}

func TestDumpBytesColorize(t *testing.T) {
	out := DumpBytes([]byte{0x00, 0x41, 0xFF}, Options{Colorize: true})
	if !strings.Contains(out, ColorGray) {
		t.Errorf("Colorize=true should include ColorGray for null byte; got:\n%s", out)
	}
	if !strings.Contains(out, ColorGreen) {
		t.Errorf("Colorize=true should include ColorGreen for printable byte; got:\n%s", out)
	}
	if !strings.Contains(out, ColorMagenta) {
		t.Errorf("Colorize=true should include ColorMagenta for high byte; got:\n%s", out)
	}
}

func TestGetByteColorAllRanges(t *testing.T) {
	tests := []struct {
		b    byte
		want string
	}{
		{0x00, ColorGray},
		{0x41, ColorGreen},  // 'A' printable
		{0x0A, ColorYellow}, // LF
		{0x0D, ColorYellow}, // CR
		{0x09, ColorYellow}, // TAB
		{0x80, ColorMagenta},
		{0x01, ColorRed}, // other non-printable
	}

	for _, tt := range tests {
		if got := getByteColor(tt.b); got != tt.want {
			t.Errorf("getByteColor(%#02x) = %q, want %q", tt.b, got, tt.want)
		}
	}
}

func TestDumpFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sample.bin")
	if err := os.WriteFile(path, []byte("Hello, hexdump!"), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	err := Dump(path, Options{})
	if err != nil {
		t.Errorf("Dump returned error: %v", err)
	}
}

func TestDumpFileWithOffsetAndLength(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sample.bin")
	if err := os.WriteFile(path, []byte("0123456789ABCDEF"), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	err := Dump(path, Options{Offset: 4, Length: 4})
	if err != nil {
		t.Errorf("Dump with offset/length returned error: %v", err)
	}
}

func TestDumpMissingFile(t *testing.T) {
	err := Dump("/nonexistent/path/to/file.bin", Options{})
	if err == nil {
		t.Error("Dump on a missing file should return an error")
	}
}

func TestGetFileInfo(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sized.bin")
	content := []byte("exactly twenty bytes")
	if err := os.WriteFile(path, content, 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	size, err := GetFileInfo(path)
	if err != nil {
		t.Fatalf("GetFileInfo returned error: %v", err)
	}
	if size != int64(len(content)) {
		t.Errorf("GetFileInfo size = %d, want %d", size, len(content))
	}
}

func TestGetFileInfoMissingFile(t *testing.T) {
	_, err := GetFileInfo("/nonexistent/path/to/file.bin")
	if err == nil {
		t.Error("GetFileInfo on a missing file should return an error")
	}
}
