package strings

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTempFile(t *testing.T, content []byte) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "sample.bin")
	if err := os.WriteFile(path, content, 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}
	return path
}

func TestExtractASCII(t *testing.T) {
	// Two printable runs separated by null bytes, one below minLength.
	content := []byte("hi\x00\x00\x00hello world\x00\x00this-one-long-enough")
	path := writeTempFile(t, content)

	results, err := Extract(path, Options{MinLength: 4, Encoding: EncodingASCII})
	if err != nil {
		t.Fatalf("Extract returned error: %v", err)
	}

	var found []string
	for _, r := range results {
		found = append(found, r.String)
	}

	wantContains := []string{"hello world", "this-one-long-enough"}
	for _, w := range wantContains {
		ok := false
		for _, f := range found {
			if f == w {
				ok = true
			}
		}
		if !ok {
			t.Errorf("Extract results %v missing expected string %q", found, w)
		}
	}
	for _, f := range found {
		if f == "hi" {
			t.Errorf("Extract should have excluded %q (shorter than MinLength=4)", f)
		}
	}
}

func TestExtractDefaultEncoding(t *testing.T) {
	path := writeTempFile(t, []byte("plain ascii text here"))
	results, err := Extract(path, Options{MinLength: 4})
	if err != nil {
		t.Fatalf("Extract returned error: %v", err)
	}
	if len(results) == 0 {
		t.Error("Extract with default (empty) Encoding should fall back to ASCII extraction")
	}
}

func TestExtractMissingFile(t *testing.T) {
	_, err := Extract("/nonexistent/path", Options{})
	if err == nil {
		t.Error("Extract on a missing file should return an error")
	}
}

func writeUTF16String(order binary.ByteOrder, s string) []byte {
	var buf bytes.Buffer
	for _, r := range s {
		binary.Write(&buf, order, uint16(r))
	}
	return buf.Bytes()
}

func TestExtractUTF16LE(t *testing.T) {
	content := writeUTF16String(binary.LittleEndian, "hello unicode")
	path := writeTempFile(t, content)

	results, err := Extract(path, Options{MinLength: 4, Encoding: EncodingUTF16LE})
	if err != nil {
		t.Fatalf("Extract returned error: %v", err)
	}
	if len(results) != 1 || results[0].String != "hello unicode" {
		t.Errorf("Extract(UTF16LE) = %+v, want a single result %q", results, "hello unicode")
	}
	if results[0].Encoding != EncodingUTF16LE {
		t.Errorf("Encoding = %q, want %q", results[0].Encoding, EncodingUTF16LE)
	}
}

func TestExtractUTF16BE(t *testing.T) {
	content := writeUTF16String(binary.BigEndian, "hello unicode")
	path := writeTempFile(t, content)

	results, err := Extract(path, Options{MinLength: 4, Encoding: EncodingUTF16BE})
	if err != nil {
		t.Fatalf("Extract returned error: %v", err)
	}
	if len(results) != 1 || results[0].String != "hello unicode" {
		t.Errorf("Extract(UTF16BE) = %+v, want a single result %q", results, "hello unicode")
	}
}

func TestExtractUnicodeAliasesUTF16LE(t *testing.T) {
	content := writeUTF16String(binary.LittleEndian, "alias test")
	path := writeTempFile(t, content)

	results, err := Extract(path, Options{MinLength: 4, Encoding: EncodingUnicode})
	if err != nil {
		t.Fatalf("Extract returned error: %v", err)
	}
	if len(results) != 1 || results[0].String != "alias test" {
		t.Errorf("Extract(EncodingUnicode) = %+v, want a single result %q", results, "alias test")
	}
}

func TestExtractAll(t *testing.T) {
	content := []byte("ascii-run-here")
	path := writeTempFile(t, content)

	results, err := Extract(path, Options{MinLength: 4, Encoding: EncodingAll})
	if err != nil {
		t.Fatalf("Extract returned error: %v", err)
	}
	if len(results) == 0 {
		t.Error("Extract(EncodingAll) should find the ASCII string")
	}
}

func TestStreamExtractFormats(t *testing.T) {
	content := []byte("streamed-content-here")
	path := writeTempFile(t, content)

	tests := []struct {
		name string
		opts Options
		want []string
	}{
		{"plain", Options{MinLength: 4}, []string{"streamed-content-here"}},
		{"offset", Options{MinLength: 4, ShowOffset: true}, []string{"00000000", "streamed-content-here"}},
		{"encoding", Options{MinLength: 4, ShowEncoding: true}, []string{"[ascii]", "streamed-content-here"}},
		{"both", Options{MinLength: 4, ShowOffset: true, ShowEncoding: true}, []string{"00000000", "[ascii]", "streamed-content-here"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := StreamExtract(path, tt.opts, &buf); err != nil {
				t.Fatalf("StreamExtract returned error: %v", err)
			}
			out := buf.String()
			for _, want := range tt.want {
				if !strings.Contains(out, want) {
					t.Errorf("StreamExtract(%s) output missing %q; got %q", tt.name, want, out)
				}
			}
		})
	}
}

func TestStreamExtractMissingFile(t *testing.T) {
	var buf bytes.Buffer
	err := StreamExtract("/nonexistent/path", Options{}, &buf)
	if err == nil {
		t.Error("StreamExtract on a missing file should return an error")
	}
}
