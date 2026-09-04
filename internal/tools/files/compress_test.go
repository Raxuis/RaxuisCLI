package files

import (
	"os"
	"path/filepath"
	"testing"
)

// chdirTemp switches the working directory to a fresh temp dir for the
// duration of the test and restores it afterward. Needed because
// Extract/extractZip/extractTar write output relative to the current
// working directory (there's no --output-dir option).
func chdirTemp(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	orig, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("failed to chdir into temp dir: %v", err)
	}
	t.Cleanup(func() { os.Chdir(orig) })
	return dir
}

func TestDetectFormat(t *testing.T) {
	tests := map[string]string{
		"archive.zip":     "zip",
		"archive.tar":     "tar",
		"archive.tar.gz":  "tar.gz",
		"archive.tgz":     "tar.gz",
		"archive.tar.bz2": "tar.bz2",
		"archive.tbz2":    "tar.bz2",
		"archive.tar.xz":  "tar.xz",
		"archive.txz":     "tar.xz",
		"archive.gz":      "gzip",
		"archive.bz2":     "bzip2",
		"archive.xz":      "xz",
		"archive.unknown": "",
		"ARCHIVE.ZIP":     "zip", // case-insensitive
	}
	for name, want := range tests {
		if got := detectFormat(name); got != want {
			t.Errorf("detectFormat(%q) = %q, want %q", name, got, want)
		}
	}
}

func TestCompressExtractZipRoundTrip(t *testing.T) {
	srcDir := t.TempDir()
	writeFile(t, srcDir, "a.txt", "content a")
	sub := filepath.Join(srcDir, "sub")
	os.Mkdir(sub, 0755)
	writeFile(t, sub, "b.txt", "content b")

	archivePath := filepath.Join(t.TempDir(), "out.zip")
	if err := Compress([]string{filepath.Join(srcDir, "a.txt"), sub}, CompressOptions{Format: "zip", Output: archivePath}); err != nil {
		t.Fatalf("Compress(zip) returned error: %v", err)
	}

	chdirTemp(t)
	if err := Extract(archivePath, ExtractOptions{Format: "zip", Overwrite: true}); err != nil {
		t.Fatalf("Extract(zip) returned error: %v", err)
	}

	got, err := os.ReadFile("a.txt")
	if err != nil {
		t.Fatalf("expected a.txt to be extracted: %v", err)
	}
	if string(got) != "content a" {
		t.Errorf("extracted a.txt content = %q, want %q", got, "content a")
	}
}

func TestCompressExtractTarPlainRoundTrip(t *testing.T) {
	srcDir := t.TempDir()
	filePath := writeFile(t, srcDir, "a.txt", "plain tar content")

	archivePath := filepath.Join(t.TempDir(), "out.tar")
	if err := Compress([]string{filePath}, CompressOptions{Format: "tar", Output: archivePath}); err != nil {
		t.Fatalf("Compress(tar) returned error: %v", err)
	}

	chdirTemp(t)
	if err := Extract(archivePath, ExtractOptions{Format: "tar", Overwrite: true}); err != nil {
		t.Fatalf("Extract(tar) returned error: %v", err)
	}

	got, err := os.ReadFile("a.txt")
	if err != nil {
		t.Fatalf("expected a.txt to be extracted: %v", err)
	}
	if string(got) != "plain tar content" {
		t.Errorf("extracted content = %q, want %q", got, "plain tar content")
	}
}

func TestCompressExtractGzipRoundTrip(t *testing.T) {
	srcDir := t.TempDir()
	filePath := writeFile(t, srcDir, "a.txt", "gzip content")

	archivePath := filepath.Join(t.TempDir(), "out.tar.gz")
	if err := Compress([]string{filePath}, CompressOptions{Format: "gz", Output: archivePath}); err != nil {
		t.Fatalf("Compress(gz) returned error: %v", err)
	}

	chdirTemp(t)
	if err := Extract(archivePath, ExtractOptions{Overwrite: true}); err != nil { // auto-detect from extension
		t.Fatalf("Extract(auto-detect gz) returned error: %v", err)
	}

	got, err := os.ReadFile("a.txt")
	if err != nil {
		t.Fatalf("expected a.txt to be extracted: %v", err)
	}
	if string(got) != "gzip content" {
		t.Errorf("extracted content = %q, want %q", got, "gzip content")
	}
}

func TestCompressExtractXzRoundTrip(t *testing.T) {
	srcDir := t.TempDir()
	filePath := writeFile(t, srcDir, "a.txt", "xz content")

	archivePath := filepath.Join(t.TempDir(), "out.tar.xz")
	if err := Compress([]string{filePath}, CompressOptions{Format: "xz", Output: archivePath}); err != nil {
		t.Fatalf("Compress(xz) returned error: %v", err)
	}

	chdirTemp(t)
	if err := Extract(archivePath, ExtractOptions{Format: "xz", Overwrite: true}); err != nil {
		t.Fatalf("Extract(xz) returned error: %v", err)
	}

	got, err := os.ReadFile("a.txt")
	if err != nil {
		t.Fatalf("expected a.txt to be extracted: %v", err)
	}
	if string(got) != "xz content" {
		t.Errorf("extracted content = %q, want %q", got, "xz content")
	}
}

func TestCompressStripComponents(t *testing.T) {
	srcDir := t.TempDir()
	sub := filepath.Join(srcDir, "sub")
	os.Mkdir(sub, 0755)
	writeFile(t, sub, "a.txt", "nested content")

	archivePath := filepath.Join(t.TempDir(), "out.tar")
	if err := Compress([]string{sub}, CompressOptions{Format: "tar", Output: archivePath}); err != nil {
		t.Fatalf("Compress(tar) returned error: %v", err)
	}

	chdirTemp(t)
	if err := Extract(archivePath, ExtractOptions{Format: "tar", StripComponents: 1, Overwrite: true}); err != nil {
		t.Fatalf("Extract(StripComponents: 1) returned error: %v", err)
	}

	if _, err := os.Stat("a.txt"); err != nil {
		t.Errorf("expected a.txt directly in the output dir after stripping 1 component: %v", err)
	}
}

func TestCompressUnsupportedFormat(t *testing.T) {
	dir := t.TempDir()
	filePath := writeFile(t, dir, "a.txt", "x")

	if err := Compress([]string{filePath}, CompressOptions{Format: "bogus", Output: filepath.Join(dir, "out.bogus")}); err == nil {
		t.Error("Compress with an unsupported format should return an error")
	}
}

func TestCompressMissingOutput(t *testing.T) {
	if err := Compress([]string{"somefile"}, CompressOptions{Format: "zip"}); err == nil {
		t.Error("Compress with no Output path should return an error")
	}
}

func TestCompressRefusesToOverwrite(t *testing.T) {
	dir := t.TempDir()
	filePath := writeFile(t, dir, "a.txt", "x")
	archivePath := writeFile(t, dir, "out.zip", "existing")

	if err := Compress([]string{filePath}, CompressOptions{Format: "zip", Output: archivePath}); err == nil {
		t.Error("Compress should refuse to overwrite an existing output file without Overwrite=true")
	}
}

func TestCompressMissingSourceFile(t *testing.T) {
	dir := t.TempDir()
	if err := Compress([]string{"/nonexistent/file"}, CompressOptions{Format: "zip", Output: filepath.Join(dir, "out.zip")}); err == nil {
		t.Error("Compress with a missing source file should return an error")
	}
}

func TestExtractUnsupportedFormat(t *testing.T) {
	dir := t.TempDir()
	archivePath := writeFile(t, dir, "archive.unknownext", "not a real archive")

	if err := Extract(archivePath, ExtractOptions{}); err == nil {
		t.Error("Extract with an undetectable/unsupported format should return an error")
	}
}

func TestExtractMissingArchive(t *testing.T) {
	if err := Extract("/nonexistent/archive.zip", ExtractOptions{Format: "zip"}); err == nil {
		t.Error("Extract on a missing archive should return an error")
	}
}

func TestExtractZipSkipsExistingFileWithoutOverwrite(t *testing.T) {
	srcDir := t.TempDir()
	filePath := writeFile(t, srcDir, "a.txt", "archive content")

	archivePath := filepath.Join(t.TempDir(), "out.zip")
	if err := Compress([]string{filePath}, CompressOptions{Format: "zip", Output: archivePath}); err != nil {
		t.Fatalf("Compress(zip) returned error: %v", err)
	}

	chdirTemp(t)
	os.WriteFile("a.txt", []byte("pre-existing content"), 0644)

	if err := Extract(archivePath, ExtractOptions{Format: "zip", Overwrite: false}); err != nil {
		t.Fatalf("Extract(Overwrite: false) returned error: %v", err)
	}

	got, _ := os.ReadFile("a.txt")
	if string(got) != "pre-existing content" {
		t.Errorf("existing file should not have been overwritten, got %q", got)
	}
}
