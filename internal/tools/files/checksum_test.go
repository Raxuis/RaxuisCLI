package files

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write %s: %v", path, err)
	}
	return path
}

func TestCalculateChecksumKnownVector(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "hello.txt", "hello")

	got, err := calculateChecksum(path, "md5")
	if err != nil {
		t.Fatalf("calculateChecksum returned error: %v", err)
	}
	want := "5d41402abc4b2a76b9719d911017c592"
	if got != want {
		t.Errorf("calculateChecksum(md5) = %q, want %q", got, want)
	}
}

func TestCalculateChecksumAllAlgorithms(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "sample.txt", "some content")

	for _, algo := range []string{"md5", "sha1", "sha256", "sha512", "blake2"} {
		if _, err := calculateChecksum(path, algo); err != nil {
			t.Errorf("calculateChecksum(%s) returned error: %v", algo, err)
		}
	}
}

func TestCalculateChecksumUnsupportedAlgorithm(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "sample.txt", "x")

	if _, err := calculateChecksum(path, "bogus"); err == nil {
		t.Error("calculateChecksum with an unsupported algorithm should return an error")
	}
}

func TestCalculateChecksumMissingFile(t *testing.T) {
	if _, err := calculateChecksum("/nonexistent/file", "md5"); err == nil {
		t.Error("calculateChecksum on a missing file should return an error")
	}
}

func TestDetectAlgorithm(t *testing.T) {
	tests := []struct {
		checksum string
		want     string
	}{
		{strings.Repeat("a", 32), "md5"},
		{strings.Repeat("a", 40), "sha1"},
		{strings.Repeat("a", 64), "sha256"},
		{strings.Repeat("a", 128), "sha512"},
		{strings.Repeat("a", 10), ""},
	}
	for _, tt := range tests {
		if got := detectAlgorithm(tt.checksum); got != tt.want {
			t.Errorf("detectAlgorithm(len=%d) = %q, want %q", len(tt.checksum), got, tt.want)
		}
	}
}

func TestChecksumSingleFile(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "a.txt", "content a")
	path := filepath.Join(dir, "a.txt")

	if err := Checksum([]string{path}, ChecksumOptions{Algorithm: "sha256"}); err != nil {
		t.Errorf("Checksum returned error: %v", err)
	}
}

func TestChecksumDirectoryWithoutRecursiveFails(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "a.txt", "content a")

	if err := Checksum([]string{dir}, ChecksumOptions{Algorithm: "sha256"}); err == nil {
		t.Error("Checksum on a directory without Recursive should return an error")
	}
}

func TestChecksumDirectoryRecursive(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "a.txt", "content a")
	sub := filepath.Join(dir, "sub")
	os.Mkdir(sub, 0755)
	writeFile(t, sub, "b.txt", "content b")

	if err := Checksum([]string{dir}, ChecksumOptions{Algorithm: "sha256", Recursive: true}); err != nil {
		t.Errorf("Checksum(Recursive: true) returned error: %v", err)
	}
}

func TestChecksumOutputFile(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "a.txt", "content a")
	outPath := filepath.Join(dir, "checksums.txt")

	if err := Checksum([]string{path}, ChecksumOptions{Algorithm: "sha256", Output: outPath}); err != nil {
		t.Fatalf("Checksum returned error: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("failed to read output checksum file: %v", err)
	}
	if !strings.Contains(string(data), "a.txt") {
		t.Errorf("checksum output file missing filename, got: %s", data)
	}
}

func TestChecksumMissingPath(t *testing.T) {
	if err := Checksum([]string{"/nonexistent/path"}, ChecksumOptions{Algorithm: "sha256"}); err == nil {
		t.Error("Checksum on a missing path should return an error")
	}
}

func TestVerifyChecksumsSuccess(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "verify-me.txt", "verify content")

	sum, err := calculateChecksum(path, "sha256")
	if err != nil {
		t.Fatalf("calculateChecksum returned error: %v", err)
	}

	manifestPath := filepath.Join(dir, "manifest.txt")
	manifest := "# comment line\n\n" + sum + "  " + path + "\n"
	if err := os.WriteFile(manifestPath, []byte(manifest), 0644); err != nil {
		t.Fatalf("failed to write manifest: %v", err)
	}

	if err := Checksum(nil, ChecksumOptions{Verify: manifestPath}); err != nil {
		t.Errorf("Checksum(Verify) with a correct manifest should succeed, got: %v", err)
	}
}

func TestVerifyChecksumsFailure(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "verify-me.txt", "verify content")

	manifestPath := filepath.Join(dir, "manifest.txt")
	wrongSum := strings.Repeat("0", 64)
	manifest := wrongSum + "  " + path + "\n"
	if err := os.WriteFile(manifestPath, []byte(manifest), 0644); err != nil {
		t.Fatalf("failed to write manifest: %v", err)
	}

	if err := Checksum(nil, ChecksumOptions{Verify: manifestPath}); err == nil {
		t.Error("Checksum(Verify) with a wrong checksum should return an error")
	}
}

func TestVerifyChecksumsMissingFile(t *testing.T) {
	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "manifest.txt")
	manifest := strings.Repeat("a", 64) + "  /nonexistent/file.txt\n"
	if err := os.WriteFile(manifestPath, []byte(manifest), 0644); err != nil {
		t.Fatalf("failed to write manifest: %v", err)
	}

	if err := Checksum(nil, ChecksumOptions{Verify: manifestPath}); err == nil {
		t.Error("Checksum(Verify) referencing a missing file should return an error")
	}
}

func TestVerifyChecksumsUnknownAlgorithmLength(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "x.txt", "x")
	manifestPath := filepath.Join(dir, "manifest.txt")
	manifest := "short  " + path + "\n"
	if err := os.WriteFile(manifestPath, []byte(manifest), 0644); err != nil {
		t.Fatalf("failed to write manifest: %v", err)
	}

	// Should not error out entirely - just report the line as failed.
	err := Checksum(nil, ChecksumOptions{Verify: manifestPath})
	if err == nil {
		t.Error("Checksum(Verify) with an undetectable algorithm should report failure")
	}
}

func TestVerifyChecksumsMissingManifest(t *testing.T) {
	if err := Checksum(nil, ChecksumOptions{Verify: "/nonexistent/manifest.txt"}); err == nil {
		t.Error("Checksum(Verify) with a missing manifest file should return an error")
	}
}
