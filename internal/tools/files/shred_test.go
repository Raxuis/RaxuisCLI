package files

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func withStdin(t *testing.T, input string) {
	t.Helper()
	orig := os.Stdin
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}
	if _, err := w.WriteString(input); err != nil {
		t.Fatalf("failed to write stdin input: %v", err)
	}
	w.Close()
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = orig })
}

func captureShredStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	fn()
	w.Close()
	os.Stdout = orig
	data, _ := io.ReadAll(r)
	return string(data)
}

func TestShredFileForcedRemovesFile(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "secret.txt", "sensitive data")

	if err := Shred([]string{path}, ShredOptions{Passes: 1, Force: true}); err != nil {
		t.Fatalf("Shred returned error: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("shredded file should no longer exist")
	}
}

func TestShredFileRandomMultiPass(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "secret.txt", "sensitive data")

	if err := Shred([]string{path}, ShredOptions{Passes: 3, Random: true, Force: true}); err != nil {
		t.Fatalf("Shred returned error: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("shredded file should no longer exist")
	}
}

func TestShredFileWithZeroPass(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "secret.txt", "sensitive data")

	if err := Shred([]string{path}, ShredOptions{Passes: 1, Zero: true, Force: true}); err != nil {
		t.Fatalf("Shred returned error: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("shredded file should no longer exist")
	}
}

func TestShredMissingFile(t *testing.T) {
	if err := Shred([]string{"/nonexistent/file"}, ShredOptions{Force: true}); err == nil {
		t.Error("Shred on a missing file should return an error")
	}
}

func TestShredDirectoryWithoutRecursiveFails(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "a.txt", "x")

	if err := Shred([]string{dir}, ShredOptions{Force: true}); err == nil {
		t.Error("Shred on a directory without Recursive should return an error")
	}
}

func TestShredDirectoryRecursive(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "a.txt", "x")
	sub := filepath.Join(dir, "sub")
	os.Mkdir(sub, 0755)
	writeFile(t, sub, "b.txt", "y")

	if err := Shred([]string{dir}, ShredOptions{Passes: 1, Force: true, Recursive: true}); err != nil {
		t.Fatalf("Shred(Recursive) returned error: %v", err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Error("shredded directory should no longer exist")
	}
}

func TestShredFileConfirmationDeclined(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "secret.txt", "data")

	withStdin(t, "n\n")
	out := captureShredStdout(t, func() {
		if err := Shred([]string{path}, ShredOptions{Passes: 1, Force: false}); err != nil {
			t.Fatalf("Shred returned error: %v", err)
		}
	})

	if !strings.Contains(out, "Skipped") {
		t.Errorf("expected a 'Skipped' message, got: %q", out)
	}
	if _, err := os.Stat(path); err != nil {
		t.Error("declining the confirmation should leave the file in place")
	}
}

func TestShredFileConfirmationAccepted(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "secret.txt", "data")

	withStdin(t, "y\n")
	captureShredStdout(t, func() {
		if err := Shred([]string{path}, ShredOptions{Passes: 1, Force: false}); err != nil {
			t.Fatalf("Shred returned error: %v", err)
		}
	})

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("accepting the confirmation should remove the file")
	}
}
