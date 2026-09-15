package report

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type testRenderer struct {
	content string
	err     error
}

func (renderer testRenderer) Render(writer io.Writer, _ Report) error {
	if renderer.err != nil {
		return renderer.err
	}
	_, err := io.WriteString(writer, renderer.content)
	return err
}

func TestWriteFileCreatesAtomically(t *testing.T) {
	directory := t.TempDir()
	destination := filepath.Join(directory, "report.json")
	if err := WriteFile(destination, Report{}, testRenderer{content: "new report"}, false); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	got, err := os.ReadFile(destination)
	if err != nil {
		t.Fatalf("read destination: %v", err)
	}
	if string(got) != "new report" {
		t.Errorf("destination = %q, want %q", got, "new report")
	}
	assertNoTemporaryFiles(t, directory)
}

func TestWriteFileRefusesOverwriteWithoutForce(t *testing.T) {
	directory := t.TempDir()
	destination := filepath.Join(directory, "report.json")
	if err := os.WriteFile(destination, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}

	err := WriteFile(destination, Report{}, testRenderer{content: "replacement"}, false)
	if !errors.Is(err, ErrDestinationExists) {
		t.Fatalf("WriteFile error = %v, want ErrDestinationExists", err)
	}
	got, readErr := os.ReadFile(destination)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(got) != "original" {
		t.Errorf("destination = %q, want original", got)
	}
	assertNoTemporaryFiles(t, directory)
}

func TestWriteFileNoForcePreservesInterposedDestination(t *testing.T) {
	directory := t.TempDir()
	destination := filepath.Join(directory, "report.json")

	originalBeforePublish := beforeNoReplacePublish
	t.Cleanup(func() { beforeNoReplacePublish = originalBeforePublish })
	beforeNoReplacePublish = func(path string) {
		if err := os.WriteFile(path, []byte("interposed creator"), 0o600); err != nil {
			t.Fatalf("interpose destination creation: %v", err)
		}
	}

	err := WriteFile(destination, Report{}, testRenderer{content: "replacement"}, false)
	if !errors.Is(err, ErrDestinationExists) {
		t.Fatalf("WriteFile error = %v, want ErrDestinationExists", err)
	}
	got, readErr := os.ReadFile(destination)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(got) != "interposed creator" {
		t.Errorf("destination = %q, want interposed creator preserved", got)
	}
	assertNoTemporaryFiles(t, directory)
}

func TestWriteFileForceReplacesExistingFile(t *testing.T) {
	directory := t.TempDir()
	destination := filepath.Join(directory, "report.json")
	if err := os.WriteFile(destination, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteFile(destination, Report{}, testRenderer{content: "replacement"}, true); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	got, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "replacement" {
		t.Errorf("destination = %q, want replacement", got)
	}
	assertNoTemporaryFiles(t, directory)
}

func TestWriteFileCleansTemporaryFileAfterRenderFailure(t *testing.T) {
	directory := t.TempDir()
	destination := filepath.Join(directory, "report.json")
	errRender := errors.New("render failed")
	err := WriteFile(destination, Report{}, testRenderer{err: errRender}, false)
	if !errors.Is(err, errRender) {
		t.Fatalf("WriteFile error = %v, want render error", err)
	}
	if _, statErr := os.Stat(destination); !errors.Is(statErr, os.ErrNotExist) {
		t.Errorf("destination stat error = %v, want not exist", statErr)
	}
	assertNoTemporaryFiles(t, directory)
}

func TestWriteFileForcePreservesDestinationWhenPublicationFails(t *testing.T) {
	directory := t.TempDir()
	destination := filepath.Join(directory, "report.json")
	if err := os.WriteFile(destination, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}

	originalPublishReplace := publishReplace
	t.Cleanup(func() { publishReplace = originalPublishReplace })
	publishReplace = func(_, _ string) error { return errors.New("simulated replacement failure") }

	err := WriteFile(destination, Report{}, testRenderer{content: "replacement"}, true)
	if err == nil || !strings.Contains(err.Error(), "replacement failure") {
		t.Fatalf("WriteFile error = %v, want replacement failure", err)
	}
	got, readErr := os.ReadFile(destination)
	if readErr != nil {
		t.Fatalf("read restored destination: %v", readErr)
	}
	if string(got) != "original" {
		t.Errorf("destination = %q, want original preserved", got)
	}
	assertNoTemporaryFiles(t, directory)
}

func assertNoTemporaryFiles(t *testing.T, directory string) {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.Contains(entry.Name(), ".tmp-") || strings.Contains(entry.Name(), ".backup-") {
			t.Errorf("temporary file %q was not cleaned up", entry.Name())
		}
	}
}
