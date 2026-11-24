package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/Raxuis/RaxuisCLI/internal/shared/output"
	"github.com/spf13/cobra"
)

func TestReviewRepeatedExecuteRestoresHandlersAndCurrentOptions(t *testing.T) {
	root := newRootCommand()
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	calls := 0
	root.AddCommand(&cobra.Command{Use: "emit", Run: func(c *cobra.Command, _ []string) { calls++; fmt.Fprintf(c.OutOrStdout(), "call %d\n", calls) }})
	dir := t.TempDir()
	bad := filepath.Join(dir, "missing", "result.txt")
	root.SetArgs([]string{"emit", "--output-file", bad})
	if execute(root) != 1 || calls != 0 {
		t.Fatalf("failed destination ran action: %d calls; stderr=%s", calls, &stderr)
	}
	path := filepath.Join(dir, "result.txt")
	root.SetArgs([]string{"emit", "--output-file", path})
	if execute(root) != 0 {
		t.Fatalf("second execution failed: %s", &stderr)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "call 1\n" {
		t.Fatalf("file=%q, %v", data, err)
	}
	root.SetArgs([]string{"emit", "--output-file="})
	if execute(root) != 0 || stdout.String() != "call 2\n" {
		t.Fatalf("stdout=%q stderr=%s", &stdout, &stderr)
	}
}

func TestReviewFailedForcedWritePreservesExistingFile(t *testing.T) {
	root := newRootCommand()
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	root.AddCommand(&cobra.Command{Use: "emit", RunE: func(c *cobra.Command, _ []string) error {
		fmt.Fprint(c.OutOrStdout(), "partial replacement")
		return errors.New("failed action")
	}})
	path := filepath.Join(t.TempDir(), "result.txt")
	if err := os.WriteFile(path, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	root.SetArgs([]string{"emit", "--force", "--output-file", path})
	if execute(root) != 1 {
		t.Fatal("expected failure")
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "original" {
		t.Fatalf("file=%q, %v", data, err)
	}
}

func TestReviewNoColorStripsEscapeSequencesAcrossWrites(t *testing.T) {
	root := newRootCommand()
	var stdout bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(io.Discard)
	root.AddCommand(&cobra.Command{Use: "emit", Run: func(*cobra.Command, []string) {
		fmt.Fprint(output.Std, "\x1b[")
		fmt.Fprint(output.Std, "31mred")
		fmt.Fprint(output.Std, "\x1b[0m")
	}})
	root.SetArgs([]string{"emit", "--no-color"})
	if execute(root) != 0 {
		t.Fatal("execution failed")
	}
	if stdout.String() != "red" {
		t.Fatalf("plain output=%q, want red", stdout.String())
	}
}

func TestReviewUnsupportedFileDoesNotRunLongLivedAction(t *testing.T) {
	root := newRootCommand()
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	pivot := &cobra.Command{Use: "pivot"}
	root.AddCommand(pivot)
	ran := false
	pivot.AddCommand(&cobra.Command{Use: "socks5", Run: func(*cobra.Command, []string) { ran = true }})
	path := filepath.Join(t.TempDir(), "result.txt")
	root.SetArgs([]string{"pivot", "socks5", "--output-file", path})
	if execute(root) != 1 || ran {
		t.Fatalf("unsupported file option ran action: %v", ran)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("unexpected destination: %v", err)
	}
}

type reviewShortWriter struct{}

func (reviewShortWriter) Write(p []byte) (int, error) { return len(p) - 1, nil }
func TestReviewIgnoredShortWriteFailsCommand(t *testing.T) {
	root := newRootCommand()
	root.SetOut(reviewShortWriter{})
	root.SetErr(io.Discard)
	root.AddCommand(&cobra.Command{Use: "emit", Run: func(c *cobra.Command, _ []string) { fmt.Fprint(c.OutOrStdout(), "payload") }})
	root.SetArgs([]string{"emit"})
	if execute(root) != 1 {
		t.Fatal("ignored short write returned success")
	}
}
