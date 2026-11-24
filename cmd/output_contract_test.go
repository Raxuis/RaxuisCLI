package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Raxuis/RaxuisCLI/internal/shared/output"
	"github.com/spf13/cobra"
)

func TestOutputFileIsAtomicAndRespectsForce(t *testing.T) {
	root := newRootCommand()
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.AddCommand(&cobra.Command{Use: "emit", RunE: func(_ *cobra.Command, _ []string) error { _, err := io.WriteString(output.Std, "result\n"); return err }})
	path := filepath.Join(t.TempDir(), "result.txt")
	for _, tc := range []struct {
		force bool
		want  int
	}{{false, 0}, {false, 1}, {true, 0}} {
		args := []string{"--output-file", path, "emit"}
		if tc.force {
			args = append(args, "--force")
		}
		root.SetArgs(args)
		if got := execute(root); got != tc.want {
			t.Fatalf("exit=%d want=%d stderr=%s", got, tc.want, &stderr)
		}
		data, err := os.ReadFile(path)
		if err != nil || string(data) != "result\n" {
			t.Fatalf("file=%q err=%v", data, err)
		}
	}
	if stdout.Len() != 0 {
		t.Fatalf("file output leaked to stdout: %q", &stdout)
	}
}

func TestFailedCommandDoesNotPublishOutput(t *testing.T) {
	root := newRootCommand()
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	root.AddCommand(&cobra.Command{Use: "emit", RunE: func(_ *cobra.Command, _ []string) error {
		fmt.Fprint(output.Std, "partial")
		return errors.New("failed")
	}})
	path := filepath.Join(t.TempDir(), "result.txt")
	root.SetArgs([]string{"--output-file", path, "emit"})
	if execute(root) != 1 {
		t.Fatal("expected failure")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("partial file published: %v", err)
	}
}

type brokenOutput struct{}

func (brokenOutput) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestIgnoredWriterFailureStillFailsCommand(t *testing.T) {
	root := newRootCommand()
	root.SetOut(brokenOutput{})
	var stderr bytes.Buffer
	root.SetErr(&stderr)
	root.AddCommand(&cobra.Command{Use: "emit", Run: func(c *cobra.Command, _ []string) {
		fmt.Fprintln(c.OutOrStdout(), "ignored write error")
		fmt.Fprintln(output.Std, "also ignored")
	}})
	root.SetArgs([]string{"emit"})
	if execute(root) != 1 {
		t.Fatal("writer failure returned success")
	}
	if !strings.Contains(stderr.String(), "closed pipe") {
		t.Fatalf("stderr=%q", &stderr)
	}
}

func TestUnsupportedOptionsAreRejectedBeforeAction(t *testing.T) {
	for _, args := range [][]string{{"--output=html", "--output-file=unused.html"}, {"--output=json"}, {"--fail-on=high"}, {"--quiet"}} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			root := newRootCommand()
			var stdout, stderr bytes.Buffer
			root.SetOut(&stdout)
			root.SetErr(&stderr)
			ran := false
			root.AddCommand(&cobra.Command{Use: "tunnel", Run: func(*cobra.Command, []string) { ran = true }})
			root.SetArgs(append(args, "tunnel"))
			if execute(root) != 1 || ran || stdout.Len() != 0 || stderr.Len() == 0 {
				t.Fatalf("ran=%v stdout=%s stderr=%s", ran, &stdout, &stderr)
			}
		})
	}
}
