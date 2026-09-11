package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"raxuiscli/cmd"
	localdemo "raxuiscli/internal/demo"
	sharedcommand "raxuiscli/internal/shared/command"
	"raxuiscli/internal/shared/constants"
	"raxuiscli/internal/shared/models"
	"raxuiscli/internal/shared/report"
)

func TestDemoWebRunsWithoutArgumentsAndEmitsReadableJSON(t *testing.T) {
	root := newDemoTestRoot(t, localdemo.Web)
	stdout, stderr := buffers(root)
	root.SetArgs([]string{"--output=json", "demo", "web"})

	if err := root.Execute(); err != nil {
		t.Fatalf("demo web: %v; stderr=%q", err, stderr.String())
	}
	var value report.Report
	if err := json.Unmarshal(stdout.Bytes(), &value); err != nil {
		t.Fatalf("JSON output is impure: %v\n%s", err, stdout.String())
	}
	if _, err := report.Read(bytes.NewReader(stdout.Bytes())); err != nil {
		t.Fatalf("demo output does not satisfy schema v1: %v", err)
	}
	if value.SchemaVersion != report.SchemaVersion || value.Audit.Target != localdemo.StableWebTarget || value.Audit.Kind != "web" {
		t.Fatalf("demo report metadata = %+v", value.Audit)
	}
	if value.Tool.Name != "raxuiscli" || value.Tool.Commit == "" || value.Tool.GoVersion != runtime.Version() || value.Tool.Platform != runtime.GOOS+"/"+runtime.GOARCH {
		t.Fatalf("tool metadata = %+v", value.Tool)
	}
	if stderr.Len() != 0 {
		t.Fatalf("successful demo wrote stderr: %q", stderr.String())
	}
}

func TestDemoWebRejectsArgumentsBeforeRunning(t *testing.T) {
	called := false
	root := newDemoTestRoot(t, func(context.Context) (report.Report, error) {
		called = true
		return report.Report{}, nil
	})
	root.SetArgs([]string{"demo", "web", "https://example.test"})
	err := root.Execute()
	if err == nil || !errors.Is(err, sharedcommand.ErrOperational) || sharedcommand.ExitCode(err) != 1 {
		t.Fatalf("error = %T %v, want operational exit 1", err, err)
	}
	if called {
		t.Fatal("demo runner called for invalid arguments")
	}
}

func TestDemoWebSupportsTextJSONAndHTMLFiles(t *testing.T) {
	for _, tt := range []struct {
		name   string
		format string
		match  string
	}{
		{name: "text", format: "text", match: "RaxuisCLI Audit Report"},
		{name: "json", format: "json", match: `"schema_version": 1`},
		{name: "html", format: "html", match: "RaxuisCLI Audit Report"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			destination := filepath.Join(t.TempDir(), "demo."+tt.format)
			root := newDemoTestRoot(t, localdemo.Web)
			stdout, _ := buffers(root)
			root.SetArgs([]string{"--output=" + tt.format, "--output-file", destination, "demo", "web"})
			if err := root.Execute(); err != nil {
				t.Fatal(err)
			}
			contents, err := os.ReadFile(destination)
			if err != nil || !strings.Contains(string(contents), tt.match) {
				t.Fatalf("output = %q, error = %v", contents, err)
			}
			if stdout.Len() != 0 {
				t.Fatalf("file output also wrote stdout: %q", stdout.String())
			}
		})
	}

	root := newDemoTestRoot(t, localdemo.Web)
	root.SetArgs([]string{"--output=html", "demo", "web"})
	if err := root.Execute(); err == nil || !strings.Contains(err.Error(), "--output-file is required") {
		t.Fatalf("error = %v, want HTML destination requirement", err)
	}
}

func TestDemoWebOutputFileRequiresForceToReplace(t *testing.T) {
	destination := filepath.Join(t.TempDir(), "demo.json")
	if err := os.WriteFile(destination, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	root := newDemoTestRoot(t, localdemo.Web)
	root.SetArgs([]string{"--output=json", "--output-file", destination, "demo", "web"})
	err := root.Execute()
	if err == nil || !errors.Is(err, report.ErrDestinationExists) || !errors.Is(err, sharedcommand.ErrOperational) {
		t.Fatalf("error = %v, want typed overwrite refusal", err)
	}
	if contents, readErr := os.ReadFile(destination); readErr != nil || string(contents) != "original" {
		t.Fatalf("destination changed: %q, error=%v", contents, readErr)
	}

	root = newDemoTestRoot(t, localdemo.Web)
	root.SetArgs([]string{"--output=json", "--output-file", destination, "--force", "demo", "web"})
	if err := root.Execute(); err != nil {
		t.Fatalf("force replace: %v", err)
	}
	if contents, readErr := os.ReadFile(destination); readErr != nil || json.Valid(contents) == false {
		t.Fatalf("forced destination is invalid JSON: %q, error=%v", contents, readErr)
	}
}

func TestDemoWebOperationalAndPolicyOutcomesRenderInOrder(t *testing.T) {
	base := func(status string, findings []models.VulnResult, reportErrors []report.ReportError) report.Report {
		return report.NewReport(report.ToolInfo{}, report.AuditInfo{
			Kind: "web", Target: localdemo.StableWebTarget, StartedAt: time.Now(), Status: status,
		}, findings, nil, reportErrors)
	}

	t.Run("runner failure is operational", func(t *testing.T) {
		sentinel := errors.New("demo failed")
		root := newDemoTestRoot(t, func(context.Context) (report.Report, error) {
			return report.Report{}, sentinel
		})
		root.SetArgs([]string{"demo", "web"})
		err := root.Execute()
		if !errors.Is(err, sentinel) || !errors.Is(err, sharedcommand.ErrOperational) || sharedcommand.ExitCode(err) != 1 {
			t.Fatalf("error = %T %v", err, err)
		}
	})

	t.Run("renderer failure is operational after fixture lifecycle", func(t *testing.T) {
		runnerReturned := false
		root := newDemoTestRoot(t, func(context.Context) (report.Report, error) {
			value, err := localdemo.Web(context.Background())
			runnerReturned = true
			return value, err
		})
		root.SetOut(failingWriter{err: io.ErrClosedPipe})
		root.SetErr(&bytes.Buffer{})
		root.SetArgs([]string{"demo", "web"})
		err := root.Execute()
		if !runnerReturned || !errors.Is(err, io.ErrClosedPipe) || !errors.Is(err, sharedcommand.ErrOperational) {
			t.Fatalf("runnerReturned=%v error=%T %v", runnerReturned, err, err)
		}
	})

	t.Run("fixture lifecycle ends before renderer panic", func(t *testing.T) {
		runnerReturned := false
		root := newDemoTestRoot(t, func(ctx context.Context) (report.Report, error) {
			value, err := localdemo.Web(ctx)
			runnerReturned = true
			return value, err
		})
		root.SetOut(panickingWriter{})
		root.SetErr(&bytes.Buffer{})
		root.SetArgs([]string{"demo", "web"})
		func() {
			defer func() {
				if recovered := recover(); recovered != "renderer panic" {
					t.Fatalf("recovered = %v, want renderer panic", recovered)
				}
			}()
			_ = root.Execute()
		}()
		if !runnerReturned {
			t.Fatal("renderer panicked before fixture lifecycle completed")
		}
	})

	t.Run("partial report renders then exits operationally", func(t *testing.T) {
		partial := base("partial", nil, []report.ReportError{{Code: "fixture", Message: "partial"}})
		root := newDemoTestRoot(t, func(context.Context) (report.Report, error) { return partial, nil })
		stdout, _ := buffers(root)
		root.SetArgs([]string{"--output=json", "demo", "web"})
		err := root.Execute()
		if !errors.Is(err, sharedcommand.ErrOperational) || !json.Valid(stdout.Bytes()) {
			t.Fatalf("error=%v output=%q", err, stdout.String())
		}
	})

	t.Run("policy report renders then exits two", func(t *testing.T) {
		finding := models.VulnResult{RuleID: "fixture.high", Title: "High", Severity: constants.SeverityHigh, Resource: localdemo.StableWebTarget}
		value := base("success", []models.VulnResult{finding}, nil)
		root := newDemoTestRoot(t, func(context.Context) (report.Report, error) { return value, nil })
		stdout, _ := buffers(root)
		root.SetArgs([]string{"--output=json", "--fail-on=high", "demo", "web"})
		err := root.Execute()
		if !errors.Is(err, sharedcommand.ErrPolicyThreshold) || sharedcommand.ExitCode(err) != 2 || !json.Valid(stdout.Bytes()) {
			t.Fatalf("error=%v output=%q", err, stdout.String())
		}
	})
}

func TestDemoWebPropagatesCommandContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	root := newDemoTestRoot(t, func(received context.Context) (report.Report, error) {
		if !errors.Is(received.Err(), context.Canceled) {
			t.Fatalf("runner context error = %v", received.Err())
		}
		return report.Report{}, received.Err()
	})
	root.SetContext(ctx)
	root.SetArgs([]string{"demo", "web"})
	if err := root.Execute(); !errors.Is(err, context.Canceled) || !errors.Is(err, sharedcommand.ErrOperational) {
		t.Fatalf("error = %T %v", err, err)
	}
}

func TestDemoCommandIsRegisteredExactlyOnceAtTopLevel(t *testing.T) {
	count := 0
	var found *cobra.Command
	for _, command := range cmd.RootCmd.Commands() {
		if command.Name() == "demo" {
			count++
			found = command
		}
	}
	if count != 1 || found == nil {
		t.Fatalf("top-level demo command count = %d", count)
	}
	webCount := 0
	for _, command := range found.Commands() {
		if command.Name() == "web" {
			webCount++
		}
	}
	if webCount != 1 {
		t.Fatalf("demo web command count = %d", webCount)
	}
}

func newDemoTestRoot(t *testing.T, runner demoRunner) *cobra.Command {
	t.Helper()
	root := &cobra.Command{
		Use:           "raxuiscli",
		SilenceErrors: true,
		SilenceUsage:  true,
		PersistentPreRunE: func(command *cobra.Command, _ []string) error {
			_, err := cmd.OptionsFromCommand(command)
			return err
		},
	}
	root.PersistentFlags().String("output", "text", "")
	root.PersistentFlags().String("output-file", "", "")
	root.PersistentFlags().Bool("force", false, "")
	root.PersistentFlags().Bool("no-color", false, "")
	root.PersistentFlags().Bool("quiet", false, "")
	root.PersistentFlags().String("fail-on", "none", "")
	root.AddCommand(newDemoCommand(runner))
	return root
}

type failingWriter struct{ err error }

func (writer failingWriter) Write([]byte) (int, error) { return 0, writer.err }

type panickingWriter struct{}

func (panickingWriter) Write([]byte) (int, error) { panic("renderer panic") }
