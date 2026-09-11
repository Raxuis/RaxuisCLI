package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"raxuiscli/cmd"
	webaudit "raxuiscli/internal/audit/web"
	sharedcommand "raxuiscli/internal/shared/command"
	"raxuiscli/internal/shared/constants"
	"raxuiscli/internal/shared/models"
	"raxuiscli/internal/shared/report"
)

func TestWebRequiresExactlyOneTarget(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{name: "missing target", args: []string{"audit", "web"}},
		{name: "extra target", args: []string{"audit", "web", "http://fixture.test", "unexpected"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			called := false
			root := newTestRoot(t, func(context.Context, string, webaudit.Options) (report.Report, error) {
				called = true
				return report.Report{}, nil
			})
			root.SetArgs(tt.args)

			err := root.Execute()
			if err == nil {
				t.Fatal("audit web accepted invalid arity")
			}
			if called {
				t.Fatal("audit runner was called for invalid arity")
			}
			if !strings.Contains(err.Error(), "accepts 1 arg(s)") {
				t.Fatalf("error = %q, want exact-argument error", err)
			}
			var operational *sharedcommand.OperationalError
			if !errors.As(err, &operational) || !errors.Is(err, sharedcommand.ErrOperational) {
				t.Fatalf("error = %T %v, want typed operational error", err, err)
			}
			if code := sharedcommand.ExitCode(err); code != 1 {
				t.Fatalf("ExitCode(error) = %d, want 1", code)
			}
		})
	}
}

func TestWebRejectsInvalidURLAsOperationalError(t *testing.T) {
	root := newTestRoot(t, webaudit.Audit)
	root.SetArgs([]string{"audit", "web", "ftp://example.test"})

	err := root.Execute()
	if err == nil {
		t.Fatal("audit web accepted FTP URL")
	}
	if !errors.Is(err, sharedcommand.ErrOperational) {
		t.Fatalf("error = %T %v, want operational error", err, err)
	}
}

func TestWebJSONOnStdoutIsOnlyTheReportEnvelope(t *testing.T) {
	server := localHTTPFixture(t)
	root := newTestRoot(t, webaudit.Audit)
	stdout, stderr := buffers(root)
	root.SetArgs([]string{"--output=json", "audit", "web", server.URL})

	if err := root.Execute(); err != nil {
		t.Fatalf("audit web: %v; stderr: %s", err, stderr.String())
	}
	if strings.Contains(stdout.String(), "Auditing") || strings.Contains(stdout.String(), "RaxuisCLI Audit Report") {
		t.Fatalf("stdout contains presentation text: %q", stdout.String())
	}
	var value report.Report
	if err := json.Unmarshal(stdout.Bytes(), &value); err != nil {
		t.Fatalf("stdout is not a standalone JSON report: %v\n%s", err, stdout.String())
	}
	if value.Audit.Target != server.URL+"/" {
		t.Errorf("report target = %q, want local fixture %q", value.Audit.Target, server.URL+"/")
	}
}

func TestWebHTMLRequiresOutputFile(t *testing.T) {
	root := newTestRoot(t, webaudit.Audit)
	root.SetArgs([]string{"--output=html", "audit", "web", "http://127.0.0.1:1"})

	err := root.Execute()
	if err == nil || !strings.Contains(err.Error(), "--output-file is required") {
		t.Fatalf("error = %v, want output-file requirement", err)
	}
}

func TestWebRefusesToOverwriteOutputFileWithoutForce(t *testing.T) {
	server := localHTTPFixture(t)
	destination := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(destination, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	root := newTestRoot(t, webaudit.Audit)
	root.SetArgs([]string{"--output=json", "--output-file", destination, "audit", "web", server.URL})

	err := root.Execute()
	if err == nil || !errors.Is(err, sharedcommand.ErrOperational) {
		t.Fatalf("error = %v, want operational overwrite refusal", err)
	}
	if got, readErr := os.ReadFile(destination); readErr != nil || string(got) != "original" {
		t.Fatalf("destination = %q, read error = %v; want unchanged original", got, readErr)
	}
}

func TestWebQuietDoesNotAddOutputAroundReport(t *testing.T) {
	server := localHTTPFixture(t)
	root := newTestRoot(t, webaudit.Audit)
	stdout, stderr := buffers(root)
	root.SetArgs([]string{"--quiet", "--output=json", "audit", "web", server.URL})

	if err := root.Execute(); err != nil {
		t.Fatalf("audit web: %v; stderr: %s", err, stderr.String())
	}
	var value report.Report
	if err := json.Unmarshal(stdout.Bytes(), &value); err != nil {
		t.Fatalf("quiet JSON output is impure: %v\n%s", err, stdout.String())
	}
}

func TestWebPartialAuditReturnsOperationalErrorAfterRendering(t *testing.T) {
	partial := report.NewReport(report.ToolInfo{}, report.AuditInfo{Kind: "web", Target: "https://fixture.test", StartedAt: time.Now(), Status: "partial"}, nil, nil, []report.ReportError{{Code: "tls.collect", Message: "fixture failed"}})
	root := newTestRoot(t, func(context.Context, string, webaudit.Options) (report.Report, error) { return partial, nil })
	stdout, _ := buffers(root)
	root.SetArgs([]string{"--output=json", "audit", "web", "https://fixture.test"})

	err := root.Execute()
	if !errors.Is(err, sharedcommand.ErrOperational) {
		t.Fatalf("error = %T %v, want operational error", err, err)
	}
	var value report.Report
	if decodeErr := json.Unmarshal(stdout.Bytes(), &value); decodeErr != nil || value.Audit.Status != "partial" {
		t.Fatalf("partial report was not rendered: decode=%v report=%+v", decodeErr, value.Audit)
	}
}

func TestWebFailOnReturnsPolicyError(t *testing.T) {
	completed := report.NewReport(report.ToolInfo{}, report.AuditInfo{Kind: "web", Target: "https://fixture.test", StartedAt: time.Now(), Status: "success"}, []models.VulnResult{{RuleID: "fixture.high", Severity: constants.SeverityHigh, Resource: "https://fixture.test"}}, nil, nil)
	root := newTestRoot(t, func(context.Context, string, webaudit.Options) (report.Report, error) { return completed, nil })
	buffers(root)
	root.SetArgs([]string{"--fail-on=medium", "audit", "web", "https://fixture.test"})

	err := root.Execute()
	var policy *sharedcommand.PolicyError
	if !errors.As(err, &policy) {
		t.Fatalf("error = %T %v, want policy error", err, err)
	}
	if code := sharedcommand.ExitCode(err); code != 2 {
		t.Fatalf("ExitCode(error) = %d, want 2", code)
	}
}

func TestWebAttachesBuildMetadata(t *testing.T) {
	var captured report.Report
	root := newTestRoot(t, func(ctx context.Context, target string, options webaudit.Options) (report.Report, error) {
		value := report.NewReport(report.ToolInfo{}, report.AuditInfo{Kind: "web", Target: target, StartedAt: time.Now(), Status: "success"}, nil, nil, nil)
		captured = value
		return value, nil
	})
	stdout, _ := buffers(root)
	root.SetArgs([]string{"--output=json", "audit", "web", "http://fixture.test"})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(stdout.Bytes(), &captured); err != nil {
		t.Fatal(err)
	}
	if _, err := report.Read(bytes.NewReader(stdout.Bytes())); err != nil {
		t.Fatalf("emitted audit snapshot is not self-readable: %v", err)
	}
	if captured.Tool.Name != "raxuiscli" || captured.Tool.Version == "" || captured.Tool.Commit == "" || captured.Tool.GoVersion != runtime.Version() || captured.Tool.Platform != runtime.GOOS+"/"+runtime.GOARCH {
		t.Errorf("tool metadata = %+v, want current build metadata", captured.Tool)
	}
}

func TestToolInfoFromVersionBannerCommitFallback(t *testing.T) {
	for _, tt := range []struct {
		name   string
		banner string
		commit string
	}{
		{
			name:   "missing commit uses deterministic fallback",
			banner: "raxuiscli dev\nlinux/amd64, go1.test",
			commit: "unknown",
		},
		{
			name:   "embedded commit is retained",
			banner: "raxuiscli v1.2.3 (abc123def456)\nlinux/amd64, go1.test",
			commit: "abc123def456",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := toolInfoFromVersionBanner(tt.banner).Commit; got != tt.commit {
				t.Fatalf("Commit = %q, want %q", got, tt.commit)
			}
		})
	}
}

func newTestRoot(t *testing.T, runner auditRunner) *cobra.Command {
	t.Helper()
	root := &cobra.Command{
		Use:           "raxuiscli",
		SilenceErrors: true,
		SilenceUsage:  true,
		PersistentPreRunE: func(command *cobra.Command, args []string) error {
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
	root.AddCommand(newAuditCommand(runner))
	return root
}

func buffers(command *cobra.Command) (*bytes.Buffer, *bytes.Buffer) {
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	command.SetOut(stdout)
	command.SetErr(stderr)
	return stdout, stderr
}

func localHTTPFixture(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Host != "" {
			t.Fatalf("unexpected non-local request target: %s", request.URL)
		}
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		writer.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(writer, "fixture")
	}))
	t.Cleanup(server.Close)
	return server
}
