package audit

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Raxuis/RaxuisCLI/internal/audit/combined"
	webaudit "github.com/Raxuis/RaxuisCLI/internal/audit/web"
	sharedcommand "github.com/Raxuis/RaxuisCLI/internal/shared/command"
	"github.com/Raxuis/RaxuisCLI/internal/shared/constants"
	"github.com/Raxuis/RaxuisCLI/internal/shared/models"
	"github.com/Raxuis/RaxuisCLI/internal/shared/report"
	"github.com/spf13/cobra"
)

func combinedRoot(t *testing.T, runner combinedAuditRunner) *cobra.Command {
	root := newTestRoot(t, webaudit.Audit)
	previous, _, err := root.Find([]string{"audit", "all"})
	if err != nil {
		t.Fatal(err)
	}
	parent := previous.Parent()
	parent.RemoveCommand(previous)
	parent.AddCommand(newAllCommand(runner))
	return root
}

func combinedFixture(status string) report.Report {
	return report.NewReport(report.ToolInfo{}, report.AuditInfo{Kind: "all", Target: "https://example.test/", Status: status, StartedAt: time.Now()}, []models.VulnResult{{RuleID: "combined.test", Title: "fixture", Type: constants.VulnHeaders, Severity: constants.SeverityHigh, Resource: "https://example.test/", Evidence: "fixture", Remediation: "fix"}}, nil, nil)
}

func TestCombinedReportExitCodesAndReadComparison(t *testing.T) {
	for _, test := range []struct {
		status, threshold string
		code              int
	}{{"complete", "none", 0}, {"complete", "high", 2}, {"partial", "high", 1}} {
		t.Run(test.status+test.threshold, func(t *testing.T) {
			root := combinedRoot(t, func(context.Context, string, combined.Options) (report.Report, error) {
				return combinedFixture(test.status), nil
			})
			stdout, _ := buffers(root)
			root.SetArgs([]string{"--output=json", "--fail-on=" + test.threshold, "audit", "all", "https://example.test"})
			if code := sharedcommand.ExitCode(root.Execute()); code != test.code {
				t.Fatalf("exit=%d want=%d", code, test.code)
			}
			value, err := report.Read(bytes.NewReader(stdout.Bytes()))
			if err != nil || value.Audit.Kind != "all" {
				t.Fatalf("read: %v\n%s", err, stdout)
			}
			result, err := report.Compare(value, value, false)
			if err != nil || len(result.Findings.Unchanged) != 1 {
				t.Fatalf("comparison=%+v err=%v", result, err)
			}
		})
	}
}

func TestCombinedOptionsAndHTMLFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.html")
	called := false
	root := combinedRoot(t, func(_ context.Context, target string, options combined.Options) (report.Report, error) {
		called = true
		if target != "https://example.test" || options.Timeout != 3*time.Second || !options.AXFR || options.Nameserver != "127.0.0.1:5353" || options.Web.Headers["X-Test"] != "yes" || !options.Web.InsecureTLS || options.Web.Cookie != "session=test" {
			t.Fatalf("options=%+v target=%s", options, target)
		}
		return combinedFixture("complete"), nil
	})
	stdout, _ := buffers(root)
	root.SetArgs([]string{"--output=html", "--output-file=" + path, "audit", "all", "https://example.test", "--timeout=3s", "--axfr", "--nameserver=127.0.0.1:5353", "--header=X-Test: yes", "--cookie=session=test", "--insecure"})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(contents), "<html") || stdout.Len() != 0 || !called {
		t.Fatalf("html=%s err=%v", contents, err)
	}
	root.SetArgs([]string{"--output=html", "--output-file=" + path, "audit", "all", "https://example.test", "--timeout=3s", "--axfr", "--nameserver=127.0.0.1:5353", "--header=X-Test: yes", "--cookie=session=test", "--insecure"})
	if err := root.Execute(); err == nil {
		t.Fatal("existing report overwritten")
	}
}

func TestCombinedInvalidInputBeforeRunner(t *testing.T) {
	for _, args := range [][]string{{"audit", "all"}, {"audit", "all", "https://example.test", "extra"}, {"audit", "all", "https://example.test", "--timeout=0s"}, {"audit", "all", "https://example.test", "--header=invalid"}} {
		root := combinedRoot(t, func(context.Context, string, combined.Options) (report.Report, error) {
			t.Fatal("runner called for invalid input")
			return report.Report{}, nil
		})
		root.SetArgs(args)
		if code := sharedcommand.ExitCode(root.Execute()); code != 1 {
			t.Fatalf("%v exit=%d", args, code)
		}
	}
}
