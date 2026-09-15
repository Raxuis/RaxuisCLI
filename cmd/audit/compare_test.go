package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/Raxuis/RaxuisCLI/cmd"
	sharedcommand "github.com/Raxuis/RaxuisCLI/internal/shared/command"
	"github.com/Raxuis/RaxuisCLI/internal/shared/constants"
	"github.com/Raxuis/RaxuisCLI/internal/shared/models"
	"github.com/Raxuis/RaxuisCLI/internal/shared/render"
	"github.com/Raxuis/RaxuisCLI/internal/shared/report"
)

func TestCompareRequiresExactlyTwoReportsBeforeReading(t *testing.T) {
	for _, args := range [][]string{{"compare"}, {"compare", "before.json"}, {"compare", "before.json", "after.json", "extra.json"}} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			reads := 0
			root := newCompareTestRoot(t, func(string) (report.Report, error) {
				reads++
				return report.Report{}, nil
			})
			root.SetArgs(args)

			err := root.Execute()
			if err == nil || !strings.Contains(err.Error(), "accepts 2 arg(s)") {
				t.Fatalf("error = %v, want exact-argument error", err)
			}
			if reads != 0 {
				t.Fatalf("report reader called %d times for invalid arity", reads)
			}
			if !errors.Is(err, sharedcommand.ErrOperational) || sharedcommand.ExitCode(err) != 1 {
				t.Fatalf("error = %T %v, want operational exit 1", err, err)
			}
		})
	}
}

func TestCompareReportReadFailuresAreOperational(t *testing.T) {
	valid := comparisonReport("https://fixture.test/", nil, "success")
	validPath := writeComparisonReport(t, "valid.json", valid)
	for _, tt := range []struct {
		name   string
		before string
		reader func(string) (report.Report, error)
	}{
		{name: "missing", before: filepath.Join(t.TempDir(), "missing.json"), reader: report.ReadFile},
		{name: "unreadable", before: "denied.json", reader: func(name string) (report.Report, error) {
			return report.Report{}, &os.PathError{Op: "open", Path: name, Err: fs.ErrPermission}
		}},
		{name: "truncated", before: writeComparisonBytes(t, "truncated.json", []byte(`{"schema_version":`)), reader: report.ReadFile},
		{name: "unsupported schema", before: writeComparisonBytes(t, "unsupported.json", []byte(`{"schema_version":2}`)), reader: report.ReadFile},
		{name: "invalid schema", before: writeComparisonBytes(t, "invalid.json", []byte(`[]`)), reader: report.ReadFile},
	} {
		t.Run(tt.name, func(t *testing.T) {
			root := newCompareTestRoot(t, tt.reader)
			root.SetArgs([]string{"compare", tt.before, validPath})
			err := root.Execute()
			if err == nil || !errors.Is(err, sharedcommand.ErrOperational) {
				t.Fatalf("error = %T %v, want operational error", err, err)
			}
			if code := sharedcommand.ExitCode(err); code != 1 {
				t.Fatalf("ExitCode(error) = %d, want 1", code)
			}
		})
	}
}

func TestCompareRejectsKindMismatchEvenWhenTargetMismatchAllowed(t *testing.T) {
	before := writeComparisonReport(t, "before.json", comparisonReport("https://before.test/", nil, "success"))
	afterValue := comparisonReport("https://after.test/", nil, "success")
	afterValue.Audit.Kind = "container"
	after := writeComparisonReport(t, "after.json", afterValue)
	root := newCompareTestRoot(t, report.ReadFile)
	root.SetArgs([]string{"compare", "--allow-target-mismatch", before, after})

	err := root.Execute()
	if err == nil || !errors.Is(err, report.ErrKindMismatch) || !errors.Is(err, sharedcommand.ErrOperational) {
		t.Fatalf("error = %T %v, want wrapped kind mismatch", err, err)
	}
}

func TestCompareRejectsTargetMismatchUnlessExplicitlyAllowed(t *testing.T) {
	before := writeComparisonReport(t, "before.json", comparisonReport("https://before.test/", nil, "success"))
	after := writeComparisonReport(t, "after.json", comparisonReport("https://after.test/", nil, "success"))
	root := newCompareTestRoot(t, report.ReadFile)
	root.SetArgs([]string{"compare", before, after})
	if err := root.Execute(); err == nil || !errors.Is(err, report.ErrTargetMismatch) {
		t.Fatalf("error = %v, want target mismatch", err)
	}

	root = newCompareTestRoot(t, report.ReadFile)
	stdout, _ := comparisonBuffers(root)
	root.SetArgs([]string{"--output=json", "compare", "--allow-target-mismatch", before, after})
	if err := root.Execute(); err != nil {
		t.Fatalf("allowed mismatch: %v", err)
	}
	var comparison report.Comparison
	if err := json.Unmarshal(stdout.Bytes(), &comparison); err != nil {
		t.Fatalf("allowed mismatch did not render JSON: %v\n%s", err, stdout.String())
	}
}

func TestCompareAcceptsSameCanonicalTarget(t *testing.T) {
	before := writeComparisonReport(t, "before.json", comparisonReport("https://fixture.test", nil, "partial"))
	after := writeComparisonReport(t, "after.json", comparisonReport("https://fixture.test/", nil, "partial"))
	root := newCompareTestRoot(t, report.ReadFile)
	root.SetArgs([]string{"compare", before, after})
	if err := root.Execute(); err != nil {
		t.Fatalf("same canonical target rejected: %v", err)
	}
}

func TestCompareSupportsTextJSONAndHTMLOutput(t *testing.T) {
	added := models.VulnResult{RuleID: "fixture.added", Title: "Added finding", Severity: constants.SeverityHigh, Resource: "https://fixture.test/"}
	before := writeComparisonReport(t, "before.json", comparisonReport("https://fixture.test/", nil, "success"))
	after := writeComparisonReport(t, "after.json", comparisonReport("https://fixture.test/", []models.VulnResult{added}, "success"))

	t.Run("text", func(t *testing.T) {
		root := newCompareTestRoot(t, report.ReadFile)
		stdout, _ := comparisonBuffers(root)
		root.SetArgs([]string{"compare", before, after})
		if err := root.Execute(); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(stdout.String(), "RaxuisCLI Audit Comparison") || !strings.Contains(stdout.String(), "ADDED") {
			t.Fatalf("text comparison = %q", stdout.String())
		}
	})

	t.Run("json stdout is only envelope", func(t *testing.T) {
		root := newCompareTestRoot(t, report.ReadFile)
		stdout, stderr := comparisonBuffers(root)
		root.SetArgs([]string{"--output=json", "compare", before, after})
		if err := root.Execute(); err != nil {
			t.Fatalf("compare: %v; stderr: %s", err, stderr.String())
		}
		if strings.Contains(stdout.String(), "RaxuisCLI Audit Comparison") || stderr.Len() != 0 {
			t.Fatalf("comparison JSON was not pure stdout: stdout=%q stderr=%q", stdout.String(), stderr.String())
		}
		var value report.Comparison
		if err := json.Unmarshal(stdout.Bytes(), &value); err != nil {
			t.Fatalf("stdout is not a comparison envelope: %v\n%s", err, stdout.String())
		}
	})

	t.Run("html requires output file", func(t *testing.T) {
		root := newCompareTestRoot(t, report.ReadFile)
		root.SetArgs([]string{"--output=html", "compare", before, after})
		if err := root.Execute(); err == nil || !strings.Contains(err.Error(), "--output-file is required") {
			t.Fatalf("error = %v, want HTML output-file requirement", err)
		}
	})

	t.Run("html file", func(t *testing.T) {
		destination := filepath.Join(t.TempDir(), "comparison.html")
		root := newCompareTestRoot(t, report.ReadFile)
		stdout, _ := comparisonBuffers(root)
		root.SetArgs([]string{"--output=html", "--output-file", destination, "compare", before, after})
		if err := root.Execute(); err != nil {
			t.Fatal(err)
		}
		body, err := os.ReadFile(destination)
		if err != nil || !strings.Contains(string(body), "Audit Comparison") || stdout.Len() != 0 {
			t.Fatalf("HTML output = %q, err = %v, stdout = %q", body, err, stdout.String())
		}
	})
}

func TestCompareOutputFileDoesNotOverwriteWithoutForce(t *testing.T) {
	before := writeComparisonReport(t, "before.json", comparisonReport("https://fixture.test/", nil, "success"))
	after := writeComparisonReport(t, "after.json", comparisonReport("https://fixture.test/", nil, "success"))
	destination := filepath.Join(t.TempDir(), "comparison.json")
	if err := os.WriteFile(destination, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}

	root := newCompareTestRoot(t, report.ReadFile)
	root.SetArgs([]string{"--output=json", "--output-file", destination, "compare", before, after})
	err := root.Execute()
	if err == nil || !errors.Is(err, report.ErrDestinationExists) || !errors.Is(err, sharedcommand.ErrOperational) {
		t.Fatalf("error = %v, want operational overwrite refusal", err)
	}
	if got, err := os.ReadFile(destination); err != nil || string(got) != "original" {
		t.Fatalf("destination = %q, read error = %v; want original", got, err)
	}

	root = newCompareTestRoot(t, report.ReadFile)
	root.SetArgs([]string{"--output=json", "--output-file", destination, "--force", "compare", before, after})
	if err := root.Execute(); err != nil {
		t.Fatalf("forced replacement: %v", err)
	}
	var value report.Comparison
	if got, err := os.ReadFile(destination); err != nil || json.Unmarshal(got, &value) != nil {
		t.Fatalf("forced output invalid: %v\n%s", err, got)
	}
}

func TestCompareFailOnNewParsesSupportedValuesBeforeReading(t *testing.T) {
	for _, value := range []string{"none", "info", "low", "medium", "high", "critical"} {
		t.Run(value, func(t *testing.T) {
			reads := 0
			root := newCompareTestRoot(t, func(string) (report.Report, error) {
				reads++
				return comparisonReport("https://fixture.test/", nil, "success"), nil
			})
			root.SetArgs([]string{"compare", "--fail-on-new=" + value, "before.json", "after.json"})
			if err := root.Execute(); err != nil {
				t.Fatalf("accepted value %q: %v", value, err)
			}
			if reads != 2 {
				t.Fatalf("reads = %d, want 2", reads)
			}
		})
	}

	reads := 0
	root := newCompareTestRoot(t, func(string) (report.Report, error) {
		reads++
		return report.Report{}, nil
	})
	root.SetArgs([]string{"compare", "--fail-on-new=urgent", "before.json", "after.json"})
	err := root.Execute()
	if err == nil || !errors.Is(err, sharedcommand.ErrOperational) || reads != 0 {
		t.Fatalf("error = %v, reads = %d; want invalid operational error before read", err, reads)
	}
}

func TestCompareFailOnNewOnlyFlagsAddedOrWorsenedFindingsAfterRendering(t *testing.T) {
	finding := func(severity constants.Severity, evidence string) models.VulnResult {
		return models.VulnResult{RuleID: "fixture.finding", Title: "Fixture finding", Severity: severity, Resource: "https://fixture.test/", Evidence: evidence}
	}
	for _, tt := range []struct {
		name       string
		before     []models.VulnResult
		after      []models.VulnResult
		threshold  string
		wantPolicy bool
	}{
		{name: "added at threshold", after: []models.VulnResult{finding(constants.SeverityHigh, "new")}, threshold: "high", wantPolicy: true},
		{name: "worsened at threshold", before: []models.VulnResult{finding(constants.SeverityLow, "old")}, after: []models.VulnResult{finding(constants.SeverityHigh, "new")}, threshold: "high", wantPolicy: true},
		{name: "resolved", before: []models.VulnResult{finding(constants.SeverityCritical, "old")}, threshold: "info"},
		{name: "improved", before: []models.VulnResult{finding(constants.SeverityHigh, "old")}, after: []models.VulnResult{finding(constants.SeverityLow, "new")}, threshold: "info"},
		{name: "evidence only", before: []models.VulnResult{finding(constants.SeverityHigh, "old")}, after: []models.VulnResult{finding(constants.SeverityHigh, "new")}, threshold: "info"},
		{name: "none disables policy", after: []models.VulnResult{finding(constants.SeverityCritical, "new")}, threshold: "none"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			before := writeComparisonReport(t, "before.json", comparisonReport("https://fixture.test/", tt.before, "success"))
			after := writeComparisonReport(t, "after.json", comparisonReport("https://fixture.test/", tt.after, "success"))
			root := newCompareTestRoot(t, report.ReadFile)
			stdout, _ := comparisonBuffers(root)
			root.SetArgs([]string{"--output=json", "compare", "--fail-on-new=" + tt.threshold, before, after})
			err := root.Execute()
			if tt.wantPolicy {
				if !errors.Is(err, sharedcommand.ErrPolicyThreshold) || sharedcommand.ExitCode(err) != 2 {
					t.Fatalf("error = %T %v, want policy exit 2", err, err)
				}
			} else if err != nil {
				t.Fatalf("error = %v, want success", err)
			}
			var value report.Comparison
			if decodeErr := json.Unmarshal(stdout.Bytes(), &value); decodeErr != nil {
				t.Fatalf("comparison was not rendered before policy outcome: %v\n%s", decodeErr, stdout.String())
			}
		})
	}
}

func TestCompareQuietJSONWritesOnlyTheComparisonEnvelope(t *testing.T) {
	before := writeComparisonReport(t, "before.json", comparisonReport("https://fixture.test/", nil, "partial"))
	after := writeComparisonReport(t, "after.json", comparisonReport("https://fixture.test/", nil, "partial"))
	root := newCompareTestRoot(t, report.ReadFile)
	stdout, stderr := comparisonBuffers(root)
	root.SetArgs([]string{"--quiet", "--output=json", "compare", before, after})

	if err := root.Execute(); err != nil {
		t.Fatalf("compare: %v", err)
	}
	if stderr.Len() != 0 {
		t.Fatalf("quiet comparison wrote stderr: %q", stderr.String())
	}
	var value report.Comparison
	if err := json.Unmarshal(stdout.Bytes(), &value); err != nil {
		t.Fatalf("quiet comparison JSON is impure: %v\n%s", err, stdout.String())
	}
	if value.Before.Audit.Status != "partial" || value.After.Audit.Status != "partial" {
		t.Fatalf("partial source metadata was lost: before=%q after=%q", value.Before.Audit.Status, value.After.Audit.Status)
	}
}

func TestCompareRendererFailuresAreOperational(t *testing.T) {
	sentinel := errors.New("comparison renderer failed")
	reader := func(string) (report.Report, error) {
		return comparisonReport("https://fixture.test/", nil, "success"), nil
	}
	newRoot := func(t *testing.T) *cobra.Command {
		t.Helper()
		command := newCompareCommandWithRenderer(reader, func(string) (render.ComparisonRenderer, error) {
			return failingComparisonRenderer{err: sentinel}, nil
		})
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
		root.AddCommand(command)
		return root
	}

	for _, tt := range []struct {
		name string
		args func(t *testing.T) []string
	}{
		{name: "stdout", args: func(t *testing.T) []string { return []string{"compare", "before.json", "after.json"} }},
		{name: "output file", args: func(t *testing.T) []string {
			return []string{"--output=json", "--output-file", filepath.Join(t.TempDir(), "comparison.json"), "compare", "before.json", "after.json"}
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			root := newRoot(t)
			root.SetArgs(tt.args(t))
			err := root.Execute()
			if !errors.Is(err, sentinel) || !errors.Is(err, sharedcommand.ErrOperational) {
				t.Fatalf("error = %T %v, want operational renderer failure", err, err)
			}
		})
	}
}

func TestCompareIsRegisteredAtTopLevelExactlyOnce(t *testing.T) {
	count := 0
	for _, command := range cmd.RootCmd.Commands() {
		if command.Name() == "compare" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("top-level compare registrations = %d, want 1", count)
	}
}

func newCompareTestRoot(t *testing.T, reader reportReader) *cobra.Command {
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
	root.AddCommand(newCompareCommand(reader))
	return root
}

func comparisonBuffers(command *cobra.Command) (*bytes.Buffer, *bytes.Buffer) {
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	command.SetOut(stdout)
	command.SetErr(stderr)
	return stdout, stderr
}

func comparisonReport(target string, findings []models.VulnResult, status string) report.Report {
	normalizedFindings := make([]models.VulnResult, len(findings))
	copy(normalizedFindings, findings)
	for index := range normalizedFindings {
		// Stored schema-v1 snapshots require these fields even when a finding
		// has no useful evidence or remediation. Keep fixtures readable by the
		// same strict reader used in production.
		if normalizedFindings[index].Evidence == "" {
			normalizedFindings[index].Evidence = "fixture evidence"
		}
		if normalizedFindings[index].Remediation == "" {
			normalizedFindings[index].Remediation = "fixture remediation"
		}
	}
	return report.NewReport(
		report.ToolInfo{Name: "raxuiscli", Version: "test", Commit: "test", GoVersion: "go-test", Platform: "test/test"},
		report.AuditInfo{Kind: "web", Target: target, StartedAt: time.Date(2026, time.September, 4, 12, 0, 0, 0, time.UTC), Status: status},
		normalizedFindings,
		nil,
		nil,
	)
}

func writeComparisonReport(t *testing.T, name string, value report.Report) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return writeComparisonBytes(t, name, encoded)
}

func writeComparisonBytes(t *testing.T, name string, contents []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

type failingComparisonRenderer struct{ err error }

func (renderer failingComparisonRenderer) RenderComparison(_ io.Writer, _ report.Comparison) error {
	return renderer.err
}
