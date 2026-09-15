package render

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Raxuis/RaxuisCLI/internal/shared/constants"
	"github.com/Raxuis/RaxuisCLI/internal/shared/models"
	"github.com/Raxuis/RaxuisCLI/internal/shared/report"
)

func TestRenderGolden(t *testing.T) {
	t.Parallel()

	value := fixedReport()
	for _, test := range []struct {
		name     string
		renderer Renderer
		golden   string
	}{
		{name: "text", renderer: NewTextRenderer(), golden: "report.txt"},
		{name: "json", renderer: NewJSONRenderer(), golden: "report.json"},
		{name: "html", renderer: NewHTMLRenderer(), golden: "report.html"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var got bytes.Buffer
			if err := test.renderer.Render(&got, value); err != nil {
				t.Fatalf("render: %v", err)
			}

			goldenPath := filepath.Join("testdata", test.golden)
			if os.Getenv("UPDATE_GOLDEN") != "" {
				if err := os.WriteFile(goldenPath, got.Bytes(), 0o600); err != nil {
					t.Fatalf("update golden: %v", err)
				}
			}
			want, err := os.ReadFile(goldenPath)
			if err != nil {
				t.Fatalf("read golden: %v", err)
			}
			if got.String() != string(want) {
				t.Errorf("rendered output differs from %s\nwant:\n%s\ngot:\n%s", test.golden, want, got.String())
			}
		})
	}
}

func TestJSONRendererWritesOnlyEnvelope(t *testing.T) {
	var got bytes.Buffer
	if err := NewJSONRenderer().Render(&got, fixedReport()); err != nil {
		t.Fatalf("render: %v", err)
	}
	if bytes.Contains(got.Bytes(), []byte("Created by Raxuis")) {
		t.Fatalf("JSON includes decorative content: %s", got.Bytes())
	}
	if !bytes.HasPrefix(got.Bytes(), []byte("{\n  \"schema_version\": 1,")) {
		t.Fatalf("JSON is not deterministically indented: %s", got.Bytes())
	}
}

func TestHTMLRendererIsSelfContainedAndSafe(t *testing.T) {
	value := fixedReport()
	value.Findings[0].Title = `<script>alert("xss")</script>`
	var got bytes.Buffer
	if err := NewHTMLRenderer().Render(&got, value); err != nil {
		t.Fatalf("render: %v", err)
	}

	body := got.String()
	for _, forbidden := range []string{"<script", "src=\"http"} {
		if bytes.Contains([]byte(body), []byte(forbidden)) {
			t.Errorf("HTML contains forbidden %q: %s", forbidden, body)
		}
	}
	if !bytes.Contains([]byte(body), []byte(`href="https://github.com/raxuis"`)) ||
		!bytes.Contains([]byte(body), []byte("Created by Raxuis ·")) ||
		!bytes.Contains([]byte(body), []byte("github.com/raxuis")) {
		t.Errorf("HTML does not include visible clickable Raxuis credit: %s", body)
	}
	if !bytes.Contains([]byte(body), []byte("&lt;script&gt;alert(&#34;xss&#34;)&lt;/script&gt;")) {
		t.Errorf("finding title was not escaped: %s", body)
	}
}

func TestRenderComparisonGolden(t *testing.T) {
	comparison := fixedComparison(t)
	for _, test := range []struct {
		name     string
		renderer ComparisonRenderer
		golden   string
	}{
		{name: "text", renderer: NewTextRenderer().(ComparisonRenderer), golden: "comparison.txt"},
		{name: "json", renderer: NewJSONRenderer().(ComparisonRenderer), golden: "comparison.json"},
		{name: "html", renderer: NewHTMLRenderer().(ComparisonRenderer), golden: "comparison.html"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var got bytes.Buffer
			if err := test.renderer.RenderComparison(&got, comparison); err != nil {
				t.Fatalf("render comparison: %v", err)
			}

			goldenPath := filepath.Join("testdata", test.golden)
			if os.Getenv("UPDATE_GOLDEN") != "" {
				if err := os.WriteFile(goldenPath, got.Bytes(), 0o600); err != nil {
					t.Fatalf("update golden: %v", err)
				}
			}
			want, err := os.ReadFile(goldenPath)
			if err != nil {
				t.Fatalf("read golden: %v", err)
			}
			if got.String() != string(want) {
				t.Errorf("rendered comparison differs from %s\nwant:\n%s\ngot:\n%s", test.golden, want, got.String())
			}
		})
	}
}

func TestComparisonRenderersEmphasizeRegressions(t *testing.T) {
	comparison := fixedComparison(t)
	for _, renderer := range []ComparisonRenderer{
		NewTextRenderer().(ComparisonRenderer),
		NewHTMLRenderer().(ComparisonRenderer),
	} {
		var got bytes.Buffer
		if err := renderer.RenderComparison(&got, comparison); err != nil {
			t.Fatalf("render comparison: %v", err)
		}
		body := got.String()
		regressions, resolutions := bytes.Index([]byte(body), []byte("Regressions")), bytes.Index([]byte(body), []byte("Resolutions"))
		if regressions < 0 || resolutions < 0 || regressions >= resolutions {
			t.Errorf("comparison does not place regressions before resolutions: %s", body)
		}
	}
	var htmlOutput bytes.Buffer
	if err := NewHTMLRenderer().(ComparisonRenderer).RenderComparison(&htmlOutput, comparison); err != nil {
		t.Fatalf("render HTML comparison: %v", err)
	}
	for _, forbidden := range []string{"<script", "src=\"http"} {
		if bytes.Contains(htmlOutput.Bytes(), []byte(forbidden)) {
			t.Errorf("HTML comparison contains forbidden %q: %s", forbidden, htmlOutput.Bytes())
		}
	}
	if !bytes.Contains(htmlOutput.Bytes(), []byte(`href="https://github.com/raxuis"`)) || !bytes.Contains(htmlOutput.Bytes(), []byte("Created by Raxuis ·")) {
		t.Errorf("HTML comparison does not retain Raxuis credit: %s", htmlOutput.Bytes())
	}

	var jsonOutput bytes.Buffer
	if err := NewJSONRenderer().(ComparisonRenderer).RenderComparison(&jsonOutput, comparison); err != nil {
		t.Fatalf("render JSON comparison: %v", err)
	}
	if bytes.Contains(jsonOutput.Bytes(), []byte("RaxuisCLI Audit Report")) || !bytes.HasPrefix(jsonOutput.Bytes(), []byte("{\n  \"schema_version\": 1,")) {
		t.Errorf("JSON comparison is not only its envelope: %s", jsonOutput.Bytes())
	}
}

func TestComparisonRenderersShowCooccurringFindingChanges(t *testing.T) {
	comparison := fixedComparison(t)
	for _, renderer := range []ComparisonRenderer{
		NewTextRenderer().(ComparisonRenderer),
		NewHTMLRenderer().(ComparisonRenderer),
	} {
		var got bytes.Buffer
		if err := renderer.RenderComparison(&got, comparison); err != nil {
			t.Fatalf("render comparison: %v", err)
		}
		body := got.String()
		for _, want := range []string{
			"WORSENED", "Evidence changed",
			"IMPROVED", "Title changed", "Status changed", "Remediation changed",
		} {
			if !strings.Contains(body, want) {
				t.Errorf("comparison omits %q from severity change: %s", want, body)
			}
		}
	}
}

func fixedReport() report.Report {
	return report.NewReport(
		report.ToolInfo{
			Name: "raxuiscli", Version: "1.2.3", Commit: "abc1234", GoVersion: "go1.25.13", Platform: "linux/amd64",
		},
		report.AuditInfo{
			ID: "audit-demo-001", Kind: "web", Target: "https://example.com/login", StartedAt: time.Date(2026, time.September, 4, 12, 30, 0, 0, time.UTC), Duration: 1250 * time.Millisecond, Status: "partial",
		},
		[]models.VulnResult{
			{RuleID: "http.header.hsts", Title: "HSTS header is missing", Severity: constants.SeverityHigh, Status: "open", Resource: "https://example.com/login", Evidence: "Strict-Transport-Security response header was absent.", Remediation: "Set Strict-Transport-Security with an appropriate max-age."},
			{RuleID: "tls.protocol.deprecated", Title: "Deprecated TLS protocol accepted", Severity: constants.SeverityMedium, Status: "open", Resource: "https://example.com/login", Evidence: "TLS 1.0 was accepted during the handshake.", Remediation: "Disable TLS 1.0 and TLS 1.1."},
		},
		[]report.Observation{{Key: "http.status", Value: "200"}, {Key: "tls.version", Value: "TLS 1.3"}},
		[]report.ReportError{{Code: "tls.chain", Message: "certificate chain could not be fully verified"}},
	)
}

func fixedComparison(t *testing.T) report.Comparison {
	t.Helper()
	before := fixedReport()
	before.Findings = append(before.Findings,
		models.VulnResult{RuleID: "http.header.x-frame-options", Title: "X-Frame-Options missing", Severity: constants.SeverityLow, Status: "open", Resource: "https://example.com/login", Evidence: "header missing", Remediation: "Set X-Frame-Options."},
	)
	before.Observations = append(before.Observations, report.Observation{Key: "server", Value: "before"}, report.Observation{Key: "removed", Value: "gone"})
	after := fixedReport()
	for index := range after.Findings {
		switch after.Findings[index].RuleID {
		case "tls.protocol.deprecated":
			after.Findings[index].Severity = constants.SeverityCritical
			after.Findings[index].Evidence = "TLS 1.0 was accepted during the handshake after retry."
		case "http.header.hsts":
			after.Findings[index].Severity = constants.SeverityLow
			after.Findings[index].Title = "HSTS header remains absent"
			after.Findings[index].Status = "confirmed"
			after.Findings[index].Evidence = "Strict-Transport-Security header was absent after retry."
			after.Findings[index].Remediation = "Set Strict-Transport-Security with a reviewed max-age."
		}
	}
	after.Findings = append(after.Findings,
		models.VulnResult{RuleID: "http.header.content-security-policy", Title: "CSP header is missing", Severity: constants.SeverityHigh, Status: "open", Resource: "https://example.com/login", Evidence: "Content-Security-Policy response header was absent.", Remediation: "Set Content-Security-Policy."},
	)
	after.Observations = append(after.Observations, report.Observation{Key: "server", Value: "after"}, report.Observation{Key: "added", Value: "new"})
	comparison, err := report.Compare(before, after, false)
	if err != nil {
		t.Fatalf("Compare: %v", err)
	}
	return comparison
}
