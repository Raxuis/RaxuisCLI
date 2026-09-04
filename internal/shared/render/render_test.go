package render

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"raxuiscli/internal/shared/constants"
	"raxuiscli/internal/shared/models"
	"raxuiscli/internal/shared/report"
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
