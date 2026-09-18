package tls

import (
	"bytes"
	"testing"
	"time"

	"github.com/Raxuis/RaxuisCLI/internal/crypto/tlsscan"
	"github.com/Raxuis/RaxuisCLI/internal/shared/render"
	"github.com/Raxuis/RaxuisCLI/internal/shared/report"
)

func sampleResult() *tlsscan.Result {
	return &tlsscan.Result{
		Host: "example.com",
		Port: 443,
		Protocols: []tlsscan.ProtocolResult{
			{Name: "TLS 1.0", Supported: true},
			{Name: "TLS 1.2", Supported: true},
			{Name: "TLS 1.3", Supported: false},
		},
		Certificate: &tlsscan.CertSummary{
			Subject:            "CN=example.com",
			Issuer:             "CN=Example CA",
			NotBefore:          time.Now().Add(-time.Hour),
			NotAfter:           time.Now().Add(720 * time.Hour),
			SignatureAlgorithm: "ECDSA-SHA256",
			KeyType:            "ECDSA",
			KeyBits:            256,
			HostnameValid:      true,
		},
		Findings: []tlsscan.Finding{
			{ID: "protocol-tls10", Title: "TLS 1.0 enabled", Severity: tlsscan.SeverityMedium, Detail: "deprecated"},
			{ID: "cipher-weak", Title: "Weak cipher accepted: TLS_RSA_WITH_AES_128_CBC_SHA", Severity: tlsscan.SeverityLow, Detail: "cbc"},
			{ID: "cipher-weak", Title: "Weak cipher accepted: TLS_RSA_WITH_AES_256_CBC_SHA", Severity: tlsscan.SeverityLow, Detail: "cbc"},
		},
	}
}

func TestToFindingsUniqueAndComplete(t *testing.T) {
	findings := toFindings(sampleResult(), "example.com:443")
	if len(findings) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(findings))
	}
	seen := map[string]bool{}
	for _, f := range findings {
		if f.RuleID == "" || f.Evidence == "" || f.Remediation == "" {
			t.Errorf("finding %q missing a required field: %+v", f.Title, f)
		}
		if seen[f.RuleID] {
			t.Errorf("duplicate RuleID %q would collide in a report", f.RuleID)
		}
		seen[f.RuleID] = true
	}
}

// TestReportRoundTrips proves an emitted TLS report passes the reader's schema
// validation, i.e. it is persistable and comparable with `compare`.
func TestReportRoundTrips(t *testing.T) {
	result := sampleResult()
	rep := report.NewReport(
		report.ToolInfo{Name: "raxuiscli", Version: "test", Commit: "deadbeef", GoVersion: "go1", Platform: "test/test"},
		report.AuditInfo{Kind: "tls", Target: "example.com:443", StartedAt: time.Now(), Status: "complete"},
		toFindings(result, "example.com:443"),
		toObservations(result),
		nil,
	)

	var buf bytes.Buffer
	if err := render.NewJSONRenderer().Render(&buf, rep); err != nil {
		t.Fatalf("render report: %v", err)
	}
	if _, err := report.Read(&buf); err != nil {
		t.Fatalf("emitted report failed schema validation (not comparable): %v", err)
	}
}

func TestSlug(t *testing.T) {
	got := slug("Weak cipher: TLS_RSA_WITH_AES_128_CBC_SHA")
	want := "weak-cipher-tls-rsa-with-aes-128-cbc-sha"
	if got != want {
		t.Errorf("slug = %q, want %q", got, want)
	}
}

func TestRemediationFor(t *testing.T) {
	if remediationFor("cipher-rc4") == "" {
		t.Error("expected mapped remediation for cipher-rc4")
	}
	if remediationFor("nonexistent") == "" {
		t.Error("expected a non-empty fallback remediation")
	}
}

func TestSplitTarget(t *testing.T) {
	if h, p := splitTarget("example.com:8443", 443); h != "example.com" || p != 8443 {
		t.Errorf("splitTarget host:port = %s:%d", h, p)
	}
	if h, p := splitTarget("example.com", 443); h != "example.com" || p != 443 {
		t.Errorf("splitTarget default = %s:%d", h, p)
	}
}
