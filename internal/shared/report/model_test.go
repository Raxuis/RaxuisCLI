package report

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"raxuiscli/internal/shared/constants"
	"raxuiscli/internal/shared/models"
)

func TestNewReportNormalizesPublicContract(t *testing.T) {
	startedAt := time.Date(2026, time.January, 2, 4, 4, 5, 0, time.FixedZone("CEST", 3600))
	resource := "HTTPS://alice:password@Example.COM:443/a/../account?session=super-secret&empty=#ignored"

	first := models.VulnResult{
		RuleID:      "http.header.content-security-policy",
		Title:       "A changed display title must not change the ID",
		Severity:    constants.SeverityHigh,
		Status:      "open",
		Resource:    resource,
		Evidence:    "Authorization: Bearer evidence-secret",
		Remediation: "Set Content-Security-Policy.",
	}
	second := models.VulnResult{
		RuleID:   "tls.protocol.deprecated",
		Severity: constants.SeverityMedium,
		Status:   "open",
		URL:      "https://EXAMPLE.com:443/",
	}

	report := NewReport(
		ToolInfo{Name: "raxuiscli", Version: "1.2.3", Commit: "abc123", GoVersion: "go1.26", Platform: "linux/amd64"},
		AuditInfo{Kind: "web", Target: resource, StartedAt: startedAt, Duration: 1250 * time.Millisecond, Status: "complete"},
		[]models.VulnResult{second, first},
		[]Observation{{Key: "http.status", Value: "200"}, {Key: "tls.version", Value: "TLS 1.3"}},
		[]ReportError{{Code: "tls", Message: "https://bob:another-secret@example.com/?token=token-secret"}},
	)

	const wantResource = "https://example.com/account?empty=<redacted>&session=<redacted>"
	if report.SchemaVersion != SchemaVersion {
		t.Fatalf("SchemaVersion = %d, want %d", report.SchemaVersion, SchemaVersion)
	}
	if report.Audit.Target != wantResource {
		t.Errorf("audit target = %q, want %q", report.Audit.Target, wantResource)
	}
	if report.Audit.StartedAt.Location() != time.UTC || report.Audit.StartedAt.Format(time.RFC3339) != "2026-01-02T03:04:05Z" {
		t.Errorf("started at = %s (%s), want RFC3339 UTC", report.Audit.StartedAt.Format(time.RFC3339Nano), report.Audit.StartedAt.Location())
	}
	if report.Audit.ID == "" {
		t.Error("audit ID must be populated")
	}

	if len(report.Findings) != 2 {
		t.Fatalf("findings length = %d, want 2", len(report.Findings))
	}
	for i := 1; i < len(report.Findings); i++ {
		if report.Findings[i-1].ID > report.Findings[i].ID {
			t.Errorf("findings are not sorted by stable ID: %q before %q", report.Findings[i-1].ID, report.Findings[i].ID)
		}
	}

	var normalized models.VulnResult
	for _, finding := range report.Findings {
		if finding.RuleID == first.RuleID {
			normalized = finding
			break
		}
	}
	if normalized.Resource != wantResource || normalized.URL != wantResource {
		t.Errorf("finding resource = %q / URL = %q, want %q", normalized.Resource, normalized.URL, wantResource)
	}
	if got, want := normalized.ID, FindingID(first.RuleID, wantResource); got != want {
		t.Errorf("finding ID = %q, want %q", got, want)
	}
	if strings.Contains(normalized.Evidence, "evidence-secret") {
		t.Errorf("finding evidence was not redacted: %q", normalized.Evidence)
	}

	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("marshal report: %v", err)
	}
	if !strings.Contains(string(encoded), `"started_at":"2026-01-02T03:04:05Z"`) {
		t.Errorf("report JSON timestamp is not RFC3339 UTC: %s", encoded)
	}
	for _, secret := range []string{"password", "super-secret", "evidence-secret", "another-secret", "token-secret"} {
		if strings.Contains(string(encoded), secret) {
			t.Errorf("report JSON exposes secret %q: %s", secret, encoded)
		}
	}
}

func TestFindingIDUsesRuleAndCanonicalResourceOnly(t *testing.T) {
	resource := "https://example.com/path?token=value"
	first := FindingID("http.header.hsts", resource)
	second := FindingID("http.header.hsts", "HTTPS://EXAMPLE.COM:443/path?token=other")
	changedRule := FindingID("http.header.csp", resource)

	if first != second {
		t.Errorf("IDs differ for equivalent canonical resources: %q != %q", first, second)
	}
	if first == changedRule {
		t.Errorf("ID %q did not change when the rule ID changed", first)
	}
}

func TestNormalizeFindingBackfillsLegacyVulnResultFields(t *testing.T) {
	legacy := models.VulnResult{
		Type: constants.VulnHeaders,
		URL:  "HTTPS://Example.COM:443/login?session=legacy-secret",
	}

	got := NormalizeFinding(legacy)
	const wantRuleID = "legacy.security-headers"
	const wantResource = "https://example.com/login?session=<redacted>"
	if got.RuleID != wantRuleID {
		t.Errorf("RuleID = %q, want %q", got.RuleID, wantRuleID)
	}
	if got.Resource != wantResource {
		t.Errorf("Resource = %q, want %q", got.Resource, wantResource)
	}
	if got.ID != FindingID(wantRuleID, wantResource) {
		t.Errorf("ID = %q, want ID derived from the legacy type and URL", got.ID)
	}
	if got.Status != "open" {
		t.Errorf("Status = %q, want default open", got.Status)
	}
}

func TestNewReportTotallyOrdersEquivalentFindingIdentities(t *testing.T) {
	base := models.VulnResult{
		RuleID:   "http.header.example",
		Resource: "https://example.com/",
		Evidence: "same evidence",
	}

	for _, test := range []struct {
		name string
		set  func(*models.VulnResult, string)
		get  func(models.VulnResult) string
	}{
		{"type", func(f *models.VulnResult, value string) { f.Type = constants.VulnType(value) }, func(f models.VulnResult) string { return string(f.Type) }},
		{"parameter", func(f *models.VulnResult, value string) { f.Parameter = value }, func(f models.VulnResult) string { return f.Parameter }},
		{"payload", func(f *models.VulnResult, value string) { f.Payload = value }, func(f models.VulnResult) string { return f.Payload }},
		{"description", func(f *models.VulnResult, value string) { f.Description = value }, func(f models.VulnResult) string { return f.Description }},
		{"remediation", func(f *models.VulnResult, value string) { f.Remediation = value }, func(f models.VulnResult) string { return f.Remediation }},
	} {
		t.Run(test.name, func(t *testing.T) {
			first, second := base, base
			test.set(&first, "alpha")
			test.set(&second, "beta")

			report := NewReport(ToolInfo{}, AuditInfo{}, []models.VulnResult{second, first}, nil, nil)
			if got := test.get(report.Findings[0]); got != "alpha" {
				t.Errorf("first finding %s = %q, want alpha after deterministic tie-breaking", test.name, got)
			}
		})
	}
}
