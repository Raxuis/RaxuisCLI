package report

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"raxuiscli/internal/shared/constants"
)

func TestReadNormalizesSchemaV1Deterministically(t *testing.T) {
	report, err := ReadFile(filepath.Join("testdata", "valid-v1.json"))
	if err != nil {
		t.Fatalf("ReadFile returned error: %v", err)
	}

	if got, want := report.SchemaVersion, SchemaVersion; got != want {
		t.Fatalf("schema version = %d, want %d", got, want)
	}
	if got, want := report.Audit.Target, "https://example.test/path?token=<redacted>"; got != want {
		t.Errorf("target = %q, want %q", got, want)
	}
	if got, want := report.Audit.StartedAt, time.Date(2026, 9, 4, 10, 30, 0, 0, time.UTC); !got.Equal(want) || got.Location() != time.UTC {
		t.Errorf("started_at = %v (%v), want %v UTC", got, got.Location(), want)
	}
	if len(report.Findings) != 2 {
		t.Fatalf("findings length = %d, want 2", len(report.Findings))
	}
	for i, finding := range report.Findings {
		if finding.ID != FindingID(finding.RuleID, finding.Resource) {
			t.Errorf("finding %d ID was not normalized: %q", i, finding.ID)
		}
		if strings.Contains(finding.Resource, "secret") || strings.Contains(finding.Evidence, "secret") {
			t.Errorf("finding %d retained a secret: %#v", i, finding)
		}
	}
	if report.Findings[0].ID > report.Findings[1].ID {
		t.Errorf("findings not sorted by normalized identity: %#v", report.Findings)
	}
	if got, want := report.Audit.ID, AuditID(report.Audit.Kind, report.Audit.Target, report.Audit.StartedAt); got != want {
		t.Errorf("audit ID = %q, want normalized ID %q", got, want)
	}
	if got := report.Observations; len(got) != 2 || got[0].Key != "http.status" || got[1].Key != "tls.version" {
		t.Errorf("observations not normalized: %#v", got)
	}
	if got := report.Errors; len(got) != 2 || got[0].Code != "a.collect" || got[1].Code != "z.collect" || strings.Contains(got[1].Message, "error-secret") {
		t.Errorf("report errors not sorted/redacted: %#v", got)
	}
}

func TestReadPermitsUnknownAdditiveFields(t *testing.T) {
	got, err := ReadFile(filepath.Join("testdata", "unknown-fields.json"))
	if err != nil {
		t.Fatalf("ReadFile rejected additive fields: %v", err)
	}
	if got.Audit.Kind != "web" || len(got.Findings) != 1 {
		t.Fatalf("decoded report = %#v", got)
	}
}

func TestReadRejectsUnsupportedAndMalformedDocuments(t *testing.T) {
	tests := []struct {
		name string
		file string
		is   error
	}{
		{name: "unsupported schema", file: "unsupported-v2.json", is: ErrUnsupportedSchema},
		{name: "truncated JSON", file: "truncated.json", is: ErrInvalidReport},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ReadFile(filepath.Join("testdata", tt.file))
			if !errors.Is(err, tt.is) {
				t.Fatalf("ReadFile error = %v, want errors.Is(_, %v)", err, tt.is)
			}
		})
	}

	_, err := Read(strings.NewReader(validInlineReport + ` {"extra":true}`))
	if !errors.Is(err, ErrInvalidReport) {
		t.Fatalf("trailing document error = %v, want ErrInvalidReport", err)
	}
}

func TestReadRejectsOversizedDocuments(t *testing.T) {
	oversized := validInlineReport + strings.Repeat(" ", int(maxReportBytes)-len(validInlineReport)+1)
	_, err := Read(strings.NewReader(oversized))
	if !errors.Is(err, ErrInvalidReport) || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("Read oversized error = %v, want ErrInvalidReport size limit", err)
	}
}

func TestReadRejectsDuplicateKeysRecursively(t *testing.T) {
	for _, fixture := range []string{"duplicate-root.json", "duplicate-nested.json"} {
		t.Run(fixture, func(t *testing.T) {
			_, err := ReadFile(filepath.Join("testdata", fixture))
			if !errors.Is(err, ErrInvalidReport) || !strings.Contains(err.Error(), "duplicate") {
				t.Fatalf("ReadFile error = %v, want duplicate-key ErrInvalidReport", err)
			}
		})
	}
}

func TestReadCanonicalizesSeverityForThresholdMatching(t *testing.T) {
	input := strings.Replace(validInlineReport, `"severity":"LOW"`, `"severity":"low"`, 1)
	got, err := Read(strings.NewReader(input))
	if err != nil {
		t.Fatalf("Read returned error: %v", err)
	}
	if severity := got.Findings[0].Severity; severity != constants.SeverityLow || severity.Rank() != constants.SeverityLow.Rank() {
		t.Fatalf("severity = %q rank %d, want canonical LOW rank %d", severity, severity.Rank(), constants.SeverityLow.Rank())
	}
}

func TestReadRequiresPublicContractFields(t *testing.T) {
	tests := []struct {
		name string
		json string
		want string
	}{
		{name: "schema", json: strings.Replace(validInlineReport, `"schema_version":1,`, "", 1), want: "schema_version"},
		{name: "tool", json: strings.Replace(validInlineReport, `"tool":{"name":"raxuiscli","version":"1.0.0","commit":"abc","go_version":"go1.25","platform":"linux/amd64"},`, "", 1), want: "tool"},
		{name: "audit target", json: strings.Replace(validInlineReport, `"target":"https://example.test/",`, "", 1), want: "audit.target"},
		{name: "finding rule", json: strings.Replace(validInlineReport, `"rule_id":"http.header.example",`, "", 1), want: "findings[0].rule_id"},
		{name: "findings array", json: strings.Replace(validInlineReport, `"findings":[{"id":"stale","rule_id":"http.header.example","title":"Example","severity":"LOW","status":"open","resource":"https://example.test/","evidence":"example","remediation":"fix it"}],`, "", 1), want: "findings"},
		{name: "null observations", json: strings.Replace(validInlineReport, `"observations":[]`, `"observations":null`, 1), want: "observations"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Read(strings.NewReader(tt.json))
			if !errors.Is(err, ErrInvalidReport) || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Read error = %v, want ErrInvalidReport mentioning %q", err, tt.want)
			}
		})
	}
}

func TestReadFileWrapsFilesystemErrors(t *testing.T) {
	_, err := ReadFile(filepath.Join(t.TempDir(), "missing.json"))
	if err == nil || !errors.Is(err, os.ErrNotExist) || !strings.Contains(err.Error(), "read report") {
		t.Fatalf("ReadFile error = %v, want contextual os.ErrNotExist", err)
	}
}

func TestValidateComparisonInputs(t *testing.T) {
	base := Report{Audit: AuditInfo{Kind: "web", Target: "HTTPS://EXAMPLE.test:443/path?token=one"}}
	equivalent := Report{Audit: AuditInfo{Kind: "web", Target: "https://example.test/path?token=two"}}
	otherTarget := Report{Audit: AuditInfo{Kind: "web", Target: "https://other.test/"}}
	otherKind := Report{Audit: AuditInfo{Kind: "docs", Target: "https://example.test/path?token=two"}}

	if err := ValidateComparisonInputs(base, equivalent, false); err != nil {
		t.Fatalf("equivalent canonical targets rejected: %v", err)
	}
	if err := ValidateComparisonInputs(base, otherTarget, false); !errors.Is(err, ErrTargetMismatch) {
		t.Fatalf("target mismatch error = %v, want ErrTargetMismatch", err)
	}
	if err := ValidateComparisonInputs(base, otherTarget, true); err != nil {
		t.Fatalf("allowed target mismatch rejected: %v", err)
	}
	if err := ValidateComparisonInputs(base, otherKind, true); !errors.Is(err, ErrKindMismatch) {
		t.Fatalf("kind mismatch error = %v, want ErrKindMismatch", err)
	}
}

const validInlineReport = `{"schema_version":1,"tool":{"name":"raxuiscli","version":"1.0.0","commit":"abc","go_version":"go1.25","platform":"linux/amd64"},"audit":{"id":"stale","kind":"web","target":"https://example.test/","started_at":"2026-09-04T12:30:00Z","duration":0,"status":"success"},"findings":[{"id":"stale","rule_id":"http.header.example","title":"Example","severity":"LOW","status":"open","resource":"https://example.test/","evidence":"example","remediation":"fix it"}],"observations":[],"errors":[]}`
