package dns

import (
	"bytes"
	"testing"
	"time"

	"github.com/Raxuis/RaxuisCLI/internal/shared/constants"
	"github.com/Raxuis/RaxuisCLI/internal/shared/render"
	"github.com/Raxuis/RaxuisCLI/internal/shared/report"
)

func TestSPFFindings(t *testing.T) {
	cases := []struct {
		spf      string
		wantID   string
		wantSev  constants.Severity
		wantNone bool
	}{
		{"", "dns.spf-missing", constants.SeverityMedium, false},
		{"v=spf1 +all", "dns.spf-permissive", constants.SeverityHigh, false},
		{"v=spf1 ?all", "dns.spf-neutral", constants.SeverityLow, false},
		{"v=spf1 include:x", "dns.spf-no-all", constants.SeverityLow, false},
		{"v=spf1 include:_spf.google.com -all", "", constants.SeverityNone, true},
	}
	for _, c := range cases {
		got := spfFindings("example.com", c.spf)
		if c.wantNone {
			if len(got) != 0 {
				t.Errorf("spf %q: expected no finding, got %+v", c.spf, got)
			}
			continue
		}
		if len(got) != 1 || got[0].RuleID != c.wantID || got[0].Severity != c.wantSev {
			t.Errorf("spf %q: got %+v, want %s/%s", c.spf, got, c.wantID, c.wantSev)
		}
	}
}

func TestDMARCFindings(t *testing.T) {
	if got := dmarcFindings("example.com", ""); len(got) != 1 || got[0].RuleID != "dns.dmarc-missing" {
		t.Errorf("missing dmarc: got %+v", got)
	}
	if got := dmarcFindings("example.com", "v=DMARC1; p=none"); len(got) != 1 || got[0].Severity != constants.SeverityLow {
		t.Errorf("p=none: got %+v", got)
	}
	if got := dmarcFindings("example.com", "v=DMARC1; p=reject"); len(got) != 0 {
		t.Errorf("p=reject should have no finding, got %+v", got)
	}
}

func TestFindingsAreReportValid(t *testing.T) {
	all := append(spfFindings("example.com", ""), dmarcFindings("example.com", "")...)
	rep := report.NewReport(
		report.ToolInfo{Name: "raxuiscli", Version: "test", Commit: "deadbeef", GoVersion: "go1", Platform: "test/test"},
		report.AuditInfo{Kind: "dns", Target: "example.com", StartedAt: time.Now(), Status: "complete"},
		all,
		observations([]string{"ns1.example.com."}, []string{"10 mx.example.com."}, []string{"1.2.3.4"}, "", ""),
		nil,
	)

	var buf bytes.Buffer
	if err := render.NewJSONRenderer().Render(&buf, rep); err != nil {
		t.Fatalf("render: %v", err)
	}
	if _, err := report.Read(&buf); err != nil {
		t.Fatalf("emitted DNS report failed schema validation: %v", err)
	}
}

func TestFirstWithPrefix(t *testing.T) {
	records := []string{"some other txt", "V=SPF1 -all", "google-site-verification=x"}
	if got := firstWithPrefix(records, "v=spf1"); got != "V=SPF1 -all" {
		t.Errorf("firstWithPrefix = %q", got)
	}
	if got := firstWithPrefix(records, "v=dmarc1"); got != "" {
		t.Errorf("expected empty, got %q", got)
	}
}

func TestSlug(t *testing.T) {
	if got := slug("NS1.Example.COM."); got != "ns1-example-com" {
		t.Errorf("slug = %q", got)
	}
}
