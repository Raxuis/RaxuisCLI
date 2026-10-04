package dns

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	netdns "github.com/Raxuis/RaxuisCLI/internal/network/dns"

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

func TestAuditLookupFailureDoesNotInventMissingPolicies(t *testing.T) {
	query := func(context.Context, string, netdns.RecordType, string, int) ([]string, error) {
		return nil, fmt.Errorf("resolver unavailable")
	}
	got, err := auditWithLookup(context.Background(), "example.test", Options{SkipAXFR: true}, query)
	if err != nil {
		t.Fatal(err)
	}
	if got.Audit.Status != "partial" || len(got.Errors) != 5 || len(got.Findings) != 0 {
		t.Fatalf("report = %+v", got)
	}
	for _, obs := range got.Observations {
		if (obs.Key == "dns.spf" || obs.Key == "dns.dmarc") && obs.Value != "unknown" {
			t.Fatalf("observation = %+v", obs)
		}
	}
}

func TestAuditRejectsInvalidDomainBeforeLookup(t *testing.T) {
	for _, target := range []string{"", "https://example.com", "127.0.0.1", "a..test", "-a.test", "a.test/path"} {
		t.Run(target, func(t *testing.T) {
			query := func(context.Context, string, netdns.RecordType, string, int) ([]string, error) {
				t.Fatal("invalid target queried")
				return nil, nil
			}
			if _, err := auditWithLookup(context.Background(), target, Options{}, query); err == nil {
				t.Fatal("expected invalid target error")
			}
		})
	}
}

func TestAuditPartialLookupRetainsOtherFindings(t *testing.T) {
	query := func(_ context.Context, name string, kind netdns.RecordType, _ string, _ int) ([]string, error) {
		if kind == netdns.TypeNS {
			return []string{"ns.example.test."}, nil
		}
		if name == "_dmarc.example.test" {
			return nil, fmt.Errorf("timeout")
		}
		if kind == netdns.TypeTXT {
			return []string{"v=spf1 +all"}, nil
		}
		return nil, nil
	}
	got, err := auditWithLookup(context.Background(), "example.test", Options{SkipAXFR: true}, query)
	if err != nil {
		t.Fatal(err)
	}
	if got.Audit.Status != "partial" || len(got.Findings) != 1 || got.Findings[0].RuleID != "dns.spf-permissive" {
		t.Fatalf("report = %+v", got)
	}
}

func TestPolicyParsingUsesCompleteMechanismsAndTags(t *testing.T) {
	for _, spf := range []string{"v=spf1 all", "v=spf1 ip4:192.0.2.1 all -all"} {
		if got := spfFindings("example.test", spf); len(got) != 1 || got[0].RuleID != "dns.spf-permissive" {
			t.Fatalf("%s: %+v", spf, got)
		}
	}
	if got := spfFindings("example.test", "v=spf1 include:contains+all.example -all"); len(got) != 0 {
		t.Fatalf("substring false positive: %+v", got)
	}
	for _, record := range []string{"v=DMARC1; sp=none; p=reject", "v=DMARC1; p = quarantine"} {
		if got := dmarcFindings("example.test", record); len(got) != 0 {
			t.Fatalf("%s: %+v", record, got)
		}
	}
	if got := dmarcFindings("example.test", "v=DMARC1; p=bogus"); len(got) != 1 || got[0].RuleID != "dns.dmarc-invalid-policy" {
		t.Fatalf("invalid policy: %+v", got)
	}
	if got := firstWithPrefix([]string{"v=spf10 +all"}, "v=spf1"); got != "" {
		t.Fatal("accepted wrong version")
	}
}

func TestAuditRejectsMultipleAuthenticationRecords(t *testing.T) {
	query := func(_ context.Context, name string, kind netdns.RecordType, _ string, _ int) ([]string, error) {
		if kind != netdns.TypeTXT {
			return nil, nil
		}
		if strings.HasPrefix(name, "_dmarc.") {
			return []string{"v=DMARC1; p=reject", "v=DMARC1; p=none"}, nil
		}
		return []string{"v=spf1 -all", "v=spf1 +all"}, nil
	}
	value, err := auditWithLookup(context.Background(), "example.test", Options{SkipAXFR: true}, query)
	if err != nil || len(value.Findings) != 2 {
		t.Fatalf("report=%+v err=%v", value, err)
	}
	for _, finding := range value.Findings {
		if finding.RuleID != "dns.spf-multiple" && finding.RuleID != "dns.dmarc-multiple" {
			t.Fatalf("unexpected rule %s", finding.RuleID)
		}
	}
	if got := spfFindings("example.test", "v=spf1 redirect=_spf.example.test"); len(got) != 0 {
		t.Fatalf("valid redirect: %+v", got)
	}
}
