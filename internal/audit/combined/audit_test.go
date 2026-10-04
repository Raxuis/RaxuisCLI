package combined

import (
	"context"
	"errors"
	"testing"
	"time"

	dnsaudit "github.com/Raxuis/RaxuisCLI/internal/audit/dns"
	tlsaudit "github.com/Raxuis/RaxuisCLI/internal/audit/tls"
	webaudit "github.com/Raxuis/RaxuisCLI/internal/audit/web"
	"github.com/Raxuis/RaxuisCLI/internal/shared/constants"
	"github.com/Raxuis/RaxuisCLI/internal/shared/models"
	"github.com/Raxuis/RaxuisCLI/internal/shared/report"
)

func fixture(kind, target string) report.Report {
	return report.NewReport(report.ToolInfo{}, report.AuditInfo{Kind: kind, Target: target, Status: "complete", StartedAt: time.Now()}, []models.VulnResult{{RuleID: kind + ".test", Title: kind, Type: constants.VulnHeaders, Severity: constants.SeverityHigh, Resource: target, Evidence: "fixture", Remediation: "fix"}}, nil, nil)
}

func observation(value report.Report, key string) string {
	for _, item := range value.Observations {
		if item.Key == key {
			return item.Value
		}
	}
	return ""
}

func TestAuditTargetsOptionsAndAggregation(t *testing.T) {
	var calls []string
	options := Options{Nameserver: "127.0.0.1:5353", Web: webaudit.Options{Headers: map[string]string{"X-Test": "yes"}, Cookie: "session=test", UserAgent: "agent", AllowRedirects: true, InsecureTLS: true, MaxBodyBytes: 42}}
	options.WebRunner = func(ctx context.Context, target string, opts webaudit.Options) (report.Report, error) {
		calls = append(calls, "web")
		if target != "https://example.test:8443/path" || opts.Timeout != 60*time.Second || opts.Headers["X-Test"] != "yes" || opts.Cookie != "session=test" || opts.UserAgent != "agent" || !opts.AllowRedirects || !opts.InsecureTLS || opts.MaxBodyBytes != 42 {
			t.Fatalf("web options: %s %+v", target, opts)
		}
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("missing deadline")
		}
		return fixture("web", target), nil
	}
	options.DNSRunner = func(_ context.Context, target string, opts dnsaudit.Options) (report.Report, error) {
		calls = append(calls, "dns")
		if target != "example.test" || !opts.SkipAXFR || opts.Nameserver != options.Nameserver || opts.Timeout != 10 {
			t.Fatalf("dns options: %s %+v", target, opts)
		}
		return fixture("dns", target), nil
	}
	options.TLSRunner = func(_ context.Context, target string, opts tlsaudit.Options) (report.Report, error) {
		calls = append(calls, "tls")
		if target != "example.test:8443" || opts.Port != 8443 || opts.Timeout != 10*time.Second {
			t.Fatalf("tls options: %s %+v", target, opts)
		}
		return fixture("tls", target), nil
	}
	value, err := Audit(context.Background(), "HTTPS://EXAMPLE.test:8443/path", options)
	if err != nil || value.Audit.Kind != "all" || value.Audit.Status != "complete" || len(value.Findings) != 3 {
		t.Fatalf("report=%+v err=%v", value, err)
	}
	if len(calls) != 3 || calls[0] != "web" || calls[1] != "dns" || calls[2] != "tls" {
		t.Fatal(calls)
	}
	for _, kind := range calls {
		if observation(value, "combined."+kind+".status") != "complete" {
			t.Fatal(value.Observations)
		}
	}
}

func TestSkippedStages(t *testing.T) {
	for _, target := range []string{"http://127.0.0.1:8080", "http://[::1]:8080"} {
		options := Options{WebRunner: func(_ context.Context, target string, _ webaudit.Options) (report.Report, error) {
			return fixture("web", target), nil
		}, DNSRunner: func(context.Context, string, dnsaudit.Options) (report.Report, error) {
			t.Fatal("DNS called for IP")
			return report.Report{}, nil
		}, TLSRunner: func(context.Context, string, tlsaudit.Options) (report.Report, error) {
			t.Fatal("TLS called for HTTP")
			return report.Report{}, nil
		}}
		value, err := Audit(context.Background(), target, options)
		if err != nil || value.Audit.Status != "complete" || observation(value, "combined.dns.status") != "skipped" || observation(value, "combined.tls.status") != "skipped" {
			t.Fatalf("%+v %v", value, err)
		}
	}
}

func TestPartialAuditPreservesFindingsAndContinues(t *testing.T) {
	options := Options{AXFR: true, WebRunner: func(_ context.Context, target string, _ webaudit.Options) (report.Report, error) {
		return fixture("web", target), nil
	}, DNSRunner: func(_ context.Context, target string, opts dnsaudit.Options) (report.Report, error) {
		if opts.SkipAXFR {
			t.Fatal("AXFR flag lost")
		}
		return fixture("dns", target), errors.New("DNS unavailable")
	}, TLSRunner: func(_ context.Context, target string, _ tlsaudit.Options) (report.Report, error) {
		return fixture("tls", target), nil
	}}
	value, err := Audit(context.Background(), "https://example.test", options)
	if err != nil || value.Audit.Status != "partial" || len(value.Findings) != 3 || len(value.Errors) != 1 || observation(value, "combined.tls.status") != "complete" {
		t.Fatalf("%+v %v", value, err)
	}
}

func TestTimeoutPreservesCompletedWorkAndDoesNotStartOtherStages(t *testing.T) {
	options := Options{Timeout: 20 * time.Millisecond, WebRunner: func(ctx context.Context, target string, _ webaudit.Options) (report.Report, error) {
		<-ctx.Done()
		return fixture("web", target), ctx.Err()
	}, DNSRunner: func(context.Context, string, dnsaudit.Options) (report.Report, error) {
		t.Fatal("DNS started after timeout")
		return report.Report{}, nil
	}, TLSRunner: func(context.Context, string, tlsaudit.Options) (report.Report, error) {
		t.Fatal("TLS started after timeout")
		return report.Report{}, nil
	}}
	value, err := Audit(context.Background(), "https://example.test", options)
	if err != nil || value.Audit.Status != "partial" || len(value.Findings) != 1 || len(value.Errors) != 3 {
		t.Fatalf("%+v %v", value, err)
	}
	for _, kind := range []string{"web", "dns", "tls"} {
		if observation(value, "combined."+kind+".status") != "partial" {
			t.Fatal(value.Observations)
		}
	}
}

func TestInvalidTargetDoesNotCollect(t *testing.T) {
	for _, target := range []string{"example.test", "ftp://example.test", "https://example.test:0", "https://example.test:65536"} {
		options := Options{WebRunner: func(context.Context, string, webaudit.Options) (report.Report, error) {
			t.Fatal("invalid target collected")
			return report.Report{}, nil
		}}
		if _, err := Audit(context.Background(), target, options); err == nil {
			t.Fatalf("accepted %s", target)
		}
	}
}

func TestHTTPSIPv6UsesDefaultTLSportAndSkipsDNS(t *testing.T) {
	called := false
	options := Options{
		WebRunner: func(_ context.Context, target string, _ webaudit.Options) (report.Report, error) {
			return fixture("web", target), nil
		},
		DNSRunner: func(context.Context, string, dnsaudit.Options) (report.Report, error) {
			t.Fatal("DNS called for IPv6")
			return report.Report{}, nil
		},
		TLSRunner: func(_ context.Context, target string, opts tlsaudit.Options) (report.Report, error) {
			called = true
			if target != "[::1]:443" || opts.Port != 443 {
				t.Fatalf("target=%s options=%+v", target, opts)
			}
			value := fixture("tls", target)
			value.Audit.Status = "partial"
			value.Errors = []report.ReportError{{Code: "tls.scan_failed", Message: "fixture error"}}
			return value, nil
		},
	}
	value, err := Audit(context.Background(), "https://[::1]", options)
	if err != nil || !called || value.Audit.Status != "partial" || len(value.Errors) != 1 || len(value.Findings) != 2 || observation(value, "combined.dns.status") != "skipped" {
		t.Fatalf("report=%+v err=%v", value, err)
	}
}
