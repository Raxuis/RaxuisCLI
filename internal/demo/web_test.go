package demo

import (
	"context"
	"errors"
	"net"
	"net/url"
	"reflect"
	"slices"
	"testing"
	"time"

	webaudit "raxuiscli/internal/audit/web"
	"raxuiscli/internal/shared/report"
)

func TestWebUsesProductionAuditAndOnlyLoopbackConnections(t *testing.T) {
	var captured *webFixture
	called := false
	value, err := runWeb(context.Background(), func(ctx context.Context, target string, options webaudit.Options) (report.Report, error) {
		called = true
		parsed, parseErr := url.Parse(target)
		if parseErr != nil {
			t.Fatalf("parse fixture target: %v", parseErr)
		}
		if ip := net.ParseIP(parsed.Hostname()); ip == nil || !ip.IsLoopback() {
			t.Fatalf("audit target %q is not loopback", target)
		}
		if !options.InsecureTLS {
			t.Fatal("local expired certificate was not explicitly allowed for collection")
		}
		if options.AllowRedirects {
			t.Fatal("demo unexpectedly allows redirects")
		}
		return webaudit.Audit(ctx, target, options)
	}, func() (*webFixture, error) {
		fixture, startErr := startWebFixture()
		captured = fixture
		return fixture, startErr
	})
	if err != nil {
		t.Fatalf("run demo web: %v", err)
	}
	if !called {
		t.Fatal("production-compatible audit runner was not called")
	}
	if value.Audit.Status != "success" || value.Audit.Target != StableWebTarget {
		t.Fatalf("audit metadata = %+v", value.Audit)
	}
	if captured == nil {
		t.Fatal("fixture was not captured")
	}
	for _, remote := range captured.remoteAddresses() {
		host, _, splitErr := net.SplitHostPort(remote)
		if splitErr != nil {
			t.Fatalf("split accepted remote address %q: %v", remote, splitErr)
		}
		if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
			t.Fatalf("connection escaped loopback: %q", remote)
		}
	}
	if got := len(captured.remoteAddresses()); got < 2 {
		t.Fatalf("accepted connections = %d, want HTTP and TLS collectors", got)
	}
	assertFixtureClosed(t, captured)
}

func TestWebProducesDeterministicDocumentedFindings(t *testing.T) {
	first, err := Web(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	second, err := Web(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	wantRules := []string{
		"http.cookie.security-flags",
		"http.header.content-security-policy.missing",
		"http.header.hsts.missing",
		"http.header.permissions-policy.missing",
		"http.header.referrer-policy.missing",
		"http.header.server.version-disclosure",
		"http.header.x-content-type-options.missing",
		"http.header.x-frame-options.missing",
		"http.header.x-powered-by.disclosure",
		"http.header.x-xss-protection.missing",
		"tls.certificate.chain-validation",
		"tls.certificate.expired",
		"tls.certificate.self-signed",
	}
	gotRules := make([]string, 0, len(first.Findings))
	for _, finding := range first.Findings {
		gotRules = append(gotRules, finding.RuleID)
		if finding.Resource != StableWebTarget || finding.URL != StableWebTarget {
			t.Fatalf("finding retained ephemeral target: %+v", finding)
		}
	}
	slices.Sort(gotRules)
	if !slices.Equal(gotRules, wantRules) {
		t.Fatalf("finding rules = %#v, want %#v; findings=%+v", gotRules, wantRules, first.Findings)
	}
	if first.Audit.ID != second.Audit.ID || first.Audit.StartedAt != second.Audit.StartedAt || first.Audit.Duration != second.Audit.Duration {
		t.Fatalf("demo metadata is nondeterministic:\nfirst=%+v\nsecond=%+v", first.Audit, second.Audit)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("successive demo reports differ:\nfirst=%+v\nsecond=%+v", first, second)
	}
	if !hasObservation(first, "demo.network_scope", "loopback-only") || !hasObservation(first, "demo.tls_verification", "relaxed for local fixture only") {
		t.Fatalf("demo safety observations missing: %+v", first.Observations)
	}
}

func TestWebHonorsCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var captured *webFixture
	_, err := runWeb(ctx, func(ctx context.Context, _ string, _ webaudit.Options) (report.Report, error) {
		<-ctx.Done()
		return report.Report{}, ctx.Err()
	}, func() (*webFixture, error) {
		fixture, startErr := startWebFixture()
		captured = fixture
		return fixture, startErr
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context cancellation", err)
	}
	assertFixtureClosed(t, captured)
}

func TestWebClosesFixtureAfterAuditErrorAndPanic(t *testing.T) {
	t.Run("error", func(t *testing.T) {
		var captured *webFixture
		sentinel := errors.New("audit failed")
		_, err := runWeb(context.Background(), func(context.Context, string, webaudit.Options) (report.Report, error) {
			return report.Report{}, sentinel
		}, func() (*webFixture, error) {
			fixture, startErr := startWebFixture()
			captured = fixture
			return fixture, startErr
		})
		if !errors.Is(err, sentinel) {
			t.Fatalf("error = %v, want sentinel", err)
		}
		assertFixtureClosed(t, captured)
	})

	t.Run("panic", func(t *testing.T) {
		var captured *webFixture
		func() {
			defer func() {
				if recovered := recover(); recovered != "boom" {
					t.Fatalf("recovered = %v, want boom", recovered)
				}
			}()
			_, _ = runWeb(context.Background(), func(context.Context, string, webaudit.Options) (report.Report, error) {
				panic("boom")
			}, func() (*webFixture, error) {
				fixture, startErr := startWebFixture()
				captured = fixture
				return fixture, startErr
			})
		}()
		assertFixtureClosed(t, captured)
	})
}

func assertFixtureClosed(t *testing.T, fixture *webFixture) {
	t.Helper()
	if fixture == nil {
		t.Fatal("fixture is nil")
	}
	connection, err := net.DialTimeout("tcp", fixture.address(), 100*time.Millisecond)
	if err == nil {
		_ = connection.Close()
		t.Fatalf("fixture %s still accepts connections", fixture.address())
	}
}

func hasObservation(value report.Report, key, expected string) bool {
	for _, observation := range value.Observations {
		if observation.Key == key && observation.Value == expected {
			return true
		}
	}
	return false
}
