package web

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"raxuiscli/internal/crypto/certinfo"
	"raxuiscli/internal/shared/models"
	sharedreport "raxuiscli/internal/shared/report"
)

func TestAuditHTTPSCollectsHTTPAndTLS(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setSecureHeaders(w)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	started := time.Date(2026, time.September, 5, 10, 0, 0, 0, time.UTC)
	report, err := Audit(context.Background(), server.URL, Options{
		Timeout:      time.Second,
		MaxBodyBytes: 128,
		InsecureTLS:  true,
		Now:          sequenceClock(started, started.Add(250*time.Millisecond)),
	})
	if err != nil {
		t.Fatalf("Audit returned error: %v", err)
	}
	if got, want := report.Audit.Status, "success"; got != want {
		t.Errorf("status = %q, want %q", got, want)
	}
	if got, want := report.Audit.StartedAt, started; !got.Equal(want) {
		t.Errorf("started at = %s, want %s", got, want)
	}
	if got, want := report.Audit.Duration, 250*time.Millisecond; got != want {
		t.Errorf("duration = %s, want %s", got, want)
	}
	if got := observationValue(report.Observations, "http.status"); got != "204" {
		t.Errorf("http.status = %q, want 204", got)
	}
	if got := observationValue(report.Observations, "tls.chain_valid"); got == "" {
		t.Error("TLS chain observation is missing")
	}
	if got := observationValue(report.Observations, "tls.version"); got == "" {
		t.Error("TLS version observation is missing")
	}
	if len(report.Errors) != 0 {
		t.Errorf("errors = %#v, want none", report.Errors)
	}
}

func TestAuditHTTPSValidatesEveryCollectedCertificate(t *testing.T) {
	target := "https://example.test/"
	fixed := time.Date(2020, time.January, 1, 0, 0, 0, 0, time.UTC)
	collector := tlsCollectorFunc(func(context.Context, string, int) (*certinfo.ChainInfo, error) {
		return &certinfo.ChainInfo{Certificates: []certinfo.CertInfo{
			{Subject: "expired", Issuer: "issuer", NotBefore: fixed.Add(-48 * time.Hour), NotAfter: fixed.Add(-24 * time.Hour)},
			{Subject: "future", Issuer: "issuer", NotBefore: fixed.Add(24 * time.Hour), NotAfter: fixed.Add(48 * time.Hour)},
		}}, nil
	})
	report, err := Audit(context.Background(), target, Options{
		HTTPCollector: httpCollectorFunc(func(context.Context, *url.URL, Options) (HTTPCollection, error) {
			return HTTPCollection{StatusCode: http.StatusOK, Headers: secureHeaders()}, nil
		}),
		TLSCollector: collector,
		Now:          sequenceClock(fixed, fixed),
	})
	if err != nil {
		t.Fatalf("Audit returned error: %v", err)
	}
	if countFindings(report.Findings, "tls.certificate.expired") != 1 || countFindings(report.Findings, "tls.certificate.not-yet-valid") != 1 {
		t.Errorf("findings = %#v, want a distinct finding for each certificate validation outcome", report.Findings)
	}
}

func TestAuditHTTPSkipsTLSForHTTP(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setSecureHeaders(w)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	tlsCalled := false
	report, err := Audit(context.Background(), server.URL, Options{
		TLSCollector: tlsCollectorFunc(func(context.Context, string, int) (*certinfo.ChainInfo, error) {
			tlsCalled = true
			return nil, errors.New("TLS collector must not run for HTTP")
		}),
	})
	if err != nil {
		t.Fatalf("Audit returned error: %v", err)
	}
	if tlsCalled {
		t.Error("TLS collector ran for an HTTP target")
	}
	if got, want := report.Audit.Status, "success"; got != want {
		t.Errorf("status = %q, want %q", got, want)
	}
	if got, want := observationValue(report.Observations, "tls.skipped"), "target scheme is http"; got != want {
		t.Errorf("tls.skipped = %q, want %q", got, want)
	}
}

func TestAuditRejectsInvalidScheme(t *testing.T) {
	_, err := Audit(context.Background(), "ftp://example.test/file", Options{})
	if err == nil {
		t.Fatal("Audit accepted an FTP target")
	}
	if !strings.Contains(err.Error(), "http or https") {
		t.Errorf("error = %q, want invalid-scheme explanation", err)
	}
}

func TestAuditRejectsInvalidEndpoints(t *testing.T) {
	for _, target := range []string{
		"https://:443/",
		"https://example.test:0/",
		"https://example.test:65536/",
		"https://example.test:abc/",
		"https://example.test:/",
	} {
		t.Run(target, func(t *testing.T) {
			if _, err := Audit(context.Background(), target, Options{}); err == nil {
				t.Fatalf("Audit accepted invalid endpoint %q", target)
			}
		})
	}
}

func TestAuditUsesTheSameNormalizedEndpointForHTTPAndTLS(t *testing.T) {
	const target = "https://BÜCHER.Example.:8443/path"
	var httpHost, tlsHost string
	var httpPort, tlsPort int
	fixed := time.Date(2020, time.January, 1, 0, 0, 0, 0, time.UTC)
	report, err := Audit(context.Background(), target, Options{
		Now: sequenceClock(fixed, fixed),
		HTTPCollector: httpCollectorFunc(func(_ context.Context, target *url.URL, _ Options) (HTTPCollection, error) {
			httpHost = target.Hostname()
			httpPort = targetPort(target)
			if got, want := target.String(), "https://xn--bcher-kva.example:8443/path"; got != want {
				t.Errorf("HTTP target = %q, want %q", got, want)
			}
			return HTTPCollection{StatusCode: http.StatusOK, Headers: secureHeaders()}, nil
		}),
		TLSCollector: tlsCollectorFunc(func(_ context.Context, host string, port int) (*certinfo.ChainInfo, error) {
			tlsHost, tlsPort = host, port
			return validChainAt(fixed), nil
		}),
	})
	if err != nil {
		t.Fatalf("Audit returned error: %v", err)
	}
	if got, want := httpHost, "xn--bcher-kva.example"; got != want {
		t.Errorf("HTTP hostname = %q, want %q", got, want)
	}
	if httpHost != tlsHost || httpPort != tlsPort {
		t.Errorf("HTTP endpoint %s:%d and TLS endpoint %s:%d differ", httpHost, httpPort, tlsHost, tlsPort)
	}
	if got, want := report.Audit.Target, "https://xn--bcher-kva.example:8443/path"; got != want {
		t.Errorf("report target = %q, want %q", got, want)
	}
}

func TestAuditPassesCustomAndIPv6PortsToBothCollectors(t *testing.T) {
	tests := []struct {
		target   string
		host     string
		port     int
		httpHost string
	}{
		{"https://example.test:8443/", "example.test", 8443, "example.test:8443"},
		{"https://[::1]:9443/", "::1", 9443, "[::1]:9443"},
	}
	for _, tt := range tests {
		t.Run(tt.target, func(t *testing.T) {
			var httpHost, tlsHost string
			var httpPort, tlsPort int
			_, err := Audit(context.Background(), tt.target, Options{
				HTTPCollector: httpCollectorFunc(func(_ context.Context, target *url.URL, _ Options) (HTTPCollection, error) {
					httpHost, httpPort = target.Host, targetPort(target)
					return HTTPCollection{StatusCode: http.StatusOK, Headers: secureHeaders()}, nil
				}),
				TLSCollector: tlsCollectorFunc(func(_ context.Context, host string, port int) (*certinfo.ChainInfo, error) {
					tlsHost, tlsPort = host, port
					return validChainAt(time.Now()), nil
				}),
			})
			if err != nil {
				t.Fatal(err)
			}
			if httpHost != tt.httpHost || httpPort != tt.port || tlsHost != tt.host || tlsPort != tt.port {
				t.Errorf("HTTP %s:%d TLS %s:%d, want HTTP %s:%d TLS %s:%d", httpHost, httpPort, tlsHost, tlsPort, tt.httpHost, tt.port, tt.host, tt.port)
			}
		})
	}
}

func TestAuditUsesCapturedClockForCertificateValidation(t *testing.T) {
	fixed := time.Date(2020, time.January, 1, 0, 0, 0, 0, time.UTC)
	report, err := Audit(context.Background(), "https://example.test/", Options{
		Now: sequenceClock(fixed, fixed),
		HTTPCollector: httpCollectorFunc(func(context.Context, *url.URL, Options) (HTTPCollection, error) {
			return HTTPCollection{StatusCode: http.StatusOK, Headers: secureHeaders()}, nil
		}),
		TLSCollector: tlsCollectorFunc(func(context.Context, string, int) (*certinfo.ChainInfo, error) {
			return &certinfo.ChainInfo{Valid: true, Certificates: []certinfo.CertInfo{
				{Subject: "expired", Issuer: "issuer", NotBefore: fixed.Add(-48 * time.Hour), NotAfter: fixed.Add(-24 * time.Hour)},
				{Subject: "future", Issuer: "issuer", NotBefore: fixed.Add(24 * time.Hour), NotAfter: fixed.Add(48 * time.Hour)},
			}}, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if countFindings(report.Findings, "tls.certificate.expired") != 1 || countFindings(report.Findings, "tls.certificate.not-yet-valid") != 1 {
		t.Errorf("findings = %#v, want distinct expired and not-yet-valid results at the audit clock", report.Findings)
	}
}

func TestAuditDefaultTLSVerificationUsesCapturedClock(t *testing.T) {
	fixed := time.Date(2020, time.January, 1, 0, 0, 0, 0, time.UTC)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setSecureHeaders(w)
		w.WriteHeader(http.StatusOK)
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{selfSignedServerCertificate(t, fixed.Add(-time.Hour), fixed.Add(time.Hour))}}
	server.StartTLS()
	defer server.Close()

	report, err := Audit(context.Background(), server.URL, Options{
		InsecureTLS: true,
		Now:         sequenceClock(fixed, fixed),
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := countFindings(report.Findings, "tls.certificate.expired"); got != 0 {
		t.Errorf("expired findings = %d, want none at the captured audit time: %#v", got, report.Findings)
	}
	if got := countFindings(report.Findings, "tls.certificate.chain-validation"); got != 1 {
		t.Errorf("chain-validation findings = %d, want one untrusted-chain finding", got)
	}
}

func TestAuditTreatsMissingTLSCertificatesAsPartial(t *testing.T) {
	for _, chain := range []*certinfo.ChainInfo{nil, {Valid: true}} {
		report, err := Audit(context.Background(), "https://example.test/", Options{
			HTTPCollector: httpCollectorFunc(func(context.Context, *url.URL, Options) (HTTPCollection, error) {
				return HTTPCollection{StatusCode: http.StatusOK, Headers: secureHeaders()}, nil
			}),
			TLSCollector: tlsCollectorFunc(func(context.Context, string, int) (*certinfo.ChainInfo, error) {
				return chain, nil
			}),
		})
		if err != nil {
			t.Fatal(err)
		}
		if got, want := report.Audit.Status, "partial"; got != want {
			t.Errorf("status = %q, want %q", got, want)
		}
		if got := reportError(report.Errors, "tls.collect"); got == "" {
			t.Errorf("errors = %#v, want tls.collect failure", report.Errors)
		}
		if got := observationValue(report.Observations, "tls.chain_valid"); got != "" {
			t.Errorf("tls.chain_valid = %q, want absent for missing certificates", got)
		}
	}
}

func TestAuditSharesDeadlineWithBothCollectorsAndParentCancellation(t *testing.T) {
	parent, cancel := context.WithCancel(context.Background())
	cancel()
	var httpDeadline, tlsDeadline time.Time
	var httpCalled, tlsCalled bool
	report, err := Audit(parent, "https://example.test/", Options{
		Timeout: time.Second,
		HTTPCollector: httpCollectorFunc(func(ctx context.Context, _ *url.URL, _ Options) (HTTPCollection, error) {
			httpCalled = true
			httpDeadline, _ = ctx.Deadline()
			return HTTPCollection{}, ctx.Err()
		}),
		TLSCollector: tlsCollectorFunc(func(ctx context.Context, _ string, _ int) (*certinfo.ChainInfo, error) {
			tlsCalled = true
			tlsDeadline, _ = ctx.Deadline()
			return nil, ctx.Err()
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !httpCalled || !tlsCalled || httpDeadline.IsZero() || !httpDeadline.Equal(tlsDeadline) {
		t.Errorf("collectors did not receive one shared deadline: HTTP called=%t deadline=%s, TLS called=%t deadline=%s", httpCalled, httpDeadline, tlsCalled, tlsDeadline)
	}
	if got, want := report.Audit.Status, "partial"; got != want {
		t.Errorf("status = %q, want %q", got, want)
	}
}

func TestAuditUsesOneOverallTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer server.Close()

	report, err := Audit(context.Background(), server.URL, Options{Timeout: 20 * time.Millisecond})
	if err != nil {
		t.Fatalf("Audit returned error: %v", err)
	}
	if got, want := report.Audit.Status, "partial"; got != want {
		t.Errorf("status = %q, want %q", got, want)
	}
	if got := reportError(report.Errors, "http.collect"); got == "" {
		t.Errorf("errors = %#v, want HTTP timeout error", report.Errors)
	}
}

func TestAuditCapsResponseBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setSecureHeaders(w)
		_, _ = w.Write([]byte(strings.Repeat("x", 512)))
	}))
	defer server.Close()

	report, err := Audit(context.Background(), server.URL, Options{MaxBodyBytes: 16})
	if err != nil {
		t.Fatalf("Audit returned error: %v", err)
	}
	if got, want := report.Audit.Status, "success"; got != want {
		t.Errorf("status = %q, want %q", got, want)
	}
	if got, want := observationValue(report.Observations, "http.body_truncated"), "true"; got != want {
		t.Errorf("http.body_truncated = %q, want %q", got, want)
	}
}

func TestAuditReturnsRedactedPartialResults(t *testing.T) {
	target := "https://example.test/path?token=secret"
	report, err := Audit(context.Background(), target, Options{
		HTTPCollector: httpCollectorFunc(func(context.Context, *url.URL, Options) (HTTPCollection, error) {
			return HTTPCollection{StatusCode: http.StatusOK, Headers: secureHeaders()}, nil
		}),
		TLSCollector: tlsCollectorFunc(func(context.Context, string, int) (*certinfo.ChainInfo, error) {
			return nil, errors.New("tls failed for https://user:password@example.test/path?token=secret; Authorization: Bearer secret")
		}),
	})
	if err != nil {
		t.Fatalf("Audit returned error: %v", err)
	}
	if got, want := report.Audit.Status, "partial"; got != want {
		t.Errorf("status = %q, want %q", got, want)
	}
	message := reportError(report.Errors, "tls.collect")
	if message == "" {
		t.Fatalf("errors = %#v, want TLS collector error", report.Errors)
	}
	for _, secret := range []string{"password", "token=secret", "Bearer secret"} {
		if strings.Contains(message, secret) {
			t.Errorf("partial error leaked %q: %q", secret, message)
		}
	}
	if got := observationValue(report.Observations, "http.status"); got != "200" {
		t.Errorf("HTTP result was lost after TLS failure: status=%q", got)
	}
}

func TestAuditDoesNotFollowRedirectsUnlessAllowed(t *testing.T) {
	var destinationCalls atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		destinationCalls.Add(1)
		setSecureHeaders(w)
		w.WriteHeader(http.StatusOK)
	}))
	defer destination.Close()

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL, http.StatusFound)
	}))
	defer origin.Close()

	first, err := Audit(context.Background(), origin.URL, Options{})
	if err != nil {
		t.Fatalf("Audit without redirects returned error: %v", err)
	}
	if got, want := observationValue(first.Observations, "http.status"), "302"; got != want {
		t.Errorf("non-following status = %q, want %q", got, want)
	}
	if got := destinationCalls.Load(); got != 0 {
		t.Fatalf("redirect contacted a second target %d times without permission", got)
	}

	second, err := Audit(context.Background(), origin.URL, Options{AllowRedirects: true})
	if err != nil {
		t.Fatalf("Audit with redirects returned error: %v", err)
	}
	if got, want := observationValue(second.Observations, "http.status"), "200"; got != want {
		t.Errorf("following status = %q, want %q", got, want)
	}
	if got := destinationCalls.Load(); got != 1 {
		t.Errorf("redirect destination calls = %d, want 1 after permission", got)
	}
}

func TestAuditProducesStableSortedReportCollections(t *testing.T) {
	started := time.Date(2026, time.September, 5, 11, 0, 0, 0, time.UTC)
	options := Options{
		HTTPCollector: httpCollectorFunc(func(context.Context, *url.URL, Options) (HTTPCollection, error) {
			return HTTPCollection{StatusCode: http.StatusOK, Headers: http.Header{
				"X-Powered-By": []string{"PHP/8.3"},
				"Server":       []string{"nginx/1.24"},
			}}, nil
		}),
		TLSCollector: tlsCollectorFunc(func(context.Context, string, int) (*certinfo.ChainInfo, error) {
			return &certinfo.ChainInfo{Valid: true, TLSVersion: tls.VersionTLS13, CipherSuite: tls.TLS_AES_128_GCM_SHA256}, nil
		}),
	}

	options.Now = sequenceClock(started, started)
	first, err := Audit(context.Background(), "https://example.test/", options)
	if err != nil {
		t.Fatal(err)
	}
	options.Now = sequenceClock(started, started)
	second, err := Audit(context.Background(), "https://example.test/", options)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Errorf("reports are not deterministic:\nfirst=%#v\nsecond=%#v", first, second)
	}
	for index := 1; index < len(first.Findings); index++ {
		if first.Findings[index-1].ID > first.Findings[index].ID {
			t.Errorf("findings are not sorted: %#v", first.Findings)
			break
		}
	}
	for index := 1; index < len(first.Observations); index++ {
		if first.Observations[index-1].Key > first.Observations[index].Key {
			t.Errorf("observations are not sorted: %#v", first.Observations)
			break
		}
	}
}

type httpCollectorFunc func(context.Context, *url.URL, Options) (HTTPCollection, error)

func (fn httpCollectorFunc) CollectHTTP(ctx context.Context, target *url.URL, options Options) (HTTPCollection, error) {
	return fn(ctx, target, options)
}

type tlsCollectorFunc func(context.Context, string, int) (*certinfo.ChainInfo, error)

func (fn tlsCollectorFunc) CollectTLS(ctx context.Context, host string, port int) (*certinfo.ChainInfo, error) {
	return fn(ctx, host, port)
}

func secureHeaders() http.Header {
	headers := make(http.Header)
	setSecureHeaderValues(headers)
	return headers
}

func setSecureHeaders(w interface{ Header() http.Header }) {
	setSecureHeaderValues(w.Header())
}

func setSecureHeaderValues(headers http.Header) {
	headers.Set("Strict-Transport-Security", "max-age=31536000")
	headers.Set("Content-Security-Policy", "default-src 'self'")
	headers.Set("X-Content-Type-Options", "nosniff")
	headers.Set("X-Frame-Options", "DENY")
	headers.Set("X-XSS-Protection", "1; mode=block")
	headers.Set("Referrer-Policy", "strict-origin-when-cross-origin")
	headers.Set("Permissions-Policy", "geolocation=()")
}

func observationValue(observations []sharedreport.Observation, key string) string {
	for _, observation := range observations {
		if observation.Key == key {
			return observation.Value
		}
	}
	return ""
}

func reportError(errors []sharedreport.ReportError, code string) string {
	for _, reportError := range errors {
		if reportError.Code == code {
			return reportError.Message
		}
	}
	return ""
}

func countFindings(findings []models.VulnResult, ruleID string) int {
	count := 0
	for _, finding := range findings {
		if finding.RuleID == ruleID {
			count++
		}
	}
	return count
}

func validChainAt(now time.Time) *certinfo.ChainInfo {
	return &certinfo.ChainInfo{Valid: true, Certificates: []certinfo.CertInfo{{
		Subject: "leaf", Issuer: "issuer", NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
	}}}
}

func selfSignedServerCertificate(t *testing.T, notBefore, notAfter time.Time) tls.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func sequenceClock(values ...time.Time) func() time.Time {
	index := 0
	return func() time.Time {
		if index >= len(values) {
			return values[len(values)-1]
		}
		value := values[index]
		index++
		return value
	}
}

func TestAuditNormalizesTLSDefaultPort(t *testing.T) {
	var gotPort int
	_, err := Audit(context.Background(), "https://example.test/", Options{
		HTTPCollector: httpCollectorFunc(func(context.Context, *url.URL, Options) (HTTPCollection, error) {
			return HTTPCollection{StatusCode: http.StatusOK, Headers: secureHeaders()}, nil
		}),
		TLSCollector: tlsCollectorFunc(func(_ context.Context, _ string, port int) (*certinfo.ChainInfo, error) {
			gotPort = port
			return &certinfo.ChainInfo{Valid: true}, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := gotPort, 443; got != want {
		t.Errorf("TLS port = %d, want %d", got, want)
	}
}
