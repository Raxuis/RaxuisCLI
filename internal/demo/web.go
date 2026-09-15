// Package demo provides deterministic, local-only fixtures that exercise the
// production audit services without contacting public networks.
package demo

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	webaudit "github.com/Raxuis/RaxuisCLI/internal/audit/web"
	"github.com/Raxuis/RaxuisCLI/internal/shared/report"
)

const (
	// StableWebTarget replaces the fixture's ephemeral port in persisted demo
	// reports. It is deliberately a loopback URL so the report cannot be
	// mistaken for an audit of a public host.
	StableWebTarget = "https://127.0.0.1/demo"

	demoTLSVerificationObservation = "relaxed for local fixture only"
)

var demoAuditInstant = time.Date(2024, time.January, 2, 3, 4, 5, 0, time.UTC)

// WebAuditRunner is the production web-audit contract used by the fixture.
type WebAuditRunner func(context.Context, string, webaudit.Options) (report.Report, error)

// Web runs the passive production web audit against a short-lived HTTPS
// fixture. The listener is created only on IPv4 loopback and is closed before
// this function returns, even if the audit panics.
func Web(ctx context.Context) (report.Report, error) {
	return runWeb(ctx, webaudit.Audit, startWebFixture)
}

func runWeb(ctx context.Context, runner WebAuditRunner, starter func() (*webFixture, error)) (value report.Report, err error) {
	if ctx == nil {
		return report.Report{}, fmt.Errorf("demo context must not be nil")
	}
	if runner == nil {
		return report.Report{}, fmt.Errorf("demo audit runner must not be nil")
	}
	if starter == nil {
		return report.Report{}, fmt.Errorf("demo fixture starter must not be nil")
	}

	fixture, err := starter()
	if err != nil {
		return report.Report{}, fmt.Errorf("start local web demo: %w", err)
	}
	defer func() {
		if closeErr := fixture.Close(); closeErr != nil && err == nil {
			err = fmt.Errorf("close local web demo: %w", closeErr)
		}
	}()

	value, err = runner(ctx, fixture.target(), webaudit.Options{
		Timeout:        5 * time.Second,
		MaxBodyBytes:   4 << 10,
		AllowRedirects: false,
		InsecureTLS:    true,
		Now:            func() time.Time { return demoAuditInstant },
		DialContext:    fixture.dialGuard.DialContext,
	})
	if err != nil {
		return value, err
	}
	return normalizeWebReport(value, fixture.target()), nil
}

type webFixture struct {
	listener  *loopbackListener
	server    *http.Server
	targetURL string
	closeOnce sync.Once
	closeErr  error
	dialGuard *loopbackDialGuard
}

func startWebFixture() (*webFixture, error) {
	base, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("listen on loopback: %w", err)
	}
	listener := &loopbackListener{Listener: base}
	certificate, err := generateExpiredSelfSignedCertificate()
	if err != nil {
		_ = base.Close()
		return nil, err
	}

	tlsListener := tls.NewListener(listener, &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS12,
	})
	server := &http.Server{
		Handler:           weakWebHandler(),
		ReadHeaderTimeout: 2 * time.Second,
		ErrorLog:          log.New(io.Discard, "", 0),
	}
	fixture := &webFixture{
		listener:  listener,
		server:    server,
		targetURL: "https://" + listener.Addr().String() + "/",
		dialGuard: newLoopbackDialGuard((&net.Dialer{}).DialContext),
	}
	go func() {
		serveErr := server.Serve(tlsListener)
		if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) && !errors.Is(serveErr, net.ErrClosed) {
			// A later audit request will surface unexpected serving failures. The
			// fixture intentionally has no asynchronous logging side channel.
			_ = base.Close()
		}
	}()
	return fixture, nil
}

func weakWebHandler() http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		// This intentionally weak, fixed profile is part of the public demo:
		// security headers are omitted, implementation details are disclosed,
		// and the cookie lacks Secure, HttpOnly, and SameSite attributes.
		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		writer.Header().Set("Server", "RaxuisDemo/1.0")
		writer.Header().Set("X-Powered-By", "RaxuisCLI-Demo")
		writer.Header().Add("Set-Cookie", "demo_session=local; Path=/")
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte("RaxuisCLI local passive web audit demo\n"))
	})
}

func generateExpiredSelfSignedCertificate() (tls.Certificate, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate demo certificate key: %w", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(20240904),
		Subject:               pkix.Name{CommonName: "RaxuisCLI Local Demo"},
		Issuer:                pkix.Name{CommonName: "RaxuisCLI Local Demo"},
		NotBefore:             time.Date(2020, time.January, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2021, time.January, 1, 0, 0, 0, 0, time.UTC),
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create demo certificate: %w", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: privateKey}, nil
}

func normalizeWebReport(value report.Report, ephemeralTarget string) report.Report {
	value.Audit.ID = ""
	value.Audit.Target = StableWebTarget
	value.Audit.StartedAt = demoAuditInstant
	value.Audit.Duration = 0

	for index := range value.Findings {
		value.Findings[index].Resource = StableWebTarget
		value.Findings[index].URL = StableWebTarget
		value.Findings[index].Evidence = normalizeFixtureText(value.Findings[index].Evidence, ephemeralTarget)
		value.Findings[index].Description = normalizeFixtureText(value.Findings[index].Description, ephemeralTarget)
		value.Findings[index].Remediation = normalizeFixtureText(value.Findings[index].Remediation, ephemeralTarget)
	}
	for index := range value.Observations {
		value.Observations[index].Value = normalizeFixtureText(value.Observations[index].Value, ephemeralTarget)
	}
	value.Observations = append(value.Observations,
		report.Observation{Key: "demo.network_scope", Value: "loopback-only"},
		report.Observation{Key: "demo.tls_verification", Value: demoTLSVerificationObservation},
	)
	for index := range value.Errors {
		value.Errors[index].Message = normalizeFixtureText(value.Errors[index].Message, ephemeralTarget)
	}

	return report.NewReport(value.Tool, value.Audit, value.Findings, value.Observations, value.Errors)
}

func normalizeFixtureText(value, ephemeralTarget string) string {
	value = strings.ReplaceAll(value, ephemeralTarget, StableWebTarget)
	if parsed := strings.TrimPrefix(ephemeralTarget, "https://"); parsed != ephemeralTarget {
		value = strings.ReplaceAll(value, strings.TrimSuffix(parsed, "/"), "127.0.0.1")
	}
	return value
}

func (fixture *webFixture) target() string  { return fixture.targetURL }
func (fixture *webFixture) address() string { return fixture.listener.Addr().String() }

func (fixture *webFixture) Close() error {
	fixture.closeOnce.Do(func() {
		fixture.closeErr = fixture.server.Close()
		if errors.Is(fixture.closeErr, http.ErrServerClosed) || errors.Is(fixture.closeErr, net.ErrClosed) {
			fixture.closeErr = nil
		}
		if listenerErr := fixture.listener.Close(); listenerErr != nil && !errors.Is(listenerErr, net.ErrClosed) && fixture.closeErr == nil {
			fixture.closeErr = listenerErr
		}
	})
	return fixture.closeErr
}

func (fixture *webFixture) remoteAddresses() []string {
	return fixture.listener.remoteAddresses()
}

func (fixture *webFixture) dialDestinations() []string {
	return fixture.dialGuard.destinations()
}

type loopbackDialGuard struct {
	dial    func(context.Context, string, string) (net.Conn, error)
	mu      sync.Mutex
	allowed []string
}

func newLoopbackDialGuard(dial func(context.Context, string, string) (net.Conn, error)) *loopbackDialGuard {
	return &loopbackDialGuard{dial: dial}
}

func (guard *loopbackDialGuard) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if guard == nil || guard.dial == nil {
		return nil, fmt.Errorf("demo loopback dialer is not configured")
	}
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, fmt.Errorf("demo permits only loopback TCP connections, got network %q", network)
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("demo requires a loopback IP and port: %w", err)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return nil, fmt.Errorf("demo refused non-loopback destination %q", address)
	}
	guard.mu.Lock()
	guard.allowed = append(guard.allowed, address)
	guard.mu.Unlock()
	return guard.dial(ctx, network, address)
}

func (guard *loopbackDialGuard) destinations() []string {
	guard.mu.Lock()
	defer guard.mu.Unlock()
	return append([]string(nil), guard.allowed...)
}

type loopbackListener struct {
	net.Listener
	mu      sync.Mutex
	remotes []string
}

func (listener *loopbackListener) Accept() (net.Conn, error) {
	connection, err := listener.Listener.Accept()
	if err != nil {
		return nil, err
	}
	host, _, splitErr := net.SplitHostPort(connection.RemoteAddr().String())
	if splitErr != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		_ = connection.Close()
		return nil, fmt.Errorf("demo rejected non-loopback connection from %s", connection.RemoteAddr())
	}
	listener.mu.Lock()
	listener.remotes = append(listener.remotes, connection.RemoteAddr().String())
	listener.mu.Unlock()
	return connection, nil
}

func (listener *loopbackListener) remoteAddresses() []string {
	listener.mu.Lock()
	defer listener.mu.Unlock()
	return append([]string(nil), listener.remotes...)
}
