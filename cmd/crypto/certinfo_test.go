package crypto

import (
	"errors"
	"net"
	"strconv"
	"strings"
	"testing"

	"github.com/Raxuis/RaxuisCLI/internal/crypto/certinfo"
	sharedcommand "github.com/Raxuis/RaxuisCLI/internal/shared/command"
)

func TestCertinfoCommandsRequireExactArguments(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{name: "main missing target", args: nil},
		{name: "main extra target", args: []string{"one", "two"}},
		{name: "chain missing target", args: []string{"chain"}},
		{name: "chain extra target", args: []string{"chain", "one", "two"}},
		{name: "validate missing target", args: []string{"validate"}},
		{name: "validate extra target", args: []string{"validate", "one", "two"}},
		{name: "compare missing target", args: []string{"compare", "one"}},
		{name: "compare extra target", args: []string{"compare", "one", "two", "three"}},
		{name: "san missing target", args: []string{"san"}},
		{name: "san extra target", args: []string{"san", "one", "two"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			command := newCertinfoCommand()
			command.SetArgs(tt.args)

			err := command.Execute()
			if err == nil {
				t.Fatal("certinfo command accepted invalid arguments")
			}
			if !strings.Contains(err.Error(), "accepts") {
				t.Fatalf("error = %q, want Cobra argument error", err)
			}
			assertOperationalError(t, err)
		})
	}
}

func TestCertinfoMissingFileReturnsOperationalError(t *testing.T) {
	command := newCertinfoCommand()
	command.SetArgs([]string{"/definitely/missing/certificate.pem"})

	err := command.Execute()
	if err == nil {
		t.Fatal("certinfo accepted a missing certificate file")
	}
	assertOperationalError(t, err)
	if !strings.Contains(err.Error(), "failed to read file") {
		t.Fatalf("error = %q, want file-read failure", err)
	}
}

func TestParseCertinfoTarget(t *testing.T) {
	tests := []struct {
		name     string
		target   string
		wantHost string
		wantPort int
		wantErr  bool
	}{
		{name: "hostname defaults to HTTPS", target: "example.test", wantHost: "example.test", wantPort: 443},
		{name: "IPv4 defaults to HTTPS", target: "127.0.0.1", wantHost: "127.0.0.1", wantPort: 443},
		{name: "hostname with port", target: "example.test:8443", wantHost: "example.test", wantPort: 8443},
		{name: "bracketed IPv6 with port", target: "[2001:db8::1]:8443", wantHost: "2001:db8::1", wantPort: 8443},
		{name: "bare IPv6 defaults to HTTPS", target: "2001:db8::1", wantHost: "2001:db8::1", wantPort: 443},
		{name: "empty host", target: ":443", wantErr: true},
		{name: "missing port", target: "example.test:", wantErr: true},
		{name: "non-numeric port", target: "example.test:not-a-port", wantErr: true},
		{name: "port out of range", target: "example.test:65536", wantErr: true},
		{name: "too many host separators", target: "example.test:443:8443", wantErr: true},
		{name: "bracketed IPv6 missing port", target: "[2001:db8::1]", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host, port, err := parseCertinfoTarget(tt.target)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parseCertinfoTarget(%q) succeeded: host=%q port=%d", tt.target, host, port)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseCertinfoTarget(%q) returned error: %v", tt.target, err)
			}
			if host != tt.wantHost || port != tt.wantPort {
				t.Errorf("parseCertinfoTarget(%q) = %q, %d; want %q, %d", tt.target, host, port, tt.wantHost, tt.wantPort)
			}
		})
	}
}

func TestCertinfoMalformedHostPortReturnsOperationalError(t *testing.T) {
	command := newCertinfoCommand()
	command.SetArgs([]string{"example.test:not-a-port"})

	err := command.Execute()
	if err == nil {
		t.Fatal("certinfo accepted a malformed host and port")
	}
	assertOperationalError(t, err)
}

func TestCertinfoConnectionFailureReturnsOperationalError(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}

	command := newCertinfoCommand()
	command.SetArgs([]string{"--timeout", "1", net.JoinHostPort("127.0.0.1", strconv.Itoa(port))})

	err = command.Execute()
	if err == nil {
		t.Fatal("certinfo accepted a refused local connection")
	}
	assertOperationalError(t, err)
	if !strings.Contains(err.Error(), "failed to connect") {
		t.Fatalf("error = %q, want connection failure", err)
	}
}

func TestCertinfoRejectsNilAndEmptyCertificateChains(t *testing.T) {
	tests := []struct {
		name  string
		chain *certinfo.ChainInfo
	}{
		{name: "nil chain", chain: nil},
		{name: "empty chain", chain: &certinfo.ChainInfo{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			original := getCertFromHost
			getCertFromHost = func(string, int, int) (*certinfo.ChainInfo, error) {
				return tt.chain, nil
			}
			t.Cleanup(func() { getCertFromHost = original })

			command := newCertinfoCommand()
			command.SetArgs([]string{"fixture.test"})
			err := command.Execute()
			if err == nil {
				t.Fatal("certinfo accepted a certificate chain without certificates")
			}
			assertOperationalError(t, err)
			if !strings.Contains(err.Error(), "no certificates found") {
				t.Fatalf("error = %q, want empty-chain failure", err)
			}
		})
	}
}

func assertOperationalError(t *testing.T, err error) {
	t.Helper()
	var operational *sharedcommand.OperationalError
	if !errors.As(err, &operational) || !errors.Is(err, sharedcommand.ErrOperational) {
		t.Fatalf("error = %T %v, want typed operational error", err, err)
	}
	if code := sharedcommand.ExitCode(err); code != 1 {
		t.Fatalf("ExitCode(error) = %d, want 1", code)
	}
}
