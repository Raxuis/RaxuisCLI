package recon

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

func listenerPort(t *testing.T, addr string) int {
	t.Helper()
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("failed to split host/port from %q: %v", addr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("failed to parse port %q: %v", portStr, err)
	}
	return port
}

func TestBannerGrabPlainBanner(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start listener: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.Write([]byte("SSH-2.0-OpenSSH_8.9\r\n"))
	}()

	port := listenerPort(t, ln.Addr().String())
	result := BannerGrab("127.0.0.1", port, 3, false)

	if result.Error != nil {
		t.Fatalf("BannerGrab returned error: %v", result.Error)
	}
	if !strings.Contains(result.Banner, "SSH-2.0-OpenSSH") {
		t.Errorf("Banner = %q, want it to contain SSH-2.0-OpenSSH", result.Banner)
	}
	if result.Service != "ssh" {
		t.Errorf("Service = %q, want ssh", result.Service)
	}
	if result.Version != "OpenSSH_8.9" {
		t.Errorf("Version = %q, want OpenSSH_8.9", result.Version)
	}
}

func TestGetProbe(t *testing.T) {
	if p := getProbe(80); !strings.Contains(p, "HEAD / HTTP/1.0") {
		t.Errorf("getProbe(80) = %q, want it to contain the HTTP HEAD probe", p)
	}
	if p := getProbe(443); !strings.Contains(p, "HEAD / HTTP/1.1") {
		t.Errorf("getProbe(443) = %q, want it to contain the HTTPS HEAD probe", p)
	}
	if p := getProbe(6379); p != "PING\r\n" {
		t.Errorf("getProbe(6379) = %q, want PING\\r\\n", p)
	}
	if p := getProbe(65000); p != "" {
		t.Errorf("getProbe(unrecognized port) = %q, want empty", p)
	}
}

func TestBannerGrabHTTPProbe(t *testing.T) {
	// getProbe only recognizes specific literal ports (80, 8080, 8000,
	// 8888, 443, 8443, 6379), so to exercise the real probe-sending path
	// through BannerGrab, bind directly to one of them instead of an
	// ephemeral port. 8080 doesn't require elevated privileges; skip if
	// something else on the machine already holds it.
	ln, err := net.Listen("tcp", "127.0.0.1:8080")
	if err != nil {
		t.Skipf("port 8080 unavailable in this environment: %v", err)
	}
	defer ln.Close()

	probeReceived := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 1024)
		n, _ := conn.Read(buf)
		probeReceived <- string(buf[:n])
		conn.Write([]byte("HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n\r\n"))
	}()

	result := BannerGrab("127.0.0.1", 8080, 3, false)
	if result.Error != nil {
		t.Fatalf("BannerGrab returned error: %v", result.Error)
	}
	if !strings.Contains(result.Banner, "HTTP/1.1 200 OK") {
		t.Errorf("Banner = %q, want it to contain the HTTP response", result.Banner)
	}
	if result.Service != "http" {
		t.Errorf("Service = %q, want http", result.Service)
	}

	select {
	case probe := <-probeReceived:
		if !strings.Contains(probe, "HEAD / HTTP/1.0") {
			t.Errorf("server received probe %q, want it to contain the HTTP HEAD probe", probe)
		}
	case <-time.After(time.Second):
		t.Error("server never received a probe from BannerGrab")
	}
}

func TestBannerGrabClosedPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to reserve a port: %v", err)
	}
	port := listenerPort(t, ln.Addr().String())
	ln.Close() // nothing listens here now

	result := BannerGrab("127.0.0.1", port, 1, false)
	if result.Error == nil {
		t.Error("BannerGrab against a closed port should set Error")
	}
}

func makeSelfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
	}
}

func TestBannerGrabTLS(t *testing.T) {
	cert := makeSelfSignedCert(t)
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	if err != nil {
		t.Fatalf("failed to start TLS listener: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.Write([]byte("+OK secure pop3 ready\r\n"))
	}()

	port := listenerPort(t, ln.Addr().String())
	result := BannerGrab("127.0.0.1", port, 3, true)

	if result.Error != nil {
		t.Fatalf("BannerGrab(useTLS=true) returned error: %v", result.Error)
	}
	if !result.TLS {
		t.Error("expected TLS=true")
	}
	if result.TLSVersion == "" {
		t.Error("expected TLSVersion to be populated")
	}
}

func TestShouldUseTLS(t *testing.T) {
	tests := []struct {
		port int
		want bool
	}{
		{443, true},
		{993, true},
		{995, true},
		{80, false},
		{22, false},
	}
	for _, tt := range tests {
		if got := shouldUseTLS(tt.port); got != tt.want {
			t.Errorf("shouldUseTLS(%d) = %v, want %v", tt.port, got, tt.want)
		}
	}
}

func TestGetTLSVersionName(t *testing.T) {
	tests := []struct {
		version uint16
		want    string
	}{
		{tls.VersionTLS10, "TLS 1.0"},
		{tls.VersionTLS11, "TLS 1.1"},
		{tls.VersionTLS12, "TLS 1.2"},
		{tls.VersionTLS13, "TLS 1.3"},
		{0x9999, "0x9999"},
	}
	for _, tt := range tests {
		if got := getTLSVersionName(tt.version); got != tt.want {
			t.Errorf("getTLSVersionName(%#04x) = %q, want %q", tt.version, got, tt.want)
		}
	}
}

func TestIdentifyServiceFallbackToPort(t *testing.T) {
	service, version := identifyService("", 22)
	if service != "ssh" || version != "" {
		t.Errorf("identifyService(empty banner, port 22) = (%q, %q), want (ssh, \"\")", service, version)
	}

	service, _ = identifyService("", 65000)
	if service != "unknown" {
		t.Errorf("identifyService(empty banner, unknown port) = %q, want unknown", service)
	}
}

func TestIdentifyServiceSignatures(t *testing.T) {
	tests := []struct {
		banner      string
		wantService string
	}{
		{"220 ftp.example.com FTP server ready", "ftp"},
		{"220 mail.example.com ESMTP Postfix", "smtp"},
		{"+OK example POP3 server ready", "pop3"},
		{"* OK example IMAP4rev1 ready", "imap"},
		{"5.7.29-log mysql Community Server", "mysql"}, // pattern `mysql|MariaDB` is case-sensitive
	}
	for _, tt := range tests {
		service, _ := identifyService(tt.banner, 0)
		if service != tt.wantService {
			t.Errorf("identifyService(%q) service = %q, want %q", tt.banner, service, tt.wantService)
		}
	}
}

func TestReconMultiple(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start listener: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Write([]byte("220 test server\r\n"))
			conn.Close()
		}
	}()

	openPort := listenerPort(t, ln.Addr().String())

	closedLn, _ := net.Listen("tcp", "127.0.0.1:0")
	closedPort := listenerPort(t, closedLn.Addr().String())
	closedLn.Close()

	results := ReconMultiple(ReconOptions{Host: "127.0.0.1", Ports: []int{openPort, closedPort}, Timeout: 2})
	if len(results) != 2 {
		t.Fatalf("ReconMultiple returned %d results, want 2", len(results))
	}

	var sawOpen, sawClosed bool
	for _, r := range results {
		if r.Port == openPort && r.Error == nil {
			sawOpen = true
		}
		if r.Port == closedPort && r.Error != nil {
			sawClosed = true
		}
	}
	if !sawOpen {
		t.Error("expected the open port to have no error")
	}
	if !sawClosed {
		t.Error("expected the closed port to have an error")
	}
}

func TestParsePortsSingleAndRange(t *testing.T) {
	ports, err := ParsePorts("22,80,100-102")
	if err != nil {
		t.Fatalf("ParsePorts returned error: %v", err)
	}
	want := []int{22, 80, 100, 101, 102}
	if len(ports) != len(want) {
		t.Fatalf("ParsePorts = %v, want %v", ports, want)
	}
	for i := range want {
		if ports[i] != want[i] {
			t.Errorf("index %d: got %d, want %d", i, ports[i], want[i])
		}
	}
}

func TestParsePortsDeduplicates(t *testing.T) {
	ports, err := ParsePorts("22,22,20-22")
	if err != nil {
		t.Fatalf("ParsePorts returned error: %v", err)
	}
	want := []int{22, 20, 21}
	if len(ports) != len(want) {
		t.Fatalf("ParsePorts = %v, want de-duplicated %v", ports, want)
	}
}

func TestParsePortsInvalid(t *testing.T) {
	tests := []string{"abc", "1-2-3", "1-abc", "abc-2"}
	for _, in := range tests {
		if _, err := ParsePorts(in); err == nil {
			t.Errorf("ParsePorts(%q) should return an error", in)
		}
	}
}

func TestParsePortsSwapsReversedRange(t *testing.T) {
	ports, err := ParsePorts("22-20")
	if err != nil {
		t.Fatalf("ParsePorts returned error: %v", err)
	}
	want := []int{20, 21, 22}
	if len(ports) != len(want) {
		t.Fatalf("ParsePorts(22-20) = %v, want %v (swapped)", ports, want)
	}
}

func TestGetCommonPorts(t *testing.T) {
	if len(GetCommonPorts()) == 0 {
		t.Error("GetCommonPorts() should not be empty")
	}
}

func TestSanitizeBanner(t *testing.T) {
	got := sanitizeBanner("hello\x00\x01world\tend")
	if !strings.Contains(got, "hello") || !strings.Contains(got, "world") {
		t.Errorf("sanitizeBanner output missing text: %q", got)
	}
	if strings.ContainsRune(got, 0x00) {
		t.Errorf("sanitizeBanner should strip null bytes, got %q", got)
	}
}

func TestScannerReadLine(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start listener: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.Write([]byte("hello line\n"))
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer conn.Close()

	line, err := ScannerReadLine(conn)
	if err != nil {
		t.Fatalf("ScannerReadLine returned error: %v", err)
	}
	if line != "hello line" {
		t.Errorf("ScannerReadLine = %q, want %q", line, "hello line")
	}
}

func TestDisplayResultAndResults(t *testing.T) {
	results := []ServiceResult{
		{Host: "127.0.0.1", Port: 22, Service: "ssh", Version: "OpenSSH", ResponseTime: time.Millisecond},
		{Host: "127.0.0.1", Port: 81, Error: errClosedForTest{}},
	}

	// Just verify these don't panic; output correctness for pure display
	// functions is a lower priority than the network logic above.
	DisplayResult(results[0])
	DisplayResult(results[1])
	DisplayResults(results)
	DisplayResults(nil)
}

type errClosedForTest struct{}

func (errClosedForTest) Error() string { return "closed" }
