package certinfo

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// makeCert builds a self-signed certificate with the given template overrides
// applied on top of sane defaults, returning both the DER bytes and the
// parsed *x509.Certificate.
func makeCert(t *testing.T, mutate func(*x509.Certificate)) ([]byte, *x509.Certificate) {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "test.example.com", Organization: []string{"Test Org"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:              []string{"test.example.com", "alt.example.com"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	if mutate != nil {
		mutate(template)
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("failed to parse created certificate: %v", err)
	}
	return der, cert
}

func testTLSServerCertificate(t *testing.T, notBefore, notAfter time.Time) tls.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := certificateTemplate("127.0.0.1", notBefore.Add(time.Hour), false)
	template.NotBefore, template.NotAfter = notBefore, notAfter
	template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func certificateTemplate(commonName string, at time.Time, isCA bool) *x509.Certificate {
	keyUsage := x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	if isCA {
		keyUsage |= x509.KeyUsageCertSign
	}
	return &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             at.Add(-time.Hour),
		NotAfter:              at.Add(time.Hour),
		KeyUsage:              keyUsage,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:                  isCA,
		BasicConstraintsValid: true,
	}
}

func signedCertificate(t *testing.T, template, parent *x509.Certificate, parentKey *rsa.PrivateKey) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if parent == nil {
		parent, parentKey = template, key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return key, certificate
}

func serverHostPort(t *testing.T, address string) (string, int) {
	t.Helper()
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	return host, port
}

func writePEM(t *testing.T, der []byte) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "cert.pem")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("failed to create file: %v", err)
	}
	defer f.Close()

	if err := pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		t.Fatalf("failed to encode PEM: %v", err)
	}
	return path
}

func TestGetCertFromFilePEM(t *testing.T) {
	der, _ := makeCert(t, nil)
	path := writePEM(t, der)

	chain, err := GetCertFromFile(path)
	if err != nil {
		t.Fatalf("GetCertFromFile returned error: %v", err)
	}
	if len(chain.Certificates) != 1 {
		t.Fatalf("expected 1 certificate, got %d", len(chain.Certificates))
	}

	info := chain.Certificates[0]
	if !strings.Contains(info.Subject, "test.example.com") {
		t.Errorf("Subject = %q, want it to contain test.example.com", info.Subject)
	}
	if len(info.DNSNames) != 2 {
		t.Errorf("DNSNames = %v, want 2 entries", info.DNSNames)
	}
	if len(info.IPAddresses) != 1 || info.IPAddresses[0] != "127.0.0.1" {
		t.Errorf("IPAddresses = %v, want [127.0.0.1]", info.IPAddresses)
	}
	if !info.IsCA {
		t.Error("IsCA = false, want true")
	}
	if len(info.KeyUsage) == 0 {
		t.Error("KeyUsage should not be empty")
	}
	if len(info.ExtKeyUsage) != 2 {
		t.Errorf("ExtKeyUsage = %v, want 2 entries", info.ExtKeyUsage)
	}
	if info.Raw == nil {
		t.Error("Raw certificate should be populated")
	}
}

func TestGetCertFromFileMultiplePEMBlocks(t *testing.T) {
	der1, _ := makeCert(t, func(c *x509.Certificate) { c.Subject.CommonName = "first.example.com" })
	der2, _ := makeCert(t, func(c *x509.Certificate) { c.Subject.CommonName = "second.example.com" })

	dir := t.TempDir()
	path := filepath.Join(dir, "chain.pem")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("failed to create file: %v", err)
	}
	pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: der1})
	pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: der2})
	f.Close()

	chain, err := GetCertFromFile(path)
	if err != nil {
		t.Fatalf("GetCertFromFile returned error: %v", err)
	}
	if len(chain.Certificates) != 2 {
		t.Fatalf("expected 2 certificates, got %d", len(chain.Certificates))
	}
}

func TestGetCertFromFileDER(t *testing.T) {
	der, _ := makeCert(t, nil)

	dir := t.TempDir()
	path := filepath.Join(dir, "cert.der")
	if err := os.WriteFile(path, der, 0644); err != nil {
		t.Fatalf("failed to write DER file: %v", err)
	}

	chain, err := GetCertFromFile(path)
	if err != nil {
		t.Fatalf("GetCertFromFile(DER) returned error: %v", err)
	}
	if len(chain.Certificates) != 1 {
		t.Fatalf("expected 1 certificate, got %d", len(chain.Certificates))
	}
}

func TestGetCertFromFileMissingFile(t *testing.T) {
	_, err := GetCertFromFile("/nonexistent/path/cert.pem")
	if err == nil {
		t.Error("GetCertFromFile on a missing file should return an error")
	}
}

func TestGetCertFromFileGarbageContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "garbage.pem")
	if err := os.WriteFile(path, []byte("this is not a certificate at all"), 0644); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	_, err := GetCertFromFile(path)
	if err == nil {
		t.Error("GetCertFromFile on garbage content should return an error")
	}
}

func TestGetCertFromHostLocalTLSServer(t *testing.T) {
	srv := httptest.NewTLSServer(nil)
	defer srv.Close()

	addr := srv.Listener.Addr().String()
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("failed to split host/port from %q: %v", addr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("failed to parse port %q: %v", portStr, err)
	}

	chain, err := GetCertFromHost(host, port, 5)
	if err != nil {
		t.Fatalf("GetCertFromHost returned error: %v", err)
	}
	if len(chain.Certificates) == 0 {
		t.Fatal("expected at least one certificate from the local TLS server")
	}
	if chain.Host != host || chain.Port != port {
		t.Errorf("chain.Host/Port = %s/%d, want %s/%d", chain.Host, chain.Port, host, port)
	}
	// A locally-generated httptest cert won't verify against the system's DNS
	// name expectations, so we only assert that the verification path ran
	// (Valid is false and Error is populated) rather than asserting Valid.
	if chain.Valid == false && chain.Error == "" {
		t.Error("expected either Valid=true or a non-empty Error explaining why verification failed")
	}
	if chain.Error != "" && chain.VerificationError == nil {
		t.Error("expected the concrete certificate verification error to be retained")
	}
}

func TestGetCertFromHostContextAtWithDialContextUsesInjectedDial(t *testing.T) {
	srv := httptest.NewTLSServer(nil)
	defer srv.Close()
	host, port := serverHostPort(t, srv.Listener.Addr().String())

	var network, address string
	dialer := &net.Dialer{}
	chain, err := GetCertFromHostContextAtWithDialContext(context.Background(), host, port, time.Now(), func(ctx context.Context, gotNetwork, gotAddress string) (net.Conn, error) {
		network, address = gotNetwork, gotAddress
		return dialer.DialContext(ctx, gotNetwork, gotAddress)
	})
	if err != nil {
		t.Fatalf("GetCertFromHostContextAtWithDialContext: %v", err)
	}
	if len(chain.Certificates) == 0 || network != "tcp" || address != srv.Listener.Addr().String() {
		t.Fatalf("chain=%+v dial=%s/%s, want injected TCP dial to %s", chain, network, address, srv.Listener.Addr())
	}
}

func TestGetCertFromHostContextAtUsesRequestedVerificationTime(t *testing.T) {
	fixed := time.Date(2020, time.January, 1, 0, 0, 0, 0, time.UTC)
	server := httptest.NewUnstartedServer(nil)
	server.TLS = &tls.Config{Certificates: []tls.Certificate{testTLSServerCertificate(t, fixed.Add(-time.Hour), fixed.Add(time.Hour))}}
	server.StartTLS()
	defer server.Close()

	host, port := serverHostPort(t, server.Listener.Addr().String())
	atFixed, err := GetCertFromHostContextAt(context.Background(), host, port, fixed)
	if err != nil {
		t.Fatalf("GetCertFromHostContextAt returned error: %v", err)
	}
	if strings.Contains(strings.ToLower(atFixed.Error), "expired") {
		t.Errorf("fixed-time verification reported wall-clock expiry: %q", atFixed.Error)
	}

	compatibility, err := GetCertFromHostContext(context.Background(), host, port)
	if err != nil {
		t.Fatalf("GetCertFromHostContext returned error: %v", err)
	}
	if compatibility.Host != host || compatibility.Port != port || len(compatibility.Certificates) == 0 {
		t.Errorf("compatibility wrapper returned %#v, want the collected chain", compatibility)
	}

	zeroTime, err := GetCertFromHostContextAt(context.Background(), host, port, time.Time{})
	if err != nil {
		t.Fatalf("zero-time helper returned error: %v", err)
	}
	if zeroTime.Host != host || zeroTime.Port != port || len(zeroTime.Certificates) == 0 {
		t.Errorf("zero-time helper returned %#v, want current-time compatibility behavior", zeroTime)
	}
}

func TestVerifyPeerCertificatesUsesPeerIntermediates(t *testing.T) {
	fixed := time.Date(2020, time.January, 1, 0, 0, 0, 0, time.UTC)
	rootTemplate := certificateTemplate("Root", fixed, true)
	rootKey, root := signedCertificate(t, rootTemplate, nil, nil)
	intermediateTemplate := certificateTemplate("Intermediate", fixed, true)
	intermediateKey, intermediate := signedCertificate(t, intermediateTemplate, root, rootKey)
	leafTemplate := certificateTemplate("service.example", fixed, false)
	leafTemplate.DNSNames = []string{"service.example"}
	_, leaf := signedCertificate(t, leafTemplate, intermediate, intermediateKey)

	roots := x509.NewCertPool()
	roots.AddCert(root)
	if err := verifyPeerCertificates([]*x509.Certificate{leaf, intermediate}, "service.example", fixed, roots); err != nil {
		t.Fatalf("verification with peer intermediate failed: %v", err)
	}
	if err := verifyPeerCertificates([]*x509.Certificate{leaf, intermediate}, "service.example", time.Now(), roots); err == nil || !strings.Contains(strings.ToLower(err.Error()), "expired") {
		t.Fatalf("wall-clock verification error = %v, want expiry outside the fixed validity window", err)
	}
}

func TestGetCertFromHostDefaultPort(t *testing.T) {
	_, err := GetCertFromHost("127.0.0.1", 0, 1)
	// Port 0 should be substituted with 443; nothing should be listening there
	// in the test environment, so we expect a connection error, not a panic.
	if err == nil {
		t.Skip("something is listening on localhost:443 in this environment")
	}
}

func TestGetCertFromHostUnreachable(t *testing.T) {
	_, err := GetCertFromHost("127.0.0.1", 1, 1)
	if err == nil {
		t.Error("GetCertFromHost against a closed port should return an error")
	}
}

func TestGetCertFromHostContextHonorsCanceledContext(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	accepted := make(chan struct{})
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		close(accepted)
		defer conn.Close()
		<-time.After(2 * time.Second)
	}()

	host, portText, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatalf("split address: %v", err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errs := make(chan error, 1)
	go func() {
		_, callErr := GetCertFromHostContext(ctx, host, port)
		errs <- callErr
	}()

	select {
	case <-accepted:
		cancel()
	case <-time.After(time.Second):
		t.Fatal("TLS client did not connect")
	}

	select {
	case err := <-errs:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("GetCertFromHostContext did not stop after cancellation")
	}
}

func TestValidateCertificateExpired(t *testing.T) {
	info := &CertInfo{
		Subject:            "CN=a",
		Issuer:             "CN=b",
		NotBefore:          time.Now().Add(-48 * time.Hour),
		NotAfter:           time.Now().Add(-24 * time.Hour),
		SignatureAlgorithm: "SHA256-RSA",
	}

	result := ValidateCertificate(info)
	if result.Valid {
		t.Error("expired certificate should not be Valid")
	}
	if !result.Expired {
		t.Error("Expired should be true")
	}
}

func TestValidateCertificateNotYetValid(t *testing.T) {
	info := &CertInfo{
		Subject:            "CN=a",
		Issuer:             "CN=b",
		NotBefore:          time.Now().Add(24 * time.Hour),
		NotAfter:           time.Now().Add(48 * time.Hour),
		SignatureAlgorithm: "SHA256-RSA",
	}

	result := ValidateCertificate(info)
	if result.Valid {
		t.Error("not-yet-valid certificate should not be Valid")
	}
	if !result.NotYetValid {
		t.Error("NotYetValid should be true")
	}
}

func TestValidateCertificateAtUsesSuppliedInstant(t *testing.T) {
	fixed := time.Date(2020, time.January, 1, 0, 0, 0, 0, time.UTC)
	info := &CertInfo{
		Subject: "CN=a", Issuer: "CN=b",
		NotBefore: fixed.Add(24 * time.Hour),
		NotAfter:  fixed.Add(48 * time.Hour),
	}

	result := ValidateCertificateAt(info, fixed)
	if result.Expired || !result.NotYetValid {
		t.Errorf("validation at %s = %#v, want not-yet-valid only", fixed, result)
	}
}

func TestValidateCertificateSelfSigned(t *testing.T) {
	info := &CertInfo{
		Subject:            "CN=self",
		Issuer:             "CN=self",
		NotBefore:          time.Now().Add(-time.Hour),
		NotAfter:           time.Now().Add(365 * 24 * time.Hour),
		SignatureAlgorithm: "SHA256-RSA",
	}

	result := ValidateCertificate(info)
	if !result.SelfSigned {
		t.Error("SelfSigned should be true when Subject == Issuer")
	}
	if !result.Valid {
		t.Error("a self-signed cert that's within its validity window should still be Valid")
	}
}

func TestValidateCertificateExpiringSoon(t *testing.T) {
	info := &CertInfo{
		Subject:            "CN=a",
		Issuer:             "CN=b",
		NotBefore:          time.Now().Add(-time.Hour),
		NotAfter:           time.Now().Add(10 * 24 * time.Hour),
		SignatureAlgorithm: "SHA256-RSA",
	}

	result := ValidateCertificate(info)
	found := false
	for _, w := range result.Warnings {
		if strings.Contains(w, "expires in") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected an expiry warning in %v", result.Warnings)
	}
}

func TestValidateCertificateWeakSignatureAlgorithm(t *testing.T) {
	for _, algo := range []string{"SHA1-RSA", "MD5-RSA"} {
		info := &CertInfo{
			Subject:            "CN=a",
			Issuer:             "CN=b",
			NotBefore:          time.Now().Add(-time.Hour),
			NotAfter:           time.Now().Add(365 * 24 * time.Hour),
			SignatureAlgorithm: algo,
		}

		result := ValidateCertificate(info)
		found := false
		for _, w := range result.Warnings {
			if strings.Contains(w, "Weak signature algorithm") {
				found = true
			}
		}
		if !found {
			t.Errorf("expected a weak signature algorithm warning for %s, got %v", algo, result.Warnings)
		}
	}
}

func TestValidateCertificateHealthyCert(t *testing.T) {
	info := &CertInfo{
		Subject:            "CN=a",
		Issuer:             "CN=ca",
		NotBefore:          time.Now().Add(-time.Hour),
		NotAfter:           time.Now().Add(365 * 24 * time.Hour),
		SignatureAlgorithm: "SHA256-RSA",
	}

	result := ValidateCertificate(info)
	if !result.Valid {
		t.Error("healthy certificate should be Valid")
	}
	if len(result.Warnings) != 0 || len(result.ChainErrors) != 0 {
		t.Errorf("healthy certificate should have no warnings/errors, got warnings=%v errors=%v", result.Warnings, result.ChainErrors)
	}
}

// Display* and Compare* functions only print to stdout; exercised here for
// coverage and to make sure they don't panic.
func TestDisplayAndCompareDoNotPanic(t *testing.T) {
	der, cert := makeCert(t, nil)
	path := writePEM(t, der)

	chain, err := GetCertFromFile(path)
	if err != nil {
		t.Fatalf("GetCertFromFile returned error: %v", err)
	}
	info := chain.Certificates[0]

	DisplayCertInfo(&info)

	chain.Host = "example.com"
	chain.Port = 443
	chain.Valid = true
	DisplayChain(chain)

	chain.Valid = false
	chain.Error = "verification failed"
	DisplayChain(chain)

	result := ValidateCertificate(&info)
	DisplayValidation(result)

	der2, _ := makeCert(t, func(c *x509.Certificate) { c.Subject.CommonName = "other.example.com" })
	path2 := writePEM(t, der2)
	chain2, err := GetCertFromFile(path2)
	if err != nil {
		t.Fatalf("GetCertFromFile returned error: %v", err)
	}
	info2 := chain2.Certificates[0]
	CompareCertificates(&info, &info2)

	_ = cert // keep parsed cert referenced for clarity/future assertions
}
