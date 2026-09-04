package keygen

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateRSAKeyPair(t *testing.T) {
	kp, err := GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("GenerateRSAKeyPair returned error: %v", err)
	}
	if kp.Algorithm != "RSA" || kp.Bits != 2048 {
		t.Errorf("Algorithm/Bits = %s/%d, want RSA/2048", kp.Algorithm, kp.Bits)
	}

	block, _ := pem.Decode(kp.PrivateKeyPEM)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		t.Fatal("PrivateKeyPEM did not decode to an RSA PRIVATE KEY block")
	}
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse generated RSA private key: %v", err)
	}
	if priv.N.BitLen() < 2040 { // allow for slight bit-length variance
		t.Errorf("generated RSA key bit length = %d, want ~2048", priv.N.BitLen())
	}

	pubBlock, _ := pem.Decode(kp.PublicKeyPEM)
	if pubBlock == nil || pubBlock.Type != "PUBLIC KEY" {
		t.Fatal("PublicKeyPEM did not decode to a PUBLIC KEY block")
	}
	pub, err := x509.ParsePKIXPublicKey(pubBlock.Bytes)
	if err != nil {
		t.Fatalf("failed to parse generated RSA public key: %v", err)
	}
	if _, ok := pub.(*rsa.PublicKey); !ok {
		t.Errorf("parsed public key is not *rsa.PublicKey: %T", pub)
	}
}

func TestGenerateRSAKeyPairMinimumBitsEnforced(t *testing.T) {
	kp, err := GenerateRSAKeyPair(512)
	if err != nil {
		t.Fatalf("GenerateRSAKeyPair returned error: %v", err)
	}
	if kp.Bits != 2048 {
		t.Errorf("Bits = %d, want the enforced minimum of 2048", kp.Bits)
	}
}

func TestGenerateECDSAKeyPairCurves(t *testing.T) {
	tests := []struct {
		curve    string
		wantBits int
	}{
		{"p256", 256},
		{"P256", 256},
		{"prime256v1", 256},
		{"p384", 384},
		{"p521", 521},
		{"unknown-curve", 256}, // defaults to P256
	}

	for _, tt := range tests {
		kp, err := GenerateECDSAKeyPair(tt.curve)
		if err != nil {
			t.Fatalf("GenerateECDSAKeyPair(%q) returned error: %v", tt.curve, err)
		}
		if kp.Bits != tt.wantBits {
			t.Errorf("GenerateECDSAKeyPair(%q).Bits = %d, want %d", tt.curve, kp.Bits, tt.wantBits)
		}

		block, _ := pem.Decode(kp.PrivateKeyPEM)
		if block == nil || block.Type != "EC PRIVATE KEY" {
			t.Fatalf("GenerateECDSAKeyPair(%q): PrivateKeyPEM did not decode to an EC PRIVATE KEY block", tt.curve)
		}
		priv, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			t.Fatalf("GenerateECDSAKeyPair(%q): failed to parse EC private key: %v", tt.curve, err)
		}
		if priv.Curve.Params().BitSize != tt.wantBits {
			t.Errorf("GenerateECDSAKeyPair(%q): curve bit size = %d, want %d", tt.curve, priv.Curve.Params().BitSize, tt.wantBits)
		}

		pubBlock, _ := pem.Decode(kp.PublicKeyPEM)
		pub, err := x509.ParsePKIXPublicKey(pubBlock.Bytes)
		if err != nil {
			t.Fatalf("GenerateECDSAKeyPair(%q): failed to parse public key: %v", tt.curve, err)
		}
		if _, ok := pub.(*ecdsa.PublicKey); !ok {
			t.Errorf("GenerateECDSAKeyPair(%q): parsed public key is not *ecdsa.PublicKey: %T", tt.curve, pub)
		}
	}
}

func TestGenerateEd25519KeyPair(t *testing.T) {
	kp, err := GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateEd25519KeyPair returned error: %v", err)
	}
	if kp.Algorithm != "Ed25519" || kp.Bits != 256 {
		t.Errorf("Algorithm/Bits = %s/%d, want Ed25519/256", kp.Algorithm, kp.Bits)
	}

	block, _ := pem.Decode(kp.PrivateKeyPEM)
	if block == nil || block.Type != "PRIVATE KEY" {
		t.Fatal("PrivateKeyPEM did not decode to a PRIVATE KEY block")
	}
	priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse Ed25519 private key: %v", err)
	}
	if _, ok := priv.(ed25519.PrivateKey); !ok {
		t.Errorf("parsed private key is not ed25519.PrivateKey: %T", priv)
	}
}

func TestGenerateSSHKeyPairRSA(t *testing.T) {
	kp, err := GenerateSSHKeyPair("rsa", 2048)
	if err != nil {
		t.Fatalf("GenerateSSHKeyPair(rsa) returned error: %v", err)
	}
	if kp.Algorithm != "ssh-rsa" || kp.Bits != 2048 {
		t.Errorf("Algorithm/Bits = %s/%d, want ssh-rsa/2048", kp.Algorithm, kp.Bits)
	}
	if !strings.HasPrefix(kp.PublicKey, "ssh-rsa") {
		t.Errorf("PublicKey = %q, want it to start with ssh-rsa", kp.PublicKey)
	}
}

func TestGenerateSSHKeyPairEd25519(t *testing.T) {
	kp, err := GenerateSSHKeyPair("ed25519", 0)
	if err != nil {
		t.Fatalf("GenerateSSHKeyPair(ed25519) returned error: %v", err)
	}
	if kp.Algorithm != "ssh-ed25519" {
		t.Errorf("Algorithm = %q, want ssh-ed25519", kp.Algorithm)
	}
	if !strings.HasPrefix(kp.PublicKey, "ssh-ed25519") {
		t.Errorf("PublicKey = %q, want it to start with ssh-ed25519", kp.PublicKey)
	}
}

func TestGenerateSSHKeyPairECDSA(t *testing.T) {
	tests := []struct {
		bits     int
		wantName string
	}{
		{256, "nistp256"},
		{384, "nistp384"},
		{521, "nistp521"},
		{999, "nistp256"}, // unknown bits default to P256
	}

	for _, tt := range tests {
		kp, err := GenerateSSHKeyPair("ecdsa", tt.bits)
		if err != nil {
			t.Fatalf("GenerateSSHKeyPair(ecdsa, %d) returned error: %v", tt.bits, err)
		}
		wantAlgo := "ecdsa-sha2-" + tt.wantName
		if kp.Algorithm != wantAlgo {
			t.Errorf("GenerateSSHKeyPair(ecdsa, %d).Algorithm = %q, want %q", tt.bits, kp.Algorithm, wantAlgo)
		}
		if !strings.Contains(kp.PublicKey, tt.wantName) {
			t.Errorf("GenerateSSHKeyPair(ecdsa, %d).PublicKey = %q, want it to mention %q", tt.bits, kp.PublicKey, tt.wantName)
		}
	}
}

func TestGenerateSSHKeyPairUnknownTypeDefaultsToRSA(t *testing.T) {
	kp, err := GenerateSSHKeyPair("bogus-type", 2048)
	if err != nil {
		t.Fatalf("GenerateSSHKeyPair(bogus-type) returned error: %v", err)
	}
	if kp.Algorithm != "ssh-rsa" {
		t.Errorf("GenerateSSHKeyPair(bogus-type).Algorithm = %q, want ssh-rsa", kp.Algorithm)
	}
}

func TestGenerateSelfSignedCert(t *testing.T) {
	cert, err := GenerateSelfSignedCert("example.com", 30, 2048)
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert returned error: %v", err)
	}

	if cert.Subject != "example.com" || cert.Issuer != "example.com" {
		t.Errorf("Subject/Issuer = %s/%s, want example.com/example.com", cert.Subject, cert.Issuer)
	}

	block, _ := pem.Decode(cert.CertPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatal("CertPEM did not decode to a CERTIFICATE block")
	}
	x509Cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse generated certificate: %v", err)
	}
	if len(x509Cert.DNSNames) != 1 || x509Cert.DNSNames[0] != "example.com" {
		t.Errorf("DNSNames = %v, want [example.com] because CN contains a dot", x509Cert.DNSNames)
	}

	wantDuration := 30 * 24
	gotDuration := int(cert.NotAfter.Sub(cert.NotBefore).Hours())
	if gotDuration < wantDuration-1 || gotDuration > wantDuration+1 {
		t.Errorf("cert validity duration = %dh, want ~%dh", gotDuration, wantDuration)
	}
}

func TestGenerateSelfSignedCertDefaultsAndNoDNSName(t *testing.T) {
	// days<1 and keyBits<2048 both get corrected to safe defaults; CN without a
	// dot should not get a DNSNames SAN.
	cert, err := GenerateSelfSignedCert("plainname", 0, 512)
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert returned error: %v", err)
	}

	block, _ := pem.Decode(cert.CertPEM)
	x509Cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse generated certificate: %v", err)
	}
	if len(x509Cert.DNSNames) != 0 {
		t.Errorf("DNSNames = %v, want none for a CN without a dot", x509Cert.DNSNames)
	}

	gotDays := int(cert.NotAfter.Sub(cert.NotBefore).Hours() / 24)
	if gotDays != 365 {
		t.Errorf("default validity = %d days, want 365", gotDays)
	}
}

func TestGenerateAESKey(t *testing.T) {
	tests := []struct {
		bits     int
		wantBits int
	}{
		{128, 128},
		{192, 192},
		{256, 256},
		{999, 256}, // invalid size defaults to 256
	}

	for _, tt := range tests {
		hexKey, raw, err := GenerateAESKey(tt.bits)
		if err != nil {
			t.Fatalf("GenerateAESKey(%d) returned error: %v", tt.bits, err)
		}
		wantLen := tt.wantBits / 8
		if len(raw) != wantLen {
			t.Errorf("GenerateAESKey(%d): raw key length = %d, want %d", tt.bits, len(raw), wantLen)
		}
		if len(hexKey) != wantLen*2 {
			t.Errorf("GenerateAESKey(%d): hex key length = %d, want %d", tt.bits, len(hexKey), wantLen*2)
		}
	}
}

func TestGenerateRandomBytes(t *testing.T) {
	hexStr, raw, err := GenerateRandomBytes(16)
	if err != nil {
		t.Fatalf("GenerateRandomBytes returned error: %v", err)
	}
	if len(raw) != 16 {
		t.Errorf("raw length = %d, want 16", len(raw))
	}
	if len(hexStr) != 32 {
		t.Errorf("hex length = %d, want 32", len(hexStr))
	}
}

func TestSaveKeyPair(t *testing.T) {
	dir := t.TempDir()
	kp := &KeyPair{
		PrivateKeyPEM: []byte("PRIVATE"),
		PublicKeyPEM:  []byte("PUBLIC"),
	}

	privPath := filepath.Join(dir, "key.priv")
	pubPath := filepath.Join(dir, "key.pub")

	if err := SaveKeyPair(kp, privPath, pubPath); err != nil {
		t.Fatalf("SaveKeyPair returned error: %v", err)
	}

	privData, err := os.ReadFile(privPath)
	if err != nil || string(privData) != "PRIVATE" {
		t.Errorf("private key file content = %q, err %v, want PRIVATE", privData, err)
	}
	pubData, err := os.ReadFile(pubPath)
	if err != nil || string(pubData) != "PUBLIC" {
		t.Errorf("public key file content = %q, err %v, want PUBLIC", pubData, err)
	}
}

func TestSaveKeyPairEmptyPaths(t *testing.T) {
	kp := &KeyPair{PrivateKeyPEM: []byte("x"), PublicKeyPEM: []byte("y")}
	if err := SaveKeyPair(kp, "", ""); err != nil {
		t.Errorf("SaveKeyPair with empty paths should not error, got: %v", err)
	}
}

func TestSaveKeyPairInvalidPath(t *testing.T) {
	kp := &KeyPair{PrivateKeyPEM: []byte("x")}
	if err := SaveKeyPair(kp, "/nonexistent/dir/key.priv", ""); err == nil {
		t.Error("SaveKeyPair with an invalid path should return an error")
	}
}

func TestSaveCertificate(t *testing.T) {
	dir := t.TempDir()
	cert := &CertificateInfo{CertPEM: []byte("CERT"), KeyPEM: []byte("KEY")}

	certPath := filepath.Join(dir, "c.pem")
	keyPath := filepath.Join(dir, "k.pem")

	if err := SaveCertificate(cert, certPath, keyPath); err != nil {
		t.Fatalf("SaveCertificate returned error: %v", err)
	}

	certData, err := os.ReadFile(certPath)
	if err != nil || string(certData) != "CERT" {
		t.Errorf("cert file content = %q, err %v, want CERT", certData, err)
	}
}

func TestSaveCertificateInvalidPath(t *testing.T) {
	cert := &CertificateInfo{CertPEM: []byte("CERT")}
	if err := SaveCertificate(cert, "/nonexistent/dir/c.pem", ""); err == nil {
		t.Error("SaveCertificate with an invalid path should return an error")
	}
}

// Display* functions only print to stdout; exercised here for coverage and to
// make sure they don't panic on both short and long field values.
func TestDisplayFunctionsDoNotPanic(t *testing.T) {
	shortKP, err := GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateEd25519KeyPair returned error: %v", err)
	}
	DisplayKeyPair(shortKP)

	longKP, err := GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("GenerateRSAKeyPair returned error: %v", err)
	}
	DisplayKeyPair(longKP)

	cert, err := GenerateSelfSignedCert("example.com", 30, 2048)
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert returned error: %v", err)
	}
	DisplayCertificate(cert)

	hexKey, _, err := GenerateAESKey(256)
	if err != nil {
		t.Fatalf("GenerateAESKey returned error: %v", err)
	}
	DisplayAESKey(hexKey, 256)
}
