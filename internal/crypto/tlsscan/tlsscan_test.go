package tlsscan

import (
	"testing"
	"time"
)

func findingIDs(findings []Finding) map[string]Severity {
	out := map[string]Severity{}
	for _, f := range findings {
		out[f.ID] = f.Severity
	}
	return out
}

func TestDeriveFindingsProtocols(t *testing.T) {
	r := &Result{
		Protocols: []ProtocolResult{
			{Name: "TLS 1.0", Supported: true},
			{Name: "TLS 1.1", Supported: true},
			{Name: "TLS 1.2", Supported: true},
			{Name: "TLS 1.3", Supported: false},
		},
		Ciphers: []CipherResult{
			{Protocol: "TLS 1.2", Name: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", ForwardSecrecy: true},
		},
	}
	got := findingIDs(deriveFindings(r))

	for _, id := range []string{"protocol-tls10", "protocol-tls11", "protocol-no-tls13"} {
		if _, ok := got[id]; !ok {
			t.Errorf("expected finding %q, got %v", id, got)
		}
	}
	if _, ok := got["protocol-no-modern"]; ok {
		t.Error("did not expect protocol-no-modern when TLS 1.2 is supported")
	}
}

func TestDeriveFindingsDedupesWeakCiphers(t *testing.T) {
	name := "TLS_RSA_WITH_AES_128_CBC_SHA"
	r := &Result{
		Protocols: []ProtocolResult{{Name: "TLS 1.2", Supported: true}, {Name: "TLS 1.3", Supported: true}},
		Ciphers: []CipherResult{
			{Protocol: "TLS 1.0", Name: name, Insecure: true},
			{Protocol: "TLS 1.1", Name: name, Insecure: true},
			{Protocol: "TLS 1.2", Name: name, Insecure: true},
		},
	}
	count := 0
	for _, f := range deriveFindings(r) {
		if f.ID == "cipher-weak" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected a single deduped cipher-weak finding, got %d", count)
	}
}

func TestDeriveFindingsClassifiesCiphers(t *testing.T) {
	r := &Result{
		Protocols: []ProtocolResult{{Name: "TLS 1.2", Supported: true}, {Name: "TLS 1.3", Supported: true}},
		Ciphers: []CipherResult{
			{Protocol: "TLS 1.2", Name: "TLS_RSA_WITH_RC4_128_SHA", Insecure: true},
			{Protocol: "TLS 1.2", Name: "TLS_RSA_WITH_3DES_EDE_CBC_SHA", Insecure: true},
		},
	}
	got := findingIDs(deriveFindings(r))
	if got["cipher-rc4"] != SeverityHigh {
		t.Errorf("expected RC4 high finding, got %v", got)
	}
	if got["cipher-3des"] != SeverityMedium {
		t.Errorf("expected 3DES medium finding, got %v", got)
	}
	if _, ok := got["no-forward-secrecy"]; !ok {
		t.Error("expected no-forward-secrecy finding when no FS suite is present")
	}
}

func TestCertFindings(t *testing.T) {
	expired := &CertSummary{
		NotBefore: time.Now().Add(-2 * time.Hour),
		NotAfter:  time.Now().Add(-1 * time.Hour),
	}
	got := findingIDs(certFindings(expired))
	if got["cert-expired"] != SeverityCritical {
		t.Errorf("expected cert-expired critical, got %v", got)
	}

	weakKey := &CertSummary{
		NotBefore:          time.Now().Add(-time.Hour),
		NotAfter:           time.Now().Add(365 * 24 * time.Hour),
		DaysToExpiry:       365,
		SignatureAlgorithm: "SHA1-RSA",
		KeyType:            "RSA",
		KeyBits:            1024,
		HostnameValid:      true,
	}
	got = findingIDs(certFindings(weakKey))
	if got["cert-weak-sig"] != SeverityHigh {
		t.Errorf("expected cert-weak-sig high, got %v", got)
	}
	if got["cert-weak-key"] != SeverityHigh {
		t.Errorf("expected cert-weak-key high, got %v", got)
	}
}

func TestGrade(t *testing.T) {
	cases := []struct {
		sev  Severity
		want string
	}{
		{SeverityCritical, "F"},
		{SeverityHigh, "D"},
		{SeverityMedium, "C"},
		{SeverityLow, "B"},
	}
	for _, c := range cases {
		r := &Result{Findings: []Finding{{Severity: c.sev}}}
		if got := r.Grade(); got != c.want {
			t.Errorf("severity %s: grade = %q, want %q", c.sev, got, c.want)
		}
	}
	clean := &Result{}
	if got := clean.Grade(); got != "A" {
		t.Errorf("no findings: grade = %q, want A", got)
	}
}

func TestHelpers(t *testing.T) {
	if !weakSignature("SHA1-RSA") || !weakSignature("MD5-RSA") {
		t.Error("SHA1/MD5 should be weak")
	}
	if weakSignature("ECDSA-SHA256") {
		t.Error("SHA256 should not be weak")
	}
	if !hasForwardSecrecy("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256") {
		t.Error("ECDHE should have forward secrecy")
	}
	if hasForwardSecrecy("TLS_RSA_WITH_AES_128_GCM_SHA256") {
		t.Error("RSA key exchange has no forward secrecy")
	}
}
