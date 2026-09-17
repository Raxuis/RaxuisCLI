// Package tlsscan performs a passive TLS/SSL posture assessment of a server:
// which protocol versions and cipher suites it accepts, its certificate health,
// and the weaknesses those imply. It only completes ordinary handshakes, so it
// is safe to run against systems you are authorized to test.
package tlsscan

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"
)

// Severity ranks a finding from informational to critical.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

// Finding is a single weakness or notable observation.
type Finding struct {
	ID       string   `json:"id"`
	Title    string   `json:"title"`
	Severity Severity `json:"severity"`
	Detail   string   `json:"detail,omitempty"`
}

// ProtocolResult records whether a protocol version was accepted.
type ProtocolResult struct {
	Name      string `json:"name"`
	Supported bool   `json:"supported"`
}

// CipherResult records an accepted cipher suite for a protocol version.
type CipherResult struct {
	Protocol       string `json:"protocol"`
	Name           string `json:"name"`
	Insecure       bool   `json:"insecure"`
	ForwardSecrecy bool   `json:"forward_secrecy"`
}

// CertSummary is the certificate posture of the scanned host.
type CertSummary struct {
	Subject            string    `json:"subject"`
	Issuer             string    `json:"issuer"`
	NotBefore          time.Time `json:"not_before"`
	NotAfter           time.Time `json:"not_after"`
	DaysToExpiry       int       `json:"days_to_expiry"`
	SignatureAlgorithm string    `json:"signature_algorithm"`
	KeyType            string    `json:"key_type"`
	KeyBits            int       `json:"key_bits"`
	SelfSigned         bool      `json:"self_signed"`
	HostnameValid      bool      `json:"hostname_valid"`
}

// Result is the complete assessment for one host:port.
type Result struct {
	Host        string           `json:"host"`
	Port        int              `json:"port"`
	Protocols   []ProtocolResult `json:"protocols"`
	Ciphers     []CipherResult   `json:"ciphers"`
	Certificate *CertSummary     `json:"certificate,omitempty"`
	Findings    []Finding        `json:"findings"`
	Error       string           `json:"error,omitempty"`
}

var probedVersions = []struct {
	name    string
	version uint16
}{
	{"TLS 1.0", tls.VersionTLS10},
	{"TLS 1.1", tls.VersionTLS11},
	{"TLS 1.2", tls.VersionTLS12},
	{"TLS 1.3", tls.VersionTLS13},
}

// Scan assesses host on the given port. A zero or negative timeout defaults to
// 10 seconds per connection.
func Scan(host string, port int, timeout time.Duration) *Result {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	result := &Result{Host: host, Port: port}

	for _, pv := range probedVersions {
		supported := probeProtocol(addr, host, pv.version, timeout)
		result.Protocols = append(result.Protocols, ProtocolResult{Name: pv.name, Supported: supported})
	}

	if !anyProtocolSupported(result.Protocols) {
		result.Error = "no TLS handshake succeeded (host unreachable, not TLS, or all versions rejected)"
		return result
	}

	result.Ciphers = enumerateCiphers(addr, host, timeout)
	result.Certificate = fetchCertificate(addr, host, timeout)
	result.Findings = deriveFindings(result)
	return result
}

func probeProtocol(addr, serverName string, version uint16, timeout time.Duration) bool {
	conf := &tls.Config{
		InsecureSkipVerify: true, // #nosec G402 -- we assess the cert ourselves; connecting is the point
		MinVersion:         version,
		MaxVersion:         version,
		ServerName:         serverName,
	}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp", addr, conf)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// enumerateCiphers probes, one suite at a time, which cipher suites the server
// accepts for TLS 1.0-1.2. TLS 1.3 suites are not configurable in the standard
// library, so they are reported from the negotiated connection instead.
func enumerateCiphers(addr, serverName string, timeout time.Duration) []CipherResult {
	var out []CipherResult
	seen := map[string]bool{}

	legacy := []struct {
		name    string
		version uint16
	}{
		{"TLS 1.0", tls.VersionTLS10},
		{"TLS 1.1", tls.VersionTLS11},
		{"TLS 1.2", tls.VersionTLS12},
	}

	all := append(tls.CipherSuites(), tls.InsecureCipherSuites()...)
	for _, lv := range legacy {
		for _, suite := range all {
			if !supportsVersion(suite.SupportedVersions, lv.version) {
				continue
			}
			if !probeCipher(addr, serverName, lv.version, suite.ID, timeout) {
				continue
			}
			key := lv.name + "|" + suite.Name
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, CipherResult{
				Protocol:       lv.name,
				Name:           suite.Name,
				Insecure:       suite.Insecure,
				ForwardSecrecy: hasForwardSecrecy(suite.Name),
			})
		}
	}

	// TLS 1.3: report the suite the server negotiates (not individually selectable).
	if state, ok := negotiate(addr, serverName, tls.VersionTLS13, timeout); ok {
		name := tls.CipherSuiteName(state.CipherSuite)
		key := "TLS 1.3|" + name
		if !seen[key] {
			out = append(out, CipherResult{
				Protocol:       "TLS 1.3",
				Name:           name,
				Insecure:       false,
				ForwardSecrecy: true, // all TLS 1.3 suites provide forward secrecy
			})
		}
	}

	return out
}

func probeCipher(addr, serverName string, version, suite uint16, timeout time.Duration) bool {
	conf := &tls.Config{
		InsecureSkipVerify: true, // #nosec G402
		MinVersion:         version,
		MaxVersion:         version,
		CipherSuites:       []uint16{suite},
		ServerName:         serverName,
	}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp", addr, conf)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func negotiate(addr, serverName string, version uint16, timeout time.Duration) (tls.ConnectionState, bool) {
	conf := &tls.Config{
		InsecureSkipVerify: true, // #nosec G402
		MinVersion:         version,
		MaxVersion:         version,
		ServerName:         serverName,
	}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp", addr, conf)
	if err != nil {
		return tls.ConnectionState{}, false
	}
	defer conn.Close()
	return conn.ConnectionState(), true
}

func fetchCertificate(addr, serverName string, timeout time.Duration) *CertSummary {
	conf := &tls.Config{
		InsecureSkipVerify: true, // #nosec G402 -- posture assessment, not trust enforcement
		ServerName:         serverName,
	}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp", addr, conf)
	if err != nil {
		return nil
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil
	}
	leaf := certs[0]

	keyType, keyBits := keyInfo(leaf.PublicKey)
	summary := &CertSummary{
		Subject:            leaf.Subject.String(),
		Issuer:             leaf.Issuer.String(),
		NotBefore:          leaf.NotBefore,
		NotAfter:           leaf.NotAfter,
		DaysToExpiry:       int(time.Until(leaf.NotAfter).Hours() / 24),
		SignatureAlgorithm: leaf.SignatureAlgorithm.String(),
		KeyType:            keyType,
		KeyBits:            keyBits,
		SelfSigned:         leaf.Subject.String() == leaf.Issuer.String(),
		HostnameValid:      leaf.VerifyHostname(serverName) == nil,
	}
	return summary
}

func keyInfo(pub any) (string, int) {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return "RSA", k.N.BitLen()
	case *ecdsa.PublicKey:
		return "ECDSA", k.Curve.Params().BitSize
	default:
		return fmt.Sprintf("%T", pub), 0
	}
}

func deriveFindings(r *Result) []Finding {
	var findings []Finding
	supported := map[string]bool{}
	for _, p := range r.Protocols {
		supported[p.Name] = p.Supported
	}

	if supported["TLS 1.0"] {
		findings = append(findings, Finding{
			ID: "protocol-tls10", Title: "TLS 1.0 enabled", Severity: SeverityMedium,
			Detail: "TLS 1.0 is deprecated (RFC 8996) and vulnerable to attacks such as BEAST. Disable it.",
		})
	}
	if supported["TLS 1.1"] {
		findings = append(findings, Finding{
			ID: "protocol-tls11", Title: "TLS 1.1 enabled", Severity: SeverityMedium,
			Detail: "TLS 1.1 is deprecated (RFC 8996). Disable it in favor of TLS 1.2+.",
		})
	}
	if !supported["TLS 1.2"] && !supported["TLS 1.3"] {
		findings = append(findings, Finding{
			ID: "protocol-no-modern", Title: "No modern TLS (1.2/1.3)", Severity: SeverityHigh,
			Detail: "The server offers only deprecated protocol versions.",
		})
	}
	if !supported["TLS 1.3"] {
		findings = append(findings, Finding{
			ID: "protocol-no-tls13", Title: "TLS 1.3 not supported", Severity: SeverityLow,
			Detail: "TLS 1.3 is faster and more secure; enabling it is recommended.",
		})
	}

	hasFS := false
	seenWeak := map[string]bool{}
	for _, c := range r.Ciphers {
		if c.ForwardSecrecy {
			hasFS = true
		}
		if seenWeak[c.Name] {
			continue // report each weak suite once, not once per protocol
		}
		var f *Finding
		switch {
		case strings.Contains(c.Name, "RC4"):
			f = &Finding{
				ID: "cipher-rc4", Title: "RC4 cipher accepted: " + c.Name, Severity: SeverityHigh,
				Detail: "RC4 has biased keystream weaknesses and is prohibited (RFC 7465).",
			}
		case strings.Contains(c.Name, "3DES") || strings.Contains(c.Name, "DES_EDE"):
			f = &Finding{
				ID: "cipher-3des", Title: "3DES cipher accepted: " + c.Name, Severity: SeverityMedium,
				Detail: "3DES is vulnerable to the SWEET32 birthday attack (CVE-2016-2183).",
			}
		case c.Insecure:
			f = &Finding{
				ID: "cipher-weak", Title: "Weak cipher accepted: " + c.Name, Severity: SeverityLow,
				Detail: "Flagged insecure: RSA key exchange (no forward secrecy) or a CBC-mode risk (e.g. Lucky13).",
			}
		}
		if f != nil {
			seenWeak[c.Name] = true
			findings = append(findings, *f)
		}
	}
	if len(r.Ciphers) > 0 && !hasFS {
		findings = append(findings, Finding{
			ID: "no-forward-secrecy", Title: "No forward secrecy", Severity: SeverityMedium,
			Detail: "No ECDHE/DHE suite was accepted; captured traffic is decryptable if the key leaks.",
		})
	}

	findings = append(findings, certFindings(r.Certificate)...)

	sortBySeverity(findings)
	return findings
}

func certFindings(c *CertSummary) []Finding {
	if c == nil {
		return nil
	}
	var findings []Finding
	now := time.Now()

	switch {
	case now.After(c.NotAfter):
		findings = append(findings, Finding{
			ID: "cert-expired", Title: "Certificate expired", Severity: SeverityCritical,
			Detail: fmt.Sprintf("Expired on %s.", c.NotAfter.Format("2006-01-02")),
		})
	case c.DaysToExpiry <= 30:
		findings = append(findings, Finding{
			ID: "cert-expiring", Title: "Certificate expiring soon", Severity: SeverityMedium,
			Detail: fmt.Sprintf("Expires in %d day(s).", c.DaysToExpiry),
		})
	}
	if now.Before(c.NotBefore) {
		findings = append(findings, Finding{
			ID: "cert-not-yet-valid", Title: "Certificate not yet valid", Severity: SeverityHigh,
			Detail: fmt.Sprintf("Not valid before %s.", c.NotBefore.Format("2006-01-02")),
		})
	}
	if c.SelfSigned {
		findings = append(findings, Finding{
			ID: "cert-self-signed", Title: "Self-signed certificate", Severity: SeverityMedium,
			Detail: "The certificate is not issued by a trusted CA.",
		})
	}
	if !c.HostnameValid {
		findings = append(findings, Finding{
			ID: "cert-hostname", Title: "Hostname mismatch", Severity: SeverityHigh,
			Detail: "The certificate is not valid for the scanned hostname.",
		})
	}
	if weakSignature(c.SignatureAlgorithm) {
		findings = append(findings, Finding{
			ID: "cert-weak-sig", Title: "Weak signature algorithm: " + c.SignatureAlgorithm, Severity: SeverityHigh,
			Detail: "SHA-1 and MD5 signatures are collision-prone and untrusted.",
		})
	}
	if c.KeyType == "RSA" && c.KeyBits > 0 && c.KeyBits < 2048 {
		findings = append(findings, Finding{
			ID: "cert-weak-key", Title: fmt.Sprintf("Weak RSA key (%d bits)", c.KeyBits), Severity: SeverityHigh,
			Detail: "RSA keys shorter than 2048 bits are considered insecure.",
		})
	}
	return findings
}

func weakSignature(algo string) bool {
	a := strings.ToUpper(algo)
	return strings.Contains(a, "SHA1") || strings.Contains(a, "MD5")
}

func hasForwardSecrecy(name string) bool {
	return strings.Contains(name, "ECDHE") || strings.Contains(name, "DHE")
}

func supportsVersion(versions []uint16, target uint16) bool {
	for _, v := range versions {
		if v == target {
			return true
		}
	}
	return false
}

func anyProtocolSupported(protocols []ProtocolResult) bool {
	for _, p := range protocols {
		if p.Supported {
			return true
		}
	}
	return false
}

var severityRank = map[Severity]int{
	SeverityCritical: 0,
	SeverityHigh:     1,
	SeverityMedium:   2,
	SeverityLow:      3,
	SeverityInfo:     4,
}

func sortBySeverity(findings []Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		return severityRank[findings[i].Severity] < severityRank[findings[j].Severity]
	})
}

// Grade summarizes findings as a letter grade for quick human reading.
func (r *Result) Grade() string {
	worst := 5
	for _, f := range r.Findings {
		if rank, ok := severityRank[f.Severity]; ok && rank < worst {
			worst = rank
		}
	}
	switch worst {
	case 0:
		return "F"
	case 1:
		return "D"
	case 2:
		return "C"
	case 3:
		return "B"
	default:
		return "A"
	}
}
