package certinfo

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// CertInfo holds certificate information
type CertInfo struct {
	Subject            string
	Issuer             string
	SerialNumber       string
	NotBefore          time.Time
	NotAfter           time.Time
	PublicKeyAlgorithm string
	SignatureAlgorithm string
	KeyUsage           []string
	ExtKeyUsage        []string
	DNSNames           []string
	IPAddresses        []string
	EmailAddresses     []string
	IsCA               bool
	Version            int
	Fingerprint        string
	Raw                *x509.Certificate
}

// ChainInfo holds certificate chain information
type ChainInfo struct {
	Certificates []CertInfo
	Host         string
	Port         int
	Valid        bool
	Error        string
	// VerificationError preserves the concrete x509 error for callers that
	// need to distinguish trust-chain failures from hostname, validity, and
	// key-usage failures. It is runtime-only and never serialized.
	VerificationError error `json:"-"`
	TLSVersion        uint16
	CipherSuite       uint16
}

// ValidationResult holds validation results
type ValidationResult struct {
	Valid        bool
	Expired      bool
	NotYetValid  bool
	SelfSigned   bool
	ChainErrors  []string
	Warnings     []string
	DaysToExpiry int
}

// GetCertFromHost retrieves certificate from a remote host
func GetCertFromHost(host string, port int, timeout int) (*ChainInfo, error) {
	ctx := context.Background()
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
		defer cancel()
	}
	return GetCertFromHostContext(ctx, host, port)
}

// GetCertFromHostContext retrieves a host's certificate chain while honoring
// cancellation and deadlines supplied by the caller. GetCertFromHost remains
// available for existing timeout-based callers.
func GetCertFromHostContext(ctx context.Context, host string, port int) (*ChainInfo, error) {
	if port == 0 {
		port = 443
	}

	address := net.JoinHostPort(host, strconv.Itoa(port))
	dialer := &net.Dialer{}
	rawConnection, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, fmt.Errorf("failed to connect: %w", err)
	}
	conn := tls.Client(rawConnection, &tls.Config{InsecureSkipVerify: true, ServerName: host})
	defer conn.Close()
	if err := conn.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("failed to connect: %w", err)
	}

	chain := &ChainInfo{
		Host: host,
		Port: port,
	}

	state := conn.ConnectionState()
	chain.TLSVersion = state.Version
	chain.CipherSuite = state.CipherSuite
	certs := state.PeerCertificates
	for _, cert := range certs {
		chain.Certificates = append(chain.Certificates, parseCertificate(cert))
	}

	// Check if chain is valid
	if len(certs) > 0 {
		_, err := certs[0].Verify(x509.VerifyOptions{
			DNSName: host,
		})
		chain.Valid = err == nil
		if err != nil {
			chain.Error = err.Error()
			chain.VerificationError = err
		}
	}

	return chain, nil
}

// GetCertFromFile reads certificate from a file
func GetCertFromFile(filepath string) (*ChainInfo, error) {
	data, err := os.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %v", err)
	}

	chain := &ChainInfo{}

	// Try to parse PEM certificates
	for {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}

		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				continue
			}
			chain.Certificates = append(chain.Certificates, parseCertificate(cert))
		}

		data = rest
	}

	// If no PEM found, try DER
	if len(chain.Certificates) == 0 {
		data, _ = os.ReadFile(filepath)
		cert, err := x509.ParseCertificate(data)
		if err == nil {
			chain.Certificates = append(chain.Certificates, parseCertificate(cert))
		}
	}

	if len(chain.Certificates) == 0 {
		return nil, fmt.Errorf("no certificates found in file")
	}

	return chain, nil
}

// parseCertificate extracts information from x509.Certificate
func parseCertificate(cert *x509.Certificate) CertInfo {
	info := CertInfo{
		Subject:            cert.Subject.String(),
		Issuer:             cert.Issuer.String(),
		SerialNumber:       fmt.Sprintf("%x", cert.SerialNumber),
		NotBefore:          cert.NotBefore,
		NotAfter:           cert.NotAfter,
		PublicKeyAlgorithm: cert.PublicKeyAlgorithm.String(),
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		DNSNames:           cert.DNSNames,
		EmailAddresses:     cert.EmailAddresses,
		IsCA:               cert.IsCA,
		Version:            cert.Version,
		Raw:                cert,
	}

	// Extract IP addresses
	for _, ip := range cert.IPAddresses {
		info.IPAddresses = append(info.IPAddresses, ip.String())
	}

	// Extract key usage
	info.KeyUsage = parseKeyUsage(cert.KeyUsage)

	// Extract extended key usage
	info.ExtKeyUsage = parseExtKeyUsage(cert.ExtKeyUsage)

	return info
}

// parseKeyUsage converts key usage flags to strings
func parseKeyUsage(usage x509.KeyUsage) []string {
	var result []string

	usages := map[x509.KeyUsage]string{
		x509.KeyUsageDigitalSignature:  "Digital Signature",
		x509.KeyUsageContentCommitment: "Content Commitment",
		x509.KeyUsageKeyEncipherment:   "Key Encipherment",
		x509.KeyUsageDataEncipherment:  "Data Encipherment",
		x509.KeyUsageKeyAgreement:      "Key Agreement",
		x509.KeyUsageCertSign:          "Certificate Sign",
		x509.KeyUsageCRLSign:           "CRL Sign",
		x509.KeyUsageEncipherOnly:      "Encipher Only",
		x509.KeyUsageDecipherOnly:      "Decipher Only",
	}

	for flag, name := range usages {
		if usage&flag != 0 {
			result = append(result, name)
		}
	}

	return result
}

// parseExtKeyUsage converts extended key usage to strings
func parseExtKeyUsage(usages []x509.ExtKeyUsage) []string {
	var result []string

	names := map[x509.ExtKeyUsage]string{
		x509.ExtKeyUsageAny:                            "Any",
		x509.ExtKeyUsageServerAuth:                     "Server Authentication",
		x509.ExtKeyUsageClientAuth:                     "Client Authentication",
		x509.ExtKeyUsageCodeSigning:                    "Code Signing",
		x509.ExtKeyUsageEmailProtection:                "Email Protection",
		x509.ExtKeyUsageIPSECEndSystem:                 "IPSEC End System",
		x509.ExtKeyUsageIPSECTunnel:                    "IPSEC Tunnel",
		x509.ExtKeyUsageIPSECUser:                      "IPSEC User",
		x509.ExtKeyUsageTimeStamping:                   "Time Stamping",
		x509.ExtKeyUsageOCSPSigning:                    "OCSP Signing",
		x509.ExtKeyUsageMicrosoftServerGatedCrypto:     "Microsoft Server Gated Crypto",
		x509.ExtKeyUsageNetscapeServerGatedCrypto:      "Netscape Server Gated Crypto",
		x509.ExtKeyUsageMicrosoftCommercialCodeSigning: "Microsoft Commercial Code Signing",
		x509.ExtKeyUsageMicrosoftKernelCodeSigning:     "Microsoft Kernel Code Signing",
	}

	for _, usage := range usages {
		if name, ok := names[usage]; ok {
			result = append(result, name)
		}
	}

	return result
}

// ValidateCertificate performs validation checks
func ValidateCertificate(info *CertInfo) *ValidationResult {
	result := &ValidationResult{
		Valid: true,
	}

	now := time.Now()

	// Check expiration
	if now.After(info.NotAfter) {
		result.Valid = false
		result.Expired = true
		result.ChainErrors = append(result.ChainErrors, "Certificate has expired")
	}

	// Check not yet valid
	if now.Before(info.NotBefore) {
		result.Valid = false
		result.NotYetValid = true
		result.ChainErrors = append(result.ChainErrors, "Certificate is not yet valid")
	}

	// Calculate days to expiry
	result.DaysToExpiry = int(info.NotAfter.Sub(now).Hours() / 24)

	// Check self-signed
	if info.Subject == info.Issuer {
		result.SelfSigned = true
		result.Warnings = append(result.Warnings, "Certificate is self-signed")
	}

	// Check for soon-to-expire (30 days)
	if result.DaysToExpiry > 0 && result.DaysToExpiry < 30 {
		result.Warnings = append(result.Warnings, fmt.Sprintf("Certificate expires in %d days", result.DaysToExpiry))
	}

	// Check for weak signature algorithm
	weakAlgos := []string{"MD5", "SHA1"}
	for _, weak := range weakAlgos {
		if strings.Contains(info.SignatureAlgorithm, weak) {
			result.Warnings = append(result.Warnings, fmt.Sprintf("Weak signature algorithm: %s", info.SignatureAlgorithm))
			break
		}
	}

	// Check key size for RSA
	if info.Raw != nil && info.PublicKeyAlgorithm == "RSA" {
		if info.Raw.PublicKey != nil {
			// This is a simplified check
			if strings.Contains(info.PublicKeyAlgorithm, "1024") {
				result.Warnings = append(result.Warnings, "RSA key size may be too small (1024 bits)")
			}
		}
	}

	return result
}

// DisplayCertInfo displays certificate information
func DisplayCertInfo(info *CertInfo) {
	fmt.Println("\n[CERTIFICATE INFORMATION]")
	fmt.Println(strings.Repeat("=", 70))

	fmt.Printf("\nSubject: %s\n", info.Subject)
	fmt.Printf("Issuer:  %s\n", info.Issuer)

	fmt.Printf("\nSerial Number: %s\n", info.SerialNumber)
	fmt.Printf("Version:       %d\n", info.Version)

	fmt.Println("\n[Validity]")
	fmt.Printf("Not Before: %s\n", info.NotBefore.Format(time.RFC3339))
	fmt.Printf("Not After:  %s\n", info.NotAfter.Format(time.RFC3339))

	daysLeft := int(time.Until(info.NotAfter).Hours() / 24)
	if daysLeft > 0 {
		fmt.Printf("Days Left:  %d\n", daysLeft)
	} else {
		fmt.Printf("Status:     EXPIRED (%d days ago)\n", -daysLeft)
	}

	fmt.Println("\n[Algorithms]")
	fmt.Printf("Public Key: %s\n", info.PublicKeyAlgorithm)
	fmt.Printf("Signature:  %s\n", info.SignatureAlgorithm)

	if len(info.KeyUsage) > 0 {
		fmt.Println("\n[Key Usage]")
		for _, usage := range info.KeyUsage {
			fmt.Printf("  - %s\n", usage)
		}
	}

	if len(info.ExtKeyUsage) > 0 {
		fmt.Println("\n[Extended Key Usage]")
		for _, usage := range info.ExtKeyUsage {
			fmt.Printf("  - %s\n", usage)
		}
	}

	if len(info.DNSNames) > 0 {
		fmt.Println("\n[Subject Alternative Names - DNS]")
		for _, name := range info.DNSNames {
			fmt.Printf("  - %s\n", name)
		}
	}

	if len(info.IPAddresses) > 0 {
		fmt.Println("\n[Subject Alternative Names - IP]")
		for _, ip := range info.IPAddresses {
			fmt.Printf("  - %s\n", ip)
		}
	}

	if len(info.EmailAddresses) > 0 {
		fmt.Println("\n[Email Addresses]")
		for _, email := range info.EmailAddresses {
			fmt.Printf("  - %s\n", email)
		}
	}

	fmt.Printf("\nIs CA: %v\n", info.IsCA)
}

// DisplayChain displays certificate chain
func DisplayChain(chain *ChainInfo) {
	fmt.Println("\n[CERTIFICATE CHAIN]")
	fmt.Println(strings.Repeat("=", 70))

	if chain.Host != "" {
		fmt.Printf("Host: %s:%d\n", chain.Host, chain.Port)
		if chain.Valid {
			fmt.Println("Chain Status: VALID")
		} else {
			fmt.Printf("Chain Status: INVALID - %s\n", chain.Error)
		}
	}

	fmt.Printf("Certificates in chain: %d\n", len(chain.Certificates))

	for i, cert := range chain.Certificates {
		fmt.Printf("\n[Certificate %d]", i+1)
		if i == 0 {
			fmt.Print(" (End Entity)")
		} else if cert.IsCA {
			fmt.Print(" (CA)")
		}
		fmt.Println()
		fmt.Println(strings.Repeat("-", 50))

		fmt.Printf("Subject: %s\n", cert.Subject)
		fmt.Printf("Issuer:  %s\n", cert.Issuer)
		fmt.Printf("Valid:   %s to %s\n",
			cert.NotBefore.Format("2006-01-02"),
			cert.NotAfter.Format("2006-01-02"))

		daysLeft := int(time.Until(cert.NotAfter).Hours() / 24)
		if daysLeft > 0 {
			fmt.Printf("Expires: in %d days\n", daysLeft)
		} else {
			fmt.Printf("Expires: EXPIRED %d days ago\n", -daysLeft)
		}
	}
}

// DisplayValidation displays validation results
func DisplayValidation(result *ValidationResult) {
	fmt.Println("\n[VALIDATION RESULTS]")
	fmt.Println(strings.Repeat("=", 70))

	if result.Valid {
		fmt.Println("Status: VALID")
	} else {
		fmt.Println("Status: INVALID")
	}

	if result.SelfSigned {
		fmt.Println("Type:   Self-Signed")
	}

	if result.DaysToExpiry > 0 {
		fmt.Printf("Expiry: %d days remaining\n", result.DaysToExpiry)
	}

	if len(result.ChainErrors) > 0 {
		fmt.Println("\n[Errors]")
		for _, err := range result.ChainErrors {
			fmt.Printf("  [!] %s\n", err)
		}
	}

	if len(result.Warnings) > 0 {
		fmt.Println("\n[Warnings]")
		for _, warn := range result.Warnings {
			fmt.Printf("  [*] %s\n", warn)
		}
	}
}

// CompareCertificates compares two certificates
func CompareCertificates(cert1, cert2 *CertInfo) {
	fmt.Println("\n[CERTIFICATE COMPARISON]")
	fmt.Println(strings.Repeat("=", 70))

	fmt.Printf("%-20s %-25s %-25s\n", "Field", "Certificate 1", "Certificate 2")
	fmt.Println(strings.Repeat("-", 70))

	printCompare := func(field, val1, val2 string) {
		match := ""
		if val1 != val2 {
			match = " [DIFFERENT]"
		}
		// Truncate long values
		if len(val1) > 24 {
			val1 = val1[:21] + "..."
		}
		if len(val2) > 24 {
			val2 = val2[:21] + "..."
		}
		fmt.Printf("%-20s %-25s %-25s%s\n", field, val1, val2, match)
	}

	printCompare("Serial", cert1.SerialNumber[:min(24, len(cert1.SerialNumber))],
		cert2.SerialNumber[:min(24, len(cert2.SerialNumber))])
	printCompare("Not Before", cert1.NotBefore.Format("2006-01-02"),
		cert2.NotBefore.Format("2006-01-02"))
	printCompare("Not After", cert1.NotAfter.Format("2006-01-02"),
		cert2.NotAfter.Format("2006-01-02"))
	printCompare("Algorithm", cert1.SignatureAlgorithm, cert2.SignatureAlgorithm)
	printCompare("Is CA", fmt.Sprintf("%v", cert1.IsCA), fmt.Sprintf("%v", cert2.IsCA))
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
