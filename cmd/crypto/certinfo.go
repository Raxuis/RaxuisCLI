package crypto

import (
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/Raxuis/RaxuisCLI/cmd"
	"github.com/Raxuis/RaxuisCLI/internal/crypto/certinfo"
	sharedcommand "github.com/Raxuis/RaxuisCLI/internal/shared/command"
	"github.com/Raxuis/RaxuisCLI/internal/shared/output"
)

// certInfoView is the machine-readable shape of a certificate; it drops the
// raw *x509.Certificate to keep the JSON clean.
type certInfoView struct {
	Subject            string    `json:"subject"`
	Issuer             string    `json:"issuer"`
	SerialNumber       string    `json:"serial_number"`
	NotBefore          time.Time `json:"not_before"`
	NotAfter           time.Time `json:"not_after"`
	PublicKeyAlgorithm string    `json:"public_key_algorithm"`
	SignatureAlgorithm string    `json:"signature_algorithm"`
	KeyUsage           []string  `json:"key_usage,omitempty"`
	ExtKeyUsage        []string  `json:"ext_key_usage,omitempty"`
	DNSNames           []string  `json:"dns_names,omitempty"`
	IPAddresses        []string  `json:"ip_addresses,omitempty"`
	EmailAddresses     []string  `json:"email_addresses,omitempty"`
	IsCA               bool      `json:"is_ca"`
	Version            int       `json:"version"`
	Fingerprint        string    `json:"fingerprint"`
}

func certInfoToView(c *certinfo.CertInfo) certInfoView {
	return certInfoView{
		Subject:            c.Subject,
		Issuer:             c.Issuer,
		SerialNumber:       c.SerialNumber,
		NotBefore:          c.NotBefore,
		NotAfter:           c.NotAfter,
		PublicKeyAlgorithm: c.PublicKeyAlgorithm,
		SignatureAlgorithm: c.SignatureAlgorithm,
		KeyUsage:           c.KeyUsage,
		ExtKeyUsage:        c.ExtKeyUsage,
		DNSNames:           c.DNSNames,
		IPAddresses:        c.IPAddresses,
		EmailAddresses:     c.EmailAddresses,
		IsCA:               c.IsCA,
		Version:            c.Version,
		Fingerprint:        c.Fingerprint,
	}
}

type validationView struct {
	Valid        bool     `json:"valid"`
	Expired      bool     `json:"expired"`
	NotYetValid  bool     `json:"not_yet_valid"`
	SelfSigned   bool     `json:"self_signed"`
	ChainErrors  []string `json:"chain_errors,omitempty"`
	Warnings     []string `json:"warnings,omitempty"`
	DaysToExpiry int      `json:"days_to_expiry"`
}

func validationToView(v *certinfo.ValidationResult) validationView {
	return validationView{
		Valid:        v.Valid,
		Expired:      v.Expired,
		NotYetValid:  v.NotYetValid,
		SelfSigned:   v.SelfSigned,
		ChainErrors:  v.ChainErrors,
		Warnings:     v.Warnings,
		DaysToExpiry: v.DaysToExpiry,
	}
}

const defaultCertinfoPort = 443

var (
	getCertFromFile = certinfo.GetCertFromFile
	getCertFromHost = certinfo.GetCertFromHost

	certinfoCmd = newCertinfoCommand()
)

func newCertinfoCommand() *cobra.Command {
	command := &cobra.Command{
		Use:   "certinfo [host|file]",
		Short: "Analyze X.509 certificates",
		Long: `Retrieve and analyze X.509 certificates from servers or files.

Examples:
  raxuiscli certinfo example.com
  raxuiscli certinfo example.com:8443
  raxuiscli certinfo cert.pem
  raxuiscli certinfo example.com --chain`,
		Args: exactCertinfoArgs(1),
		RunE: func(command *cobra.Command, args []string) error {
			return runCertinfo(command, args[0])
		},
	}
	command.Flags().BoolP("chain", "c", false, "Show full certificate chain")
	command.Flags().Bool("validate", false, "Validate certificate")
	command.Flags().IntP("timeout", "t", 10, "Connection timeout in seconds")

	chainCommand := &cobra.Command{
		Use:   "chain [host]",
		Short: "Display full certificate chain",
		Long: `Retrieve and display the complete certificate chain from a server.

Examples:
  raxuiscli certinfo chain example.com
  raxuiscli certinfo chain example.com:8443`,
		Args: exactCertinfoArgs(1),
		RunE: func(command *cobra.Command, args []string) error {
			return runCertinfoChain(command, args[0])
		},
	}
	chainCommand.Flags().IntP("timeout", "t", 10, "Connection timeout in seconds")

	validateCommand := &cobra.Command{
		Use:   "validate [host|file]",
		Short: "Validate certificate",
		Long: `Validate a certificate for common issues.

Checks for:
- Expiration
- Self-signed status
- Weak algorithms
- Key size

Examples:
  raxuiscli certinfo validate example.com
  raxuiscli certinfo validate cert.pem`,
		Args: exactCertinfoArgs(1),
		RunE: func(command *cobra.Command, args []string) error {
			return runCertinfoValidate(command, args[0])
		},
	}
	validateCommand.Flags().IntP("timeout", "t", 10, "Connection timeout in seconds")

	compareCommand := &cobra.Command{
		Use:   "compare [host1|file1] [host2|file2]",
		Short: "Compare two certificates",
		Long: `Compare two certificates side by side.

Examples:
  raxuiscli certinfo compare example.com test.example.com
  raxuiscli certinfo compare cert1.pem cert2.pem`,
		Args: exactCertinfoArgs(2),
		RunE: func(command *cobra.Command, args []string) error {
			return runCertinfoCompare(command, args[0], args[1])
		},
	}
	compareCommand.Flags().IntP("timeout", "t", 10, "Connection timeout in seconds")

	sanCommand := &cobra.Command{
		Use:   "san [host|file]",
		Short: "Extract Subject Alternative Names",
		Long: `Extract and display Subject Alternative Names (SANs) from a certificate.

Examples:
  raxuiscli certinfo san example.com
  raxuiscli certinfo san cert.pem`,
		Args: exactCertinfoArgs(1),
		RunE: func(command *cobra.Command, args []string) error {
			return runCertinfoSAN(command, args[0])
		},
	}
	sanCommand.Flags().IntP("timeout", "t", 10, "Connection timeout in seconds")

	command.AddCommand(chainCommand, validateCommand, compareCommand, sanCommand)
	return command
}

func exactCertinfoArgs(count int) cobra.PositionalArgs {
	return func(command *cobra.Command, args []string) error {
		if err := cobra.ExactArgs(count)(command, args); err != nil {
			return sharedcommand.NewOperationalError(err)
		}
		return nil
	}
}

func runCertinfo(command *cobra.Command, target string) error {
	chain, err := command.Flags().GetBool("chain")
	if err != nil {
		return sharedcommand.NewOperationalError(err)
	}
	validate, err := command.Flags().GetBool("validate")
	if err != nil {
		return sharedcommand.NewOperationalError(err)
	}
	timeout, err := command.Flags().GetInt("timeout")
	if err != nil {
		return sharedcommand.NewOperationalError(err)
	}

	chainInfo, err := loadCertinfoTarget(target, timeout)
	if err != nil {
		return sharedcommand.NewOperationalError(err)
	}
	if err := requireCertificates(chainInfo); err != nil {
		return sharedcommand.NewOperationalError(err)
	}
	payload := map[string]any{}
	if chain {
		certs := make([]certInfoView, 0, len(chainInfo.Certificates))
		for i := range chainInfo.Certificates {
			certs = append(certs, certInfoToView(&chainInfo.Certificates[i]))
		}
		payload["certificates"] = certs
	} else {
		payload["certificate"] = certInfoToView(&chainInfo.Certificates[0])
	}
	if validate {
		payload["validation"] = validationToView(certinfo.ValidateCertificate(&chainInfo.Certificates[0]))
	}

	return output.Emit(payload, func(_ io.Writer) {
		if chain {
			certinfo.DisplayChain(chainInfo)
		} else {
			certinfo.DisplayCertInfo(&chainInfo.Certificates[0])
		}
		if validate {
			certinfo.DisplayValidation(certinfo.ValidateCertificate(&chainInfo.Certificates[0]))
		}
	})
}

func runCertinfoChain(command *cobra.Command, target string) error {
	timeout, err := command.Flags().GetInt("timeout")
	if err != nil {
		return sharedcommand.NewOperationalError(err)
	}
	chainInfo, err := loadCertinfoHost(target, timeout)
	if err != nil {
		return sharedcommand.NewOperationalError(err)
	}
	if err := requireCertificates(chainInfo); err != nil {
		return sharedcommand.NewOperationalError(err)
	}

	certs := make([]certInfoView, 0, len(chainInfo.Certificates))
	for i := range chainInfo.Certificates {
		certs = append(certs, certInfoToView(&chainInfo.Certificates[i]))
	}
	return output.Emit(map[string]any{
		"host":         chainInfo.Host,
		"port":         chainInfo.Port,
		"certificates": certs,
	}, func(_ io.Writer) {
		certinfo.DisplayChain(chainInfo)
	})
}

func runCertinfoValidate(command *cobra.Command, target string) error {
	timeout, err := command.Flags().GetInt("timeout")
	if err != nil {
		return sharedcommand.NewOperationalError(err)
	}
	chainInfo, err := loadCertinfoTarget(target, timeout)
	if err != nil {
		return sharedcommand.NewOperationalError(err)
	}
	if err := requireCertificates(chainInfo); err != nil {
		return sharedcommand.NewOperationalError(err)
	}
	type certValidation struct {
		Index      int            `json:"index"`
		EndEntity  bool           `json:"end_entity"`
		Validation validationView `json:"validation"`
	}
	views := make([]certValidation, 0, len(chainInfo.Certificates))
	for i := range chainInfo.Certificates {
		views = append(views, certValidation{
			Index:      i + 1,
			EndEntity:  i == 0,
			Validation: validationToView(certinfo.ValidateCertificate(&chainInfo.Certificates[i])),
		})
	}

	return output.Emit(map[string]any{"certificates": views}, func(_ io.Writer) {
		for i := range chainInfo.Certificates {
			fmt.Printf("\n[Certificate %d]", i+1)
			if i == 0 {
				fmt.Print(" (End Entity)")
			}
			fmt.Println()
			certinfo.DisplayValidation(certinfo.ValidateCertificate(&chainInfo.Certificates[i]))
		}
	})
}

func runCertinfoCompare(command *cobra.Command, firstTarget, secondTarget string) error {
	timeout, err := command.Flags().GetInt("timeout")
	if err != nil {
		return sharedcommand.NewOperationalError(err)
	}
	first, err := firstCertinfoCertificate(firstTarget, timeout)
	if err != nil {
		return sharedcommand.NewOperationalError(fmt.Errorf("getting certificate 1: %w", err))
	}
	second, err := firstCertinfoCertificate(secondTarget, timeout)
	if err != nil {
		return sharedcommand.NewOperationalError(fmt.Errorf("getting certificate 2: %w", err))
	}
	return output.Emit(map[string]any{
		"certificate_1": certInfoToView(first),
		"certificate_2": certInfoToView(second),
	}, func(_ io.Writer) {
		certinfo.CompareCertificates(first, second)
	})
}

func runCertinfoSAN(command *cobra.Command, target string) error {
	timeout, err := command.Flags().GetInt("timeout")
	if err != nil {
		return sharedcommand.NewOperationalError(err)
	}
	chainInfo, err := loadCertinfoTarget(target, timeout)
	if err != nil {
		return sharedcommand.NewOperationalError(err)
	}
	if err := requireCertificates(chainInfo); err != nil {
		return sharedcommand.NewOperationalError(err)
	}

	certificate := chainInfo.Certificates[0]

	return output.Emit(map[string]any{
		"dns_names":       certificate.DNSNames,
		"ip_addresses":    certificate.IPAddresses,
		"email_addresses": certificate.EmailAddresses,
	}, func(_ io.Writer) {
		fmt.Println("\n[SUBJECT ALTERNATIVE NAMES]")
		fmt.Println(strings.Repeat("=", 60))
		if len(certificate.DNSNames) > 0 {
			fmt.Println("\nDNS Names:")
			for _, name := range certificate.DNSNames {
				fmt.Printf("  - %s\n", name)
			}
		}
		if len(certificate.IPAddresses) > 0 {
			fmt.Println("\nIP Addresses:")
			for _, ip := range certificate.IPAddresses {
				fmt.Printf("  - %s\n", ip)
			}
		}
		if len(certificate.EmailAddresses) > 0 {
			fmt.Println("\nEmail Addresses:")
			for _, email := range certificate.EmailAddresses {
				fmt.Printf("  - %s\n", email)
			}
		}
		if len(certificate.DNSNames) == 0 && len(certificate.IPAddresses) == 0 && len(certificate.EmailAddresses) == 0 {
			fmt.Println("No SANs found in certificate")
		}
	})
}

func firstCertinfoCertificate(target string, timeout int) (*certinfo.CertInfo, error) {
	chainInfo, err := loadCertinfoTarget(target, timeout)
	if err != nil {
		return nil, err
	}
	if err := requireCertificates(chainInfo); err != nil {
		return nil, err
	}
	return &chainInfo.Certificates[0], nil
}

func loadCertinfoTarget(target string, timeout int) (*certinfo.ChainInfo, error) {
	if isCertinfoFile(target) {
		return getCertFromFile(target)
	}
	return loadCertinfoHost(target, timeout)
}

func loadCertinfoHost(target string, timeout int) (*certinfo.ChainInfo, error) {
	host, port, err := parseCertinfoTarget(target)
	if err != nil {
		return nil, err
	}
	return getCertFromHost(host, port, timeout)
}

func isCertinfoFile(target string) bool {
	target = strings.ToLower(target)
	return strings.HasSuffix(target, ".pem") || strings.HasSuffix(target, ".crt") ||
		strings.HasSuffix(target, ".cer") || strings.HasSuffix(target, ".der")
}

func parseCertinfoTarget(target string) (string, int, error) {
	if target == "" {
		return "", 0, fmt.Errorf("certificate host must not be empty")
	}
	if net.ParseIP(target) != nil {
		return target, defaultCertinfoPort, nil
	}
	if !strings.Contains(target, ":") {
		return target, defaultCertinfoPort, nil
	}

	host, portText, err := net.SplitHostPort(target)
	if err != nil {
		return "", 0, fmt.Errorf("invalid certificate host/port %q: %w", target, err)
	}
	if host == "" {
		return "", 0, fmt.Errorf("invalid certificate host/port %q: host must not be empty", target)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("invalid certificate host/port %q: port must be between 1 and 65535", target)
	}
	return host, port, nil
}

func requireCertificates(chainInfo *certinfo.ChainInfo) error {
	if chainInfo == nil || len(chainInfo.Certificates) == 0 {
		return fmt.Errorf("no certificates found")
	}
	return nil
}

func init() {
	cmd.RootCmd.AddCommand(certinfoCmd)
}
