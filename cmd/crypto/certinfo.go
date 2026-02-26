package cmd

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"raxuiscli/internal/crypto/certinfo"
)

var certinfoCmd = &cobra.Command{
	Use:   "certinfo [host|file]",
	Short: "Analyze X.509 certificates",
	Long: `Retrieve and analyze X.509 certificates from servers or files.

Examples:
  raxuiscli certinfo example.com
  raxuiscli certinfo example.com:8443
  raxuiscli certinfo cert.pem
  raxuiscli certinfo example.com --chain`,
	Run: func(cmd *cobra.Command, args []string) {
		chain, _ := cmd.Flags().GetBool("chain")
		validate, _ := cmd.Flags().GetBool("validate")
		timeout, _ := cmd.Flags().GetInt("timeout")

		if len(args) == 0 {
			fmt.Println("Please provide a host or certificate file")
			return
		}

		target := args[0]

		// Check if it's a file
		if strings.HasSuffix(target, ".pem") || strings.HasSuffix(target, ".crt") ||
			strings.HasSuffix(target, ".cer") || strings.HasSuffix(target, ".der") {
			chainInfo, err := certinfo.GetCertFromFile(target)
			if err != nil {
				fmt.Printf("Error reading certificate: %v\n", err)
				return
			}

			if chain {
				certinfo.DisplayChain(chainInfo)
			} else if len(chainInfo.Certificates) > 0 {
				certinfo.DisplayCertInfo(&chainInfo.Certificates[0])
			}

			if validate && len(chainInfo.Certificates) > 0 {
				result := certinfo.ValidateCertificate(&chainInfo.Certificates[0])
				certinfo.DisplayValidation(result)
			}
			return
		}

		// Parse host and port
		host := target
		port := 443

		if strings.Contains(target, ":") {
			parts := strings.Split(target, ":")
			host = parts[0]
			if p, err := strconv.Atoi(parts[1]); err == nil {
				port = p
			}
		}

		chainInfo, err := certinfo.GetCertFromHost(host, port, timeout)
		if err != nil {
			fmt.Printf("Error connecting to %s: %v\n", target, err)
			return
		}

		if chain {
			certinfo.DisplayChain(chainInfo)
		} else if len(chainInfo.Certificates) > 0 {
			certinfo.DisplayCertInfo(&chainInfo.Certificates[0])
		}

		if validate && len(chainInfo.Certificates) > 0 {
			result := certinfo.ValidateCertificate(&chainInfo.Certificates[0])
			certinfo.DisplayValidation(result)
		}
	},
}

var certinfoChainCmd = &cobra.Command{
	Use:   "chain [host]",
	Short: "Display full certificate chain",
	Long: `Retrieve and display the complete certificate chain from a server.

Examples:
  raxuiscli certinfo chain example.com
  raxuiscli certinfo chain example.com:8443`,
	Run: func(cmd *cobra.Command, args []string) {
		timeout, _ := cmd.Flags().GetInt("timeout")

		if len(args) == 0 {
			fmt.Println("Please provide a host")
			return
		}

		target := args[0]
		host := target
		port := 443

		if strings.Contains(target, ":") {
			parts := strings.Split(target, ":")
			host = parts[0]
			if p, err := strconv.Atoi(parts[1]); err == nil {
				port = p
			}
		}

		chainInfo, err := certinfo.GetCertFromHost(host, port, timeout)
		if err != nil {
			fmt.Printf("Error connecting to %s: %v\n", target, err)
			return
		}

		certinfo.DisplayChain(chainInfo)
	},
}

var certinfoValidateCmd = &cobra.Command{
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
	Run: func(cmd *cobra.Command, args []string) {
		timeout, _ := cmd.Flags().GetInt("timeout")

		if len(args) == 0 {
			fmt.Println("Please provide a host or certificate file")
			return
		}

		target := args[0]

		var chainInfo *certinfo.ChainInfo
		var err error

		// Check if it's a file
		if strings.HasSuffix(target, ".pem") || strings.HasSuffix(target, ".crt") ||
			strings.HasSuffix(target, ".cer") || strings.HasSuffix(target, ".der") {
			chainInfo, err = certinfo.GetCertFromFile(target)
		} else {
			host := target
			port := 443
			if strings.Contains(target, ":") {
				parts := strings.Split(target, ":")
				host = parts[0]
				if p, err := strconv.Atoi(parts[1]); err == nil {
					port = p
				}
			}
			chainInfo, err = certinfo.GetCertFromHost(host, port, timeout)
		}

		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}

		if len(chainInfo.Certificates) == 0 {
			fmt.Println("No certificates found")
			return
		}

		// Validate each certificate in chain
		for i, cert := range chainInfo.Certificates {
			fmt.Printf("\n[Certificate %d]", i+1)
			if i == 0 {
				fmt.Print(" (End Entity)")
			}
			fmt.Println()

			result := certinfo.ValidateCertificate(&cert)
			certinfo.DisplayValidation(result)
		}
	},
}

var certinfoCompareCmd = &cobra.Command{
	Use:   "compare [host1|file1] [host2|file2]",
	Short: "Compare two certificates",
	Long: `Compare two certificates side by side.

Examples:
  raxuiscli certinfo compare example.com test.example.com
  raxuiscli certinfo compare cert1.pem cert2.pem`,
	Run: func(cmd *cobra.Command, args []string) {
		timeout, _ := cmd.Flags().GetInt("timeout")

		if len(args) < 2 {
			fmt.Println("Please provide two hosts or certificate files to compare")
			return
		}

		getCert := func(target string) (*certinfo.CertInfo, error) {
			var chainInfo *certinfo.ChainInfo
			var err error

			if strings.HasSuffix(target, ".pem") || strings.HasSuffix(target, ".crt") ||
				strings.HasSuffix(target, ".cer") || strings.HasSuffix(target, ".der") {
				chainInfo, err = certinfo.GetCertFromFile(target)
			} else {
				host := target
				port := 443
				if strings.Contains(target, ":") {
					parts := strings.Split(target, ":")
					host = parts[0]
					if p, err := strconv.Atoi(parts[1]); err == nil {
						port = p
					}
				}
				chainInfo, err = certinfo.GetCertFromHost(host, port, timeout)
			}

			if err != nil {
				return nil, err
			}

			if len(chainInfo.Certificates) == 0 {
				return nil, fmt.Errorf("no certificates found")
			}

			return &chainInfo.Certificates[0], nil
		}

		cert1, err := getCert(args[0])
		if err != nil {
			fmt.Printf("Error getting certificate 1: %v\n", err)
			return
		}

		cert2, err := getCert(args[1])
		if err != nil {
			fmt.Printf("Error getting certificate 2: %v\n", err)
			return
		}

		certinfo.CompareCertificates(cert1, cert2)
	},
}

var certinfoSANCmd = &cobra.Command{
	Use:   "san [host|file]",
	Short: "Extract Subject Alternative Names",
	Long: `Extract and display Subject Alternative Names (SANs) from a certificate.

Examples:
  raxuiscli certinfo san example.com
  raxuiscli certinfo san cert.pem`,
	Run: func(cmd *cobra.Command, args []string) {
		timeout, _ := cmd.Flags().GetInt("timeout")

		if len(args) == 0 {
			fmt.Println("Please provide a host or certificate file")
			return
		}

		target := args[0]

		var chainInfo *certinfo.ChainInfo
		var err error

		if strings.HasSuffix(target, ".pem") || strings.HasSuffix(target, ".crt") ||
			strings.HasSuffix(target, ".cer") || strings.HasSuffix(target, ".der") {
			chainInfo, err = certinfo.GetCertFromFile(target)
		} else {
			host := target
			port := 443
			if strings.Contains(target, ":") {
				parts := strings.Split(target, ":")
				host = parts[0]
				if p, err := strconv.Atoi(parts[1]); err == nil {
					port = p
				}
			}
			chainInfo, err = certinfo.GetCertFromHost(host, port, timeout)
		}

		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}

		if len(chainInfo.Certificates) == 0 {
			fmt.Println("No certificates found")
			return
		}

		cert := chainInfo.Certificates[0]

		fmt.Println("\n[SUBJECT ALTERNATIVE NAMES]")
		fmt.Println(strings.Repeat("=", 60))

		if len(cert.DNSNames) > 0 {
			fmt.Println("\nDNS Names:")
			for _, name := range cert.DNSNames {
				fmt.Printf("  - %s\n", name)
			}
		}

		if len(cert.IPAddresses) > 0 {
			fmt.Println("\nIP Addresses:")
			for _, ip := range cert.IPAddresses {
				fmt.Printf("  - %s\n", ip)
			}
		}

		if len(cert.EmailAddresses) > 0 {
			fmt.Println("\nEmail Addresses:")
			for _, email := range cert.EmailAddresses {
				fmt.Printf("  - %s\n", email)
			}
		}

		if len(cert.DNSNames) == 0 && len(cert.IPAddresses) == 0 && len(cert.EmailAddresses) == 0 {
			fmt.Println("No SANs found in certificate")
		}
	},
}

func init() {
	rootCmd.AddCommand(certinfoCmd)

	// Main command flags
	certinfoCmd.Flags().BoolP("chain", "c", false, "Show full certificate chain")
	certinfoCmd.Flags().Bool("validate", false, "Validate certificate")
	certinfoCmd.Flags().IntP("timeout", "t", 10, "Connection timeout in seconds")

	// Subcommands
	certinfoCmd.AddCommand(certinfoChainCmd)
	certinfoChainCmd.Flags().IntP("timeout", "t", 10, "Connection timeout in seconds")

	certinfoCmd.AddCommand(certinfoValidateCmd)
	certinfoValidateCmd.Flags().IntP("timeout", "t", 10, "Connection timeout in seconds")

	certinfoCmd.AddCommand(certinfoCompareCmd)
	certinfoCompareCmd.Flags().IntP("timeout", "t", 10, "Connection timeout in seconds")

	certinfoCmd.AddCommand(certinfoSANCmd)
	certinfoSANCmd.Flags().IntP("timeout", "t", 10, "Connection timeout in seconds")
}
