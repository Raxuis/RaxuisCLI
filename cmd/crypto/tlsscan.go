package crypto

import (
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/Raxuis/RaxuisCLI/cmd"
	"github.com/Raxuis/RaxuisCLI/internal/crypto/tlsscan"
	"github.com/Raxuis/RaxuisCLI/internal/shared/output"
)

const defaultTLSScanPort = 443

var tlsScanCmd = &cobra.Command{
	Use:   "tlsscan [host|host:port]",
	Short: "Audit a server's TLS/SSL posture",
	Long: `Assess the TLS/SSL configuration of a server.

Checks supported protocol versions (TLS 1.0-1.3), accepted cipher suites and
their weaknesses (RC4, 3DES, CBC, no forward secrecy), and certificate health
(expiry, self-signed, weak signature or key, hostname match). Each problem is
reported as a finding with a severity, and the server receives a letter grade.

Only ordinary handshakes are performed, so this is safe to run against systems
you are authorized to test.

Examples:
  raxuiscli tlsscan example.com
  raxuiscli tlsscan example.com:8443
  raxuiscli tlsscan example.com --output json`,
	Args: cobra.ExactArgs(1),
	Run: func(command *cobra.Command, args []string) {
		host, port := parseTLSScanTarget(args[0])
		timeout, _ := command.Flags().GetInt("timeout")

		if !output.JSON() {
			fmt.Printf("[TLS/SSL SCAN] %s:%d\n", host, port)
			fmt.Println(strings.Repeat("=", 60))
			fmt.Println("Scanning...")
		}

		result := tlsscan.Scan(host, port, time.Duration(timeout)*time.Second)

		_ = output.Emit(result, func(w io.Writer) {
			displayTLSScan(w, result)
		})
	},
}

func parseTLSScanTarget(target string) (string, int) {
	if idx := strings.LastIndex(target, ":"); idx != -1 {
		if p, err := strconv.Atoi(target[idx+1:]); err == nil && p > 0 && p <= 65535 {
			return target[:idx], p
		}
	}
	return target, defaultTLSScanPort
}

func displayTLSScan(w io.Writer, result *tlsscan.Result) {
	if result.Error != "" {
		fmt.Fprintf(w, "\nError: %s\n", result.Error)
		return
	}

	fmt.Fprintf(w, "\nGrade: %s\n", result.Grade())

	fmt.Fprintln(w, "\nProtocols:")
	for _, p := range result.Protocols {
		mark := "not supported"
		if p.Supported {
			mark = "supported"
		}
		fmt.Fprintf(w, "  %-8s: %s\n", p.Name, mark)
	}

	if len(result.Ciphers) > 0 {
		fmt.Fprintln(w, "\nAccepted cipher suites:")
		for _, c := range result.Ciphers {
			flags := ""
			if c.Insecure {
				flags += " [weak]"
			}
			if !c.ForwardSecrecy {
				flags += " [no-FS]"
			}
			fmt.Fprintf(w, "  %-8s %s%s\n", c.Protocol, c.Name, flags)
		}
	}

	if c := result.Certificate; c != nil {
		fmt.Fprintln(w, "\nCertificate:")
		fmt.Fprintf(w, "  Subject:   %s\n", c.Subject)
		fmt.Fprintf(w, "  Issuer:    %s\n", c.Issuer)
		fmt.Fprintf(w, "  Expires:   %s (%d days)\n", c.NotAfter.Format("2006-01-02"), c.DaysToExpiry)
		fmt.Fprintf(w, "  Key:       %s %d bits\n", c.KeyType, c.KeyBits)
		fmt.Fprintf(w, "  Signature: %s\n", c.SignatureAlgorithm)
	}

	fmt.Fprintln(w, "\nFindings:")
	if len(result.Findings) == 0 {
		fmt.Fprintln(w, "  None - solid TLS configuration.")
		return
	}
	for _, f := range result.Findings {
		fmt.Fprintf(w, "  [%s] %s\n", f.Severity, f.Title)
		if f.Detail != "" {
			fmt.Fprintf(w, "         %s\n", f.Detail)
		}
	}
}

func init() {
	cmd.RootCmd.AddCommand(tlsScanCmd)
	tlsScanCmd.Flags().IntP("timeout", "t", 10, "Per-connection timeout in seconds")
}
