package network

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Raxuis/RaxuisCLI/cmd"
	"github.com/Raxuis/RaxuisCLI/internal/network/dns"
	"github.com/Raxuis/RaxuisCLI/internal/shared/output"

	"github.com/spf13/cobra"
)

// errString renders an error as a JSON-friendly string (empty when nil).
func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

var dnsNameserver string
var dnsTimeout int

var dnsCmd = &cobra.Command{
	Use:   "dns",
	Short: "DNS lookup and analysis tools",
	Long: `DNS reconnaissance toolkit for domain analysis.

Supports DNS lookups, reverse lookups, zone transfers, and subdomain enumeration.

Examples:
  raxuiscli dns lookup example.com
  raxuiscli dns lookup example.com --type MX
  raxuiscli dns reverse 8.8.8.8
  raxuiscli dns axfr example.com --server ns1.example.com
  raxuiscli dns brute example.com --wordlist subdomains.txt`,
	RunE: func(cmd *cobra.Command, args []string) error {
		_ = cmd.Help()
		return nil
	},
}

var dnsLookupType string

var dnsLookupCmd = &cobra.Command{
	Use:   "lookup [domain]",
	Short: "Perform DNS lookup",
	Long: `Query DNS records for a domain.

Supported record types: A, AAAA, CNAME, MX, NS, TXT, SOA, PTR, ANY

Examples:
  raxuiscli dns lookup example.com              # A records (default)
  raxuiscli dns lookup example.com --type MX    # MX records
  raxuiscli dns lookup example.com --type ANY   # All record types
  raxuiscli dns lookup example.com --server 8.8.8.8  # Custom DNS server`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		domain := args[0]

		opts := dns.LookupOptions{
			Domain:     domain,
			RecordType: dns.RecordType(strings.ToUpper(dnsLookupType)),
			Nameserver: dnsNameserver,
			Timeout:    dnsTimeout,
		}

		results := dns.Lookup(opts)

		type recordOut struct {
			Domain     string   `json:"domain"`
			RecordType string   `json:"record_type"`
			Records    []string `json:"records"`
			TTL        uint32   `json:"ttl"`
			Error      string   `json:"error,omitempty"`
		}
		view := make([]recordOut, 0, len(results))
		for _, r := range results {
			view = append(view, recordOut{
				Domain:     r.Domain,
				RecordType: string(r.RecordType),
				Records:    r.Records,
				TTL:        r.TTL,
				Error:      errString(r.Error),
			})
		}

		if err := output.Emit(map[string]any{"domain": domain, "results": view}, func(_ io.Writer) {
			dns.DisplayLookupResults(results)
		}); err != nil {
			return err
		}
		failures := 0
		var lastErr error
		for _, r := range results {
			if r.Error != nil {
				failures++
				lastErr = r.Error
			}
		}
		if failures == len(results) {
			return lastErr
		}
		return nil

	},
}

var dnsReverseCmd = &cobra.Command{
	Use:   "reverse [ip]",
	Short: "Perform reverse DNS lookup",
	Long: `Perform reverse DNS lookup to find hostname for an IP address.

Examples:
  raxuiscli dns reverse 8.8.8.8
  raxuiscli dns reverse 1.1.1.1 --server 8.8.8.8`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ip := args[0]

		result := dns.ReverseLookup(ip, dnsNameserver, dnsTimeout)

		payload := map[string]any{
			"ip":       result.IP,
			"hostname": result.Hostname,
		}
		if msg := errString(result.Error); msg != "" {
			payload["error"] = msg
		}
		if err := output.Emit(payload, func(_ io.Writer) { dns.DisplayReverseResult(result) }); err != nil {
			return err
		}
		return result.Error

	},
}

var dnsAXFRServer string

var dnsAXFRCmd = &cobra.Command{
	Use:   "axfr [domain]",
	Short: "Attempt DNS zone transfer",
	Long: `Attempt a DNS zone transfer (AXFR) from a nameserver.

Zone transfers can reveal all DNS records for a domain if misconfigured.
This is a passive reconnaissance technique.

Examples:
  raxuiscli dns axfr example.com --server ns1.example.com
  raxuiscli dns axfr example.com --server 10.0.0.1`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		domain := args[0]

		if dnsAXFRServer == "" {
			return fmt.Errorf("--server is required for zone transfer")
		}

		result := dns.AttemptAXFR(domain, dnsAXFRServer, dnsTimeout)

		payload := map[string]any{
			"domain":  result.Domain,
			"server":  result.Server,
			"success": result.Success,
			"records": result.Records,
		}
		if msg := errString(result.Error); msg != "" {
			payload["error"] = msg
		}
		if err := output.Emit(payload, func(_ io.Writer) { dns.DisplayAXFRResult(result) }); err != nil {
			return err
		}
		return result.Error

	},
}

var dnsBruteWordlist string
var dnsBruteThreads int

var dnsBruteCmd = &cobra.Command{
	Use:   "brute [domain]",
	Short: "Bruteforce subdomains",
	Long: `Enumerate subdomains using a wordlist.

Performs concurrent DNS lookups to discover valid subdomains.

Examples:
  raxuiscli dns brute example.com --wordlist subdomains.txt
  raxuiscli dns brute example.com --wordlist subs.txt --threads 50
  raxuiscli dns brute example.com --wordlist subs.txt --server 8.8.8.8`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		domain := args[0]

		if dnsBruteWordlist == "" {
			return fmt.Errorf("--wordlist is required for subdomain bruteforce")
		}

		// Check if wordlist exists
		if _, err := os.Stat(dnsBruteWordlist); os.IsNotExist(err) {
			return fmt.Errorf("wordlist file not found: %s", dnsBruteWordlist)
		}

		if !output.JSON() {
			fmt.Fprintf(output.Std, "Starting subdomain bruteforce for %s...\n", domain)
		}
		result := dns.BruteSubdomains(domain, dnsBruteWordlist, dnsNameserver, dnsTimeout, dnsBruteThreads)

		type subOut struct {
			Subdomain string   `json:"subdomain"`
			IPs       []string `json:"ips"`
		}
		subs := make([]subOut, 0, len(result.Subdomains))
		for _, s := range result.Subdomains {
			subs = append(subs, subOut{Subdomain: s.Subdomain, IPs: s.IPs})
		}
		return output.Emit(map[string]any{
			"domain":     result.Domain,
			"total":      result.Total,
			"found":      result.Found,
			"subdomains": subs,
		}, func(_ io.Writer) {
			dns.DisplayBruteResult(result)
		})

	},
}

func init() {
	cmd.RootCmd.AddCommand(dnsCmd)

	// Global DNS flags
	dnsCmd.PersistentFlags().StringVarP(&dnsNameserver, "server", "s", "", "Custom DNS server (e.g., 8.8.8.8)")
	dnsCmd.PersistentFlags().IntVarP(&dnsTimeout, "timeout", "t", 5, "Timeout in seconds")

	// Lookup subcommand
	dnsCmd.AddCommand(dnsLookupCmd)
	dnsLookupCmd.Flags().StringVarP(&dnsLookupType, "type", "T", "A", "Record type (A, AAAA, CNAME, MX, NS, TXT, SOA, PTR, ANY)")

	// Reverse subcommand
	dnsCmd.AddCommand(dnsReverseCmd)

	// AXFR subcommand
	dnsCmd.AddCommand(dnsAXFRCmd)
	dnsAXFRCmd.Flags().StringVar(&dnsAXFRServer, "server", "", "DNS server for zone transfer (required)")
	dnsAXFRCmd.MarkFlagRequired("server") //nolint:errcheck // flag is defined just above

	// Brute subcommand
	dnsCmd.AddCommand(dnsBruteCmd)
	dnsBruteCmd.Flags().StringVarP(&dnsBruteWordlist, "wordlist", "w", "", "Path to subdomain wordlist (required)")
	dnsBruteCmd.Flags().IntVar(&dnsBruteThreads, "threads", 20, "Number of concurrent threads")
	dnsBruteCmd.MarkFlagRequired("wordlist") //nolint:errcheck // flag is defined just above
}
