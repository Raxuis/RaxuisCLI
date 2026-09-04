package network

import (
	"fmt"
	"os"
	"raxuiscli/cmd"
	"raxuiscli/internal/network/dns"
	"strings"

	"github.com/spf13/cobra"
)

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
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
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
	Run: func(cmd *cobra.Command, args []string) {
		domain := args[0]

		opts := dns.LookupOptions{
			Domain:     domain,
			RecordType: dns.RecordType(strings.ToUpper(dnsLookupType)),
			Nameserver: dnsNameserver,
			Timeout:    dnsTimeout,
		}

		results := dns.Lookup(opts)
		dns.DisplayLookupResults(results)
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
	Run: func(cmd *cobra.Command, args []string) {
		ip := args[0]

		result := dns.ReverseLookup(ip, dnsNameserver, dnsTimeout)
		dns.DisplayReverseResult(result)
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
	Run: func(cmd *cobra.Command, args []string) {
		domain := args[0]

		if dnsAXFRServer == "" {
			fmt.Fprintln(os.Stderr, "Error: --server is required for zone transfer")
			os.Exit(1)
		}

		result := dns.AttemptAXFR(domain, dnsAXFRServer, dnsTimeout)
		dns.DisplayAXFRResult(result)
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
	Run: func(cmd *cobra.Command, args []string) {
		domain := args[0]

		if dnsBruteWordlist == "" {
			fmt.Fprintln(os.Stderr, "Error: --wordlist is required for subdomain bruteforce")
			os.Exit(1)
		}

		// Check if wordlist exists
		if _, err := os.Stat(dnsBruteWordlist); os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "Error: wordlist file not found: %s\n", dnsBruteWordlist)
			os.Exit(1)
		}

		fmt.Printf("Starting subdomain bruteforce for %s...\n", domain)
		result := dns.BruteSubdomains(domain, dnsBruteWordlist, dnsNameserver, dnsTimeout, dnsBruteThreads)
		dns.DisplayBruteResult(result)
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
	dnsAXFRCmd.MarkFlagRequired("server")

	// Brute subcommand
	dnsCmd.AddCommand(dnsBruteCmd)
	dnsBruteCmd.Flags().StringVarP(&dnsBruteWordlist, "wordlist", "w", "", "Path to subdomain wordlist (required)")
	dnsBruteCmd.Flags().IntVar(&dnsBruteThreads, "threads", 20, "Number of concurrent threads")
	dnsBruteCmd.MarkFlagRequired("wordlist")
}
