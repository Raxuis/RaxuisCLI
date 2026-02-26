package cmd

import (
	"net"
	"raxuiscli/internal/network/whois"
	"regexp"
	"strings"

	"github.com/spf13/cobra"
)

var whoisTimeout int
var whoisRaw bool

var whoisCmd = &cobra.Command{
	Use:   "whois [domain|ip|asn]",
	Short: "WHOIS lookup for domains, IPs, and ASNs",
	Long: `Perform WHOIS lookups to gather registration and ownership information.

Automatically detects the query type (domain, IP, or ASN) and queries
the appropriate WHOIS servers.

Examples:
  raxuiscli whois example.com     # Domain WHOIS
  raxuiscli whois 8.8.8.8         # IP WHOIS
  raxuiscli whois AS15169         # ASN WHOIS
  raxuiscli whois 15169           # ASN WHOIS (without AS prefix)
  raxuiscli whois example.com --raw  # Show raw WHOIS data`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		query := args[0]
		queryType := detectQueryType(query)

		var result whois.WhoisResult

		switch queryType {
		case "domain":
			result = whois.LookupDomain(query, whoisTimeout)
		case "ip":
			result = whois.LookupIP(query, whoisTimeout)
		case "asn":
			result = whois.LookupASN(query, whoisTimeout)
		}

		if whoisRaw {
			whois.DisplayRaw(result)
		} else {
			whois.DisplayResult(result)
		}
	},
}

// detectQueryType determines if the query is a domain, IP, or ASN
func detectQueryType(query string) string {
	// Check for IP address
	if ip := net.ParseIP(query); ip != nil {
		return "ip"
	}

	// Check for ASN (starts with AS or is a number)
	if strings.HasPrefix(strings.ToUpper(query), "AS") {
		return "asn"
	}

	// Check if it's just a number (ASN without prefix)
	if match, _ := regexp.MatchString(`^\d+$`, query); match {
		return "asn"
	}

	// Default to domain
	return "domain"
}

func init() {
	rootCmd.AddCommand(whoisCmd)

	whoisCmd.Flags().IntVarP(&whoisTimeout, "timeout", "t", 10, "Timeout in seconds")
	whoisCmd.Flags().BoolVarP(&whoisRaw, "raw", "r", false, "Show raw WHOIS data")
}
