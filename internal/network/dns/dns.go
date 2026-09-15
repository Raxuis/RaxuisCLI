package dns

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// RecordType represents DNS record types
type RecordType string

const (
	TypeA     RecordType = "A"
	TypeAAAA  RecordType = "AAAA"
	TypeCNAME RecordType = "CNAME"
	TypeMX    RecordType = "MX"
	TypeNS    RecordType = "NS"
	TypeTXT   RecordType = "TXT"
	TypeSOA   RecordType = "SOA"
	TypePTR   RecordType = "PTR"
	TypeANY   RecordType = "ANY"
)

// LookupOptions holds options for DNS lookup
type LookupOptions struct {
	Domain     string
	RecordType RecordType
	Nameserver string
	Timeout    int
}

// LookupResult holds the result of a DNS lookup
type LookupResult struct {
	Domain     string
	RecordType RecordType
	Records    []string
	TTL        uint32
	Error      error
}

// ReverseResult holds the result of a reverse DNS lookup
type ReverseResult struct {
	IP       string
	Hostname []string
	Error    error
}

// AXFRResult holds the result of a zone transfer attempt
type AXFRResult struct {
	Domain  string
	Server  string
	Success bool
	Records []string
	Error   error
}

// BruteResult holds the result of subdomain bruteforce
type BruteResult struct {
	Domain     string
	Subdomains []SubdomainResult
	Total      int
	Found      int
}

// SubdomainResult holds info about a discovered subdomain
type SubdomainResult struct {
	Subdomain string
	IPs       []string
}

// Lookup performs DNS lookup for the specified record type
func Lookup(opts LookupOptions) []LookupResult {
	var results []LookupResult

	resolver := getResolver(opts.Nameserver, opts.Timeout)
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(opts.Timeout)*time.Second)
	defer cancel()

	if opts.RecordType == TypeANY {
		// Query all common record types
		types := []RecordType{TypeA, TypeAAAA, TypeCNAME, TypeMX, TypeNS, TypeTXT, TypeSOA}
		for _, t := range types {
			result := lookupType(ctx, resolver, opts.Domain, t)
			if result.Error == nil && len(result.Records) > 0 {
				results = append(results, result)
			}
		}
	} else {
		result := lookupType(ctx, resolver, opts.Domain, opts.RecordType)
		results = append(results, result)
	}

	return results
}

// lookupType performs lookup for a specific record type
func lookupType(ctx context.Context, resolver *net.Resolver, domain string, recordType RecordType) LookupResult {
	result := LookupResult{
		Domain:     domain,
		RecordType: recordType,
	}

	switch recordType {
	case TypeA:
		ips, err := resolver.LookupIP(ctx, "ip4", domain)
		if err != nil {
			result.Error = err
			return result
		}
		for _, ip := range ips {
			result.Records = append(result.Records, ip.String())
		}

	case TypeAAAA:
		ips, err := resolver.LookupIP(ctx, "ip6", domain)
		if err != nil {
			result.Error = err
			return result
		}
		for _, ip := range ips {
			result.Records = append(result.Records, ip.String())
		}

	case TypeCNAME:
		cname, err := resolver.LookupCNAME(ctx, domain)
		if err != nil {
			result.Error = err
			return result
		}
		result.Records = append(result.Records, cname)

	case TypeMX:
		mxs, err := resolver.LookupMX(ctx, domain)
		if err != nil {
			result.Error = err
			return result
		}
		for _, mx := range mxs {
			result.Records = append(result.Records, fmt.Sprintf("%d %s", mx.Pref, mx.Host))
		}

	case TypeNS:
		nss, err := resolver.LookupNS(ctx, domain)
		if err != nil {
			result.Error = err
			return result
		}
		for _, ns := range nss {
			result.Records = append(result.Records, ns.Host)
		}

	case TypeTXT:
		txts, err := resolver.LookupTXT(ctx, domain)
		if err != nil {
			result.Error = err
			return result
		}
		result.Records = txts

	case TypeSOA:
		// SOA lookup via NS records and additional info
		nss, err := resolver.LookupNS(ctx, domain)
		if err != nil {
			result.Error = err
			return result
		}
		if len(nss) > 0 {
			result.Records = append(result.Records, fmt.Sprintf("Primary NS: %s", nss[0].Host))
		}

	case TypePTR:
		names, err := resolver.LookupAddr(ctx, domain)
		if err != nil {
			result.Error = err
			return result
		}
		result.Records = names
	}

	return result
}

// ReverseLookup performs reverse DNS lookup for an IP address
func ReverseLookup(ip string, nameserver string, timeout int) ReverseResult {
	result := ReverseResult{IP: ip}

	resolver := getResolver(nameserver, timeout)
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()

	names, err := resolver.LookupAddr(ctx, ip)
	if err != nil {
		result.Error = err
		return result
	}

	result.Hostname = names
	return result
}

// AttemptAXFR attempts a zone transfer from the specified DNS server
func AttemptAXFR(domain, server string, timeout int) AXFRResult {
	result := AXFRResult{
		Domain:  domain,
		Server:  server,
		Success: false,
	}

	// Ensure server has port
	if !strings.Contains(server, ":") {
		server = server + ":53"
	}

	// Connect to DNS server
	conn, err := net.DialTimeout("tcp", server, time.Duration(timeout)*time.Second)
	if err != nil {
		result.Error = fmt.Errorf("connection failed: %v", err)
		return result
	}
	defer conn.Close()

	// Set deadline
	_ = conn.SetDeadline(time.Now().Add(time.Duration(timeout) * time.Second))

	// Build AXFR query
	query := buildAXFRQuery(domain)

	// Send length prefix (TCP DNS)
	length := uint16(len(query))
	lengthBytes := []byte{byte(length >> 8), byte(length & 0xff)}
	_, err = conn.Write(append(lengthBytes, query...))
	if err != nil {
		result.Error = fmt.Errorf("send failed: %v", err)
		return result
	}

	// Read response
	respLenBytes := make([]byte, 2)
	_, err = conn.Read(respLenBytes)
	if err != nil {
		result.Error = fmt.Errorf("read failed: %v", err)
		return result
	}

	respLen := int(respLenBytes[0])<<8 | int(respLenBytes[1])
	if respLen < 12 {
		result.Error = fmt.Errorf("invalid response length")
		return result
	}

	response := make([]byte, respLen)
	_, err = conn.Read(response)
	if err != nil {
		result.Error = fmt.Errorf("read response failed: %v", err)
		return result
	}

	// Check RCODE (response code)
	if len(response) >= 4 {
		rcode := response[3] & 0x0f
		switch rcode {
		case 0:
			result.Success = true
			result.Records = append(result.Records, "Zone transfer may be possible (NOERROR)")
		case 5:
			result.Error = fmt.Errorf("zone transfer refused (REFUSED)")
		case 9:
			result.Error = fmt.Errorf("not authorized (NOTAUTH)")
		default:
			result.Error = fmt.Errorf("transfer failed with RCODE: %d", rcode)
		}
	}

	return result
}

// buildAXFRQuery builds a DNS AXFR query packet
func buildAXFRQuery(domain string) []byte {
	// Transaction ID
	query := []byte{0x00, 0x01}
	// Flags: standard query
	query = append(query, 0x00, 0x00)
	// Questions: 1
	query = append(query, 0x00, 0x01)
	// Answer RRs: 0
	query = append(query, 0x00, 0x00)
	// Authority RRs: 0
	query = append(query, 0x00, 0x00)
	// Additional RRs: 0
	query = append(query, 0x00, 0x00)

	// QNAME
	parts := strings.Split(domain, ".")
	for _, part := range parts {
		query = append(query, byte(len(part)))
		query = append(query, []byte(part)...)
	}
	query = append(query, 0x00) // End of QNAME

	// QTYPE: AXFR (252)
	query = append(query, 0x00, 0xfc)
	// QCLASS: IN (1)
	query = append(query, 0x00, 0x01)

	return query
}

// BruteSubdomains performs subdomain bruteforce using a wordlist
func BruteSubdomains(domain, wordlistPath string, nameserver string, timeout, threads int) BruteResult {
	result := BruteResult{Domain: domain}

	// Read wordlist
	file, err := os.Open(wordlistPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening wordlist: %v\n", err)
		return result
	}
	defer file.Close()

	var words []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		word := strings.TrimSpace(scanner.Text())
		if word != "" && !strings.HasPrefix(word, "#") {
			words = append(words, word)
		}
	}

	result.Total = len(words)

	// Create resolver
	resolver := getResolver(nameserver, timeout)

	// Use worker pool for concurrent lookups
	var wg sync.WaitGroup
	var mu sync.Mutex
	semaphore := make(chan struct{}, threads)

	for _, word := range words {
		wg.Add(1)
		semaphore <- struct{}{}

		go func(subdomain string) {
			defer wg.Done()
			defer func() { <-semaphore }()

			fqdn := subdomain + "." + domain
			ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
			defer cancel()

			ips, err := resolver.LookupIP(ctx, "ip4", fqdn)
			if err == nil && len(ips) > 0 {
				var ipStrings []string
				for _, ip := range ips {
					ipStrings = append(ipStrings, ip.String())
				}

				mu.Lock()
				result.Subdomains = append(result.Subdomains, SubdomainResult{
					Subdomain: fqdn,
					IPs:       ipStrings,
				})
				result.Found++
				mu.Unlock()
			}
		}(word)
	}

	wg.Wait()

	// Sort results
	sort.Slice(result.Subdomains, func(i, j int) bool {
		return result.Subdomains[i].Subdomain < result.Subdomains[j].Subdomain
	})

	return result
}

// getResolver creates a DNS resolver with custom nameserver if specified
func getResolver(nameserver string, timeout int) *net.Resolver {
	if nameserver == "" {
		return net.DefaultResolver
	}

	// Ensure nameserver has port
	if !strings.Contains(nameserver, ":") {
		nameserver = nameserver + ":53"
	}

	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: time.Duration(timeout) * time.Second,
			}
			return d.DialContext(ctx, "udp", nameserver)
		},
	}
}

// DisplayLookupResults displays DNS lookup results
func DisplayLookupResults(results []LookupResult) {
	for _, result := range results {
		fmt.Fprintf(stdoutW, "\n[%s] Records for %s:\n", result.RecordType, result.Domain)
		fmt.Fprintln(stdoutW, strings.Repeat("-", 50))

		if result.Error != nil {
			fmt.Fprintf(stdoutW, "  Error: %v\n", result.Error)
			continue
		}

		if len(result.Records) == 0 {
			fmt.Fprintln(stdoutW, "  No records found")
			continue
		}

		for _, record := range result.Records {
			fmt.Fprintf(stdoutW, "  %s\n", record)
		}
	}
	fmt.Fprintln(stdoutW)
}

// DisplayReverseResult displays reverse DNS lookup result
func DisplayReverseResult(result ReverseResult) {
	fmt.Fprintf(stdoutW, "\n[PTR] Reverse lookup for %s:\n", result.IP)
	fmt.Fprintln(stdoutW, strings.Repeat("-", 50))

	if result.Error != nil {
		fmt.Fprintf(stdoutW, "  Error: %v\n", result.Error)
		return
	}

	if len(result.Hostname) == 0 {
		fmt.Fprintln(stdoutW, "  No hostname found")
		return
	}

	for _, hostname := range result.Hostname {
		fmt.Fprintf(stdoutW, "  %s\n", hostname)
	}
	fmt.Fprintln(stdoutW)
}

// DisplayAXFRResult displays zone transfer result
func DisplayAXFRResult(result AXFRResult) {
	fmt.Fprintf(stdoutW, "\n[AXFR] Zone transfer for %s via %s:\n", result.Domain, result.Server)
	fmt.Fprintln(stdoutW, strings.Repeat("-", 50))

	if result.Error != nil {
		fmt.Fprintf(stdoutW, "  Status: FAILED\n")
		fmt.Fprintf(stdoutW, "  Error: %v\n", result.Error)
		return
	}

	if result.Success {
		fmt.Fprintf(stdoutW, "  Status: POTENTIALLY VULNERABLE\n")
		for _, record := range result.Records {
			fmt.Fprintf(stdoutW, "  %s\n", record)
		}
	}
	fmt.Fprintln(stdoutW)
}

// DisplayBruteResult displays subdomain bruteforce results
func DisplayBruteResult(result BruteResult) {
	fmt.Fprintf(stdoutW, "\n[BRUTE] Subdomain enumeration for %s:\n", result.Domain)
	fmt.Fprintln(stdoutW, strings.Repeat("-", 50))
	fmt.Fprintf(stdoutW, "  Tested: %d | Found: %d\n\n", result.Total, result.Found)

	if result.Found == 0 {
		fmt.Fprintln(stdoutW, "  No subdomains found")
		return
	}

	for _, sub := range result.Subdomains {
		fmt.Fprintf(stdoutW, "  %-40s %s\n", sub.Subdomain, strings.Join(sub.IPs, ", "))
	}
	fmt.Fprintln(stdoutW)
}
