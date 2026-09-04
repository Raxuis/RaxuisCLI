package whois

import (
	"bufio"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"
)

// WhoisResult holds the parsed WHOIS information
type WhoisResult struct {
	Query      string
	QueryType  string // "domain", "ip", "asn"
	RawData    string
	Parsed     map[string]string
	Registrar  string
	Created    string
	Updated    string
	Expires    string
	NameServer []string
	Status     []string
	Error      error
}

// WhoisServers maps TLDs to their WHOIS servers
var WhoisServers = map[string]string{
	"com":  "whois.verisign-grs.com",
	"net":  "whois.verisign-grs.com",
	"org":  "whois.pir.org",
	"info": "whois.afilias.net",
	"io":   "whois.nic.io",
	"co":   "whois.nic.co",
	"ai":   "whois.nic.ai",
	"dev":  "whois.nic.google",
	"app":  "whois.nic.google",
	"me":   "whois.nic.me",
	"tv":   "tvwhois.verisign-grs.com",
	"cc":   "ccwhois.verisign-grs.com",
	"biz":  "whois.biz",
	"us":   "whois.nic.us",
	"uk":   "whois.nic.uk",
	"de":   "whois.denic.de",
	"fr":   "whois.nic.fr",
	"eu":   "whois.eu",
	"nl":   "whois.domain-registry.nl",
	"ru":   "whois.tcinet.ru",
	"au":   "whois.auda.org.au",
	"ca":   "whois.cira.ca",
	"jp":   "whois.jprs.jp",
	"cn":   "whois.cnnic.cn",
	"br":   "whois.registro.br",
	"in":   "whois.registry.in",
	"it":   "whois.nic.it",
	"es":   "whois.nic.es",
	"pl":   "whois.dns.pl",
	"ch":   "whois.nic.ch",
	"se":   "whois.iis.se",
	"no":   "whois.norid.no",
	"fi":   "whois.fi",
	"dk":   "whois.dk-hostmaster.dk",
	"be":   "whois.dns.be",
	"at":   "whois.nic.at",
	"cz":   "whois.nic.cz",
	"sk":   "whois.sk-nic.sk",
	"hu":   "whois.nic.hu",
	"ro":   "whois.rotld.ro",
	"bg":   "whois.register.bg",
	"ua":   "whois.ua",
	"tr":   "whois.nic.tr",
	"kr":   "whois.kr",
	"tw":   "whois.twnic.net.tw",
	"hk":   "whois.hkirc.hk",
	"sg":   "whois.sgnic.sg",
	"nz":   "whois.srs.net.nz",
	"za":   "whois.registry.net.za",
	"mx":   "whois.mx",
	"ar":   "whois.nic.ar",
	"cl":   "whois.nic.cl",
}

// IPWhoisServers for IP lookups
var IPWhoisServers = []string{
	"whois.arin.net",    // Americas
	"whois.ripe.net",    // Europe, Middle East
	"whois.apnic.net",   // Asia Pacific
	"whois.lacnic.net",  // Latin America
	"whois.afrinic.net", // Africa
}

// ASNWhoisServer for ASN lookups
var ASNWhoisServer = "whois.radb.net"

// arinWhoisServer is the fallback server LookupASN retries against.
var arinWhoisServer = "whois.arin.net"

// whoisPort is the TCP port queryWhois connects to. It is a var (not a
// hardcoded literal) purely so tests can point queryWhois at a local,
// unprivileged listener instead of the real WHOIS port 43 (binding port 43
// requires root, which test environments don't have). Real CLI usage never
// overrides it, so behavior is unchanged.
var whoisPort = "43"

// LookupDomain performs WHOIS lookup for a domain
func LookupDomain(domain string, timeout int) WhoisResult {
	result := WhoisResult{
		Query:     domain,
		QueryType: "domain",
		Parsed:    make(map[string]string),
	}

	// Get TLD
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		result.Error = fmt.Errorf("invalid domain format")
		return result
	}
	tld := parts[len(parts)-1]

	// Find WHOIS server
	server, ok := WhoisServers[strings.ToLower(tld)]
	if !ok {
		// Try generic WHOIS
		server = "whois.iana.org"
	}

	// Query WHOIS
	rawData, err := queryWhois(server, domain, timeout)
	if err != nil {
		result.Error = err
		return result
	}
	result.RawData = rawData

	// Check if we need to follow a referral
	referral := extractReferral(rawData)
	if referral != "" && referral != server {
		rawData2, err := queryWhois(referral, domain, timeout)
		if err == nil {
			result.RawData = rawData2
		}
	}

	// Parse the result
	parseDomainWhois(&result)

	return result
}

// LookupIP performs WHOIS lookup for an IP address
func LookupIP(ip string, timeout int) WhoisResult {
	result := WhoisResult{
		Query:     ip,
		QueryType: "ip",
		Parsed:    make(map[string]string),
	}

	// Validate IP
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		result.Error = fmt.Errorf("invalid IP address")
		return result
	}

	// Try each RIR
	var lastError error
	for _, server := range IPWhoisServers {
		rawData, err := queryWhois(server, ip, timeout)
		if err != nil {
			lastError = err
			continue
		}

		// Check if this RIR has the information
		if !strings.Contains(rawData, "No match") && !strings.Contains(rawData, "not found") {
			result.RawData = rawData
			parseIPWhois(&result)
			return result
		}
	}

	if result.RawData == "" {
		result.Error = lastError
	}

	return result
}

// LookupASN performs WHOIS lookup for an ASN
func LookupASN(asn string, timeout int) WhoisResult {
	result := WhoisResult{
		Query:     asn,
		QueryType: "asn",
		Parsed:    make(map[string]string),
	}

	// Normalize ASN format
	asn = strings.ToUpper(asn)
	if !strings.HasPrefix(asn, "AS") {
		asn = "AS" + asn
	}

	// Query RADB
	rawData, err := queryWhois(ASNWhoisServer, asn, timeout)
	if err != nil {
		// Try ARIN
		rawData, err = queryWhois(arinWhoisServer, asn, timeout)
		if err != nil {
			result.Error = err
			return result
		}
	}

	result.RawData = rawData
	parseASNWhois(&result)

	return result
}

// queryWhois performs raw WHOIS query
func queryWhois(server, query string, timeout int) (string, error) {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(server, whoisPort), time.Duration(timeout)*time.Second)
	if err != nil {
		return "", fmt.Errorf("connection failed: %v", err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(time.Duration(timeout) * time.Second))

	// Send query
	_, err = fmt.Fprintf(conn, "%s\r\n", query)
	if err != nil {
		return "", fmt.Errorf("write failed: %v", err)
	}

	// Read response
	var response strings.Builder
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		response.WriteString(scanner.Text())
		response.WriteString("\n")
	}

	if err := scanner.Err(); err != nil {
		return response.String(), nil // Return what we got
	}

	return response.String(), nil
}

// extractReferral finds referral server from WHOIS response
func extractReferral(data string) string {
	patterns := []string{
		`(?i)Registrar WHOIS Server:\s*(.+)`,
		`(?i)whois:\s*(.+)`,
		`(?i)refer:\s*(.+)`,
		`(?i)ReferralServer:\s*whois://(.+)`,
	}

	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		match := re.FindStringSubmatch(data)
		if len(match) > 1 {
			return strings.TrimSpace(match[1])
		}
	}

	return ""
}

// parseDomainWhois extracts structured info from domain WHOIS
func parseDomainWhois(result *WhoisResult) {
	lines := strings.Split(result.RawData, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "%") || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(strings.ToLower(parts[0]))
		value := strings.TrimSpace(parts[1])

		switch {
		case strings.Contains(key, "registrar"):
			if result.Registrar == "" {
				result.Registrar = value
				result.Parsed["Registrar"] = value
			}
		case strings.Contains(key, "creation") || strings.Contains(key, "created"):
			if result.Created == "" {
				result.Created = value
				result.Parsed["Created"] = value
			}
		case strings.Contains(key, "updated") || strings.Contains(key, "modified"):
			if result.Updated == "" {
				result.Updated = value
				result.Parsed["Updated"] = value
			}
		case strings.Contains(key, "expir"):
			if result.Expires == "" {
				result.Expires = value
				result.Parsed["Expires"] = value
			}
		case strings.Contains(key, "name server") || strings.Contains(key, "nserver"):
			result.NameServer = append(result.NameServer, value)
		case strings.Contains(key, "status"):
			result.Status = append(result.Status, value)
		case strings.Contains(key, "registrant"):
			result.Parsed["Registrant "+parts[0]] = value
		case strings.Contains(key, "admin"):
			result.Parsed["Admin "+parts[0]] = value
		case strings.Contains(key, "tech"):
			result.Parsed["Tech "+parts[0]] = value
		case strings.Contains(key, "dnssec"):
			result.Parsed["DNSSEC"] = value
		}
	}
}

// parseIPWhois extracts structured info from IP WHOIS
func parseIPWhois(result *WhoisResult) {
	lines := strings.Split(result.RawData, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "%") || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(strings.ToLower(parts[0]))
		value := strings.TrimSpace(parts[1])

		switch {
		case key == "netname" || key == "network":
			result.Parsed["Network Name"] = value
		case key == "netrange" || key == "inetnum":
			result.Parsed["IP Range"] = value
		case key == "cidr":
			result.Parsed["CIDR"] = value
		case key == "orgname" || key == "org-name" || key == "organisation":
			result.Parsed["Organization"] = value
		case key == "orgid" || key == "org":
			result.Parsed["Org ID"] = value
		case key == "country":
			result.Parsed["Country"] = value
		case key == "city":
			result.Parsed["City"] = value
		case key == "stateprov" || key == "state":
			result.Parsed["State/Province"] = value
		case key == "address":
			result.Parsed["Address"] = value
		case key == "origin" || key == "originas":
			result.Parsed["Origin AS"] = value
		case key == "descr" || key == "description":
			if _, ok := result.Parsed["Description"]; !ok {
				result.Parsed["Description"] = value
			}
		case strings.Contains(key, "abuse"):
			result.Parsed["Abuse Contact"] = value
		case key == "created" || key == "regdate":
			result.Parsed["Created"] = value
		case key == "updated" || key == "changed":
			result.Parsed["Updated"] = value
		}
	}
}

// parseASNWhois extracts structured info from ASN WHOIS
func parseASNWhois(result *WhoisResult) {
	lines := strings.Split(result.RawData, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "%") || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(strings.ToLower(parts[0]))
		value := strings.TrimSpace(parts[1])

		switch {
		case key == "aut-num" || key == "asn":
			result.Parsed["ASN"] = value
		case key == "as-name" || key == "asname":
			result.Parsed["AS Name"] = value
		case key == "descr" || key == "orgname":
			if _, ok := result.Parsed["Description"]; !ok {
				result.Parsed["Description"] = value
			}
		case key == "org" || key == "org-name":
			result.Parsed["Organization"] = value
		case key == "country":
			result.Parsed["Country"] = value
		case strings.Contains(key, "admin"):
			result.Parsed["Admin Contact"] = value
		case strings.Contains(key, "tech"):
			result.Parsed["Tech Contact"] = value
		case key == "import" || key == "export":
			// AS routing policies
		case key == "source":
			result.Parsed["Source"] = value
		case key == "mnt-by":
			result.Parsed["Maintained By"] = value
		case key == "created":
			result.Parsed["Created"] = value
		case key == "last-modified" || key == "changed":
			result.Parsed["Updated"] = value
		}
	}
}

// DisplayResult displays WHOIS result in a formatted way
func DisplayResult(result WhoisResult) {
	fmt.Printf("\n[WHOIS] %s (%s)\n", result.Query, result.QueryType)
	fmt.Println(strings.Repeat("=", 60))

	if result.Error != nil {
		fmt.Printf("Error: %v\n", result.Error)
		return
	}

	switch result.QueryType {
	case "domain":
		displayDomainResult(result)
	case "ip":
		displayIPResult(result)
	case "asn":
		displayASNResult(result)
	}
}

func displayDomainResult(result WhoisResult) {
	fmt.Println("\n--- Domain Information ---")

	if result.Registrar != "" {
		fmt.Printf("  Registrar:    %s\n", result.Registrar)
	}
	if result.Created != "" {
		fmt.Printf("  Created:      %s\n", result.Created)
	}
	if result.Updated != "" {
		fmt.Printf("  Updated:      %s\n", result.Updated)
	}
	if result.Expires != "" {
		fmt.Printf("  Expires:      %s\n", result.Expires)
	}

	if len(result.Status) > 0 {
		fmt.Println("\n--- Status ---")
		for _, status := range result.Status {
			fmt.Printf("  %s\n", status)
		}
	}

	if len(result.NameServer) > 0 {
		fmt.Println("\n--- Name Servers ---")
		for _, ns := range result.NameServer {
			fmt.Printf("  %s\n", ns)
		}
	}

	// Additional parsed info
	fmt.Println("\n--- Additional Info ---")
	for key, value := range result.Parsed {
		if key != "Registrar" && key != "Created" && key != "Updated" && key != "Expires" {
			fmt.Printf("  %-20s %s\n", key+":", value)
		}
	}

	fmt.Println()
}

func displayIPResult(result WhoisResult) {
	fmt.Println("\n--- IP Information ---")

	// Display in a specific order
	order := []string{"IP Range", "CIDR", "Network Name", "Organization", "Org ID",
		"Description", "Country", "State/Province", "City", "Address",
		"Origin AS", "Abuse Contact", "Created", "Updated"}

	for _, key := range order {
		if value, ok := result.Parsed[key]; ok {
			fmt.Printf("  %-20s %s\n", key+":", value)
		}
	}

	// Any remaining keys
	for key, value := range result.Parsed {
		found := false
		for _, k := range order {
			if k == key {
				found = true
				break
			}
		}
		if !found {
			fmt.Printf("  %-20s %s\n", key+":", value)
		}
	}

	fmt.Println()
}

func displayASNResult(result WhoisResult) {
	fmt.Println("\n--- ASN Information ---")

	order := []string{"ASN", "AS Name", "Description", "Organization",
		"Country", "Admin Contact", "Tech Contact", "Maintained By",
		"Source", "Created", "Updated"}

	for _, key := range order {
		if value, ok := result.Parsed[key]; ok {
			fmt.Printf("  %-20s %s\n", key+":", value)
		}
	}

	// Any remaining keys
	for key, value := range result.Parsed {
		found := false
		for _, k := range order {
			if k == key {
				found = true
				break
			}
		}
		if !found {
			fmt.Printf("  %-20s %s\n", key+":", value)
		}
	}

	fmt.Println()
}

// DisplayRaw displays raw WHOIS data
func DisplayRaw(result WhoisResult) {
	fmt.Printf("\n[WHOIS RAW] %s\n", result.Query)
	fmt.Println(strings.Repeat("=", 60))

	if result.Error != nil {
		fmt.Printf("Error: %v\n", result.Error)
		return
	}

	fmt.Println(result.RawData)
}
