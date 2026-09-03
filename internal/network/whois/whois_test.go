package whois

import (
	"bufio"
	"net"
	"strings"
	"testing"
)

// startFakeWhoisServer starts a local TCP listener that reads one query line
// and writes back the given response, then closes the connection. It returns
// the listener's port as a string, suitable for whoisPort.
func startFakeWhoisServer(t *testing.T, response string) (host, port string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start fake whois server: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		reader.ReadString('\n') // consume the query
		conn.Write([]byte(response))
	}()

	h, p, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("failed to split listener address: %v", err)
	}
	return h, p
}

func withWhoisPort(t *testing.T, port string) {
	t.Helper()
	orig := whoisPort
	whoisPort = port
	t.Cleanup(func() { whoisPort = orig })
}

func TestQueryWhoisReadsResponse(t *testing.T) {
	host, port := startFakeWhoisServer(t, "Domain Name: EXAMPLE.COM\nRegistrar: Fake Registrar\n")
	withWhoisPort(t, port)

	got, err := queryWhois(host, "example.com", 3)
	if err != nil {
		t.Fatalf("queryWhois returned error: %v", err)
	}
	if !strings.Contains(got, "Fake Registrar") {
		t.Errorf("queryWhois response = %q, want it to contain Fake Registrar", got)
	}
}

func TestQueryWhoisConnectionRefused(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to reserve a port: %v", err)
	}
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	ln.Close()
	withWhoisPort(t, port)

	if _, err := queryWhois("127.0.0.1", "example.com", 1); err == nil {
		t.Error("queryWhois against a closed port should return an error")
	}
}

func TestLookupDomainInvalidFormat(t *testing.T) {
	result := LookupDomain("notadomain", 3)
	if result.Error == nil {
		t.Error("LookupDomain with no TLD should return an error")
	}
}

func TestLookupDomainSuccess(t *testing.T) {
	host, port := startFakeWhoisServer(t, "Registrar: Test Registrar Inc.\nCreation Date: 2020-01-01\nName Server: ns1.example.com\nDomain Status: active\n")
	withWhoisPort(t, port)

	origServers := WhoisServers
	WhoisServers = map[string]string{"testtld": host}
	t.Cleanup(func() { WhoisServers = origServers })

	result := LookupDomain("example.testtld", 3)
	if result.Error != nil {
		t.Fatalf("LookupDomain returned error: %v", result.Error)
	}
	if result.Registrar != "Test Registrar Inc." {
		t.Errorf("Registrar = %q, want %q", result.Registrar, "Test Registrar Inc.")
	}
	if result.Created != "2020-01-01" {
		t.Errorf("Created = %q, want %q", result.Created, "2020-01-01")
	}
	if len(result.NameServer) != 1 || result.NameServer[0] != "ns1.example.com" {
		t.Errorf("NameServer = %v, want [ns1.example.com]", result.NameServer)
	}
	if len(result.Status) != 1 {
		t.Errorf("Status = %v, want 1 entry", result.Status)
	}
}

func TestLookupDomainUnknownTLDFallsBackToIANA(t *testing.T) {
	// Just verify it doesn't panic and produces a query-type/error outcome;
	// we don't have a fake IANA server, so this will fail to connect, which
	// is itself the expected behavior being exercised (unknown TLD path).
	result := LookupDomain("example.nonexistenttld12345", 1)
	if result.QueryType != "domain" {
		t.Errorf("QueryType = %q, want domain", result.QueryType)
	}
}

func TestLookupIPInvalid(t *testing.T) {
	result := LookupIP("not-an-ip", 3)
	if result.Error == nil {
		t.Error("LookupIP with an invalid IP should return an error")
	}
}

func TestLookupIPSuccess(t *testing.T) {
	host, port := startFakeWhoisServer(t, "NetName: EXAMPLE-NET\nOrgName: Example Org\nCountry: US\n")
	withWhoisPort(t, port)

	origServers := IPWhoisServers
	IPWhoisServers = []string{host}
	t.Cleanup(func() { IPWhoisServers = origServers })

	result := LookupIP("8.8.8.8", 3)
	if result.Error != nil {
		t.Fatalf("LookupIP returned error: %v", result.Error)
	}
	if result.Parsed["Network Name"] != "EXAMPLE-NET" {
		t.Errorf("Parsed[Network Name] = %q, want EXAMPLE-NET", result.Parsed["Network Name"])
	}
	if result.Parsed["Organization"] != "Example Org" {
		t.Errorf("Parsed[Organization] = %q, want Example Org", result.Parsed["Organization"])
	}
}

func TestLookupIPNoMatchReturnsError(t *testing.T) {
	// A single RIR reporting "No match" and no further servers configured
	// should surface as an error rather than a false-positive empty result.
	host, port := startFakeWhoisServer(t, "No match found for this query\n")
	withWhoisPort(t, port)

	origServers := IPWhoisServers
	IPWhoisServers = []string{host}
	t.Cleanup(func() { IPWhoisServers = origServers })

	result := LookupIP("1.2.3.4", 3)
	if result.RawData != "" {
		t.Errorf("LookupIP should not accept a 'No match' response as RawData, got %q", result.RawData)
	}
}

func TestLookupASNSuccess(t *testing.T) {
	host, port := startFakeWhoisServer(t, "as-name: EXAMPLE-AS\ndescr: Example ASN\ncountry: US\n")
	withWhoisPort(t, port)

	origASN := ASNWhoisServer
	ASNWhoisServer = host
	t.Cleanup(func() { ASNWhoisServer = origASN })

	result := LookupASN("15169", 3)
	if result.Error != nil {
		t.Fatalf("LookupASN returned error: %v", result.Error)
	}
	if result.Query != "15169" {
		t.Errorf("Query = %q, want the original input %q (normalization only affects the outgoing query)", result.Query, "15169")
	}
	if result.Parsed["AS Name"] != "EXAMPLE-AS" {
		t.Errorf("Parsed[AS Name] = %q, want EXAMPLE-AS", result.Parsed["AS Name"])
	}
}

func TestLookupASNFallsBackToARIN(t *testing.T) {
	arinHost, arinPort := startFakeWhoisServer(t, "as-name: ARIN-FALLBACK-AS\n")
	withWhoisPort(t, arinPort)

	// ASNWhoisServer (RADB) resolves to a reserved, non-routable hostname so
	// its dial fails fast regardless of whoisPort; arinWhoisServer points at
	// the fake local server, isolating the fallback path.
	origASN := ASNWhoisServer
	origARIN := arinWhoisServer
	ASNWhoisServer = "asn-primary.invalid"
	arinWhoisServer = arinHost
	t.Cleanup(func() {
		ASNWhoisServer = origASN
		arinWhoisServer = origARIN
	})

	result := LookupASN("64512", 3)
	if result.Error != nil {
		t.Fatalf("LookupASN should have fallen back to ARIN successfully, got error: %v", result.Error)
	}
	if result.Parsed["AS Name"] != "ARIN-FALLBACK-AS" {
		t.Errorf("Parsed[AS Name] = %q, want ARIN-FALLBACK-AS (fallback server's response)", result.Parsed["AS Name"])
	}
}

func TestExtractReferral(t *testing.T) {
	tests := []struct {
		data string
		want string
	}{
		{"Registrar WHOIS Server: whois.example-registrar.com\n", "whois.example-registrar.com"},
		{"refer: whois.other.net\n", "whois.other.net"},
		{"no referral here\n", ""},
	}
	for _, tt := range tests {
		if got := extractReferral(tt.data); got != tt.want {
			t.Errorf("extractReferral(%q) = %q, want %q", tt.data, got, tt.want)
		}
	}
}

func TestParseDomainWhois(t *testing.T) {
	result := &WhoisResult{RawData: strings.Join([]string{
		"% comment line should be ignored",
		"Registrar: Example Registrar",
		"Creation Date: 2015-06-01",
		"Updated Date: 2023-01-01",
		"Registry Expiry Date: 2030-06-01",
		"Name Server: ns1.example.com",
		"Name Server: ns2.example.com",
		"Domain Status: clientTransferProhibited",
		"Registrant Country: US",
		"DNSSEC: unsigned",
		"",
	}, "\n"), Parsed: make(map[string]string)}

	parseDomainWhois(result)

	if result.Registrar != "Example Registrar" {
		t.Errorf("Registrar = %q", result.Registrar)
	}
	if result.Created != "2015-06-01" {
		t.Errorf("Created = %q", result.Created)
	}
	if result.Updated != "2023-01-01" {
		t.Errorf("Updated = %q", result.Updated)
	}
	if result.Expires != "2030-06-01" {
		t.Errorf("Expires = %q", result.Expires)
	}
	if len(result.NameServer) != 2 {
		t.Errorf("NameServer = %v, want 2 entries", result.NameServer)
	}
	if len(result.Status) != 1 {
		t.Errorf("Status = %v, want 1 entry", result.Status)
	}
	if result.Parsed["DNSSEC"] != "unsigned" {
		t.Errorf("Parsed[DNSSEC] = %q", result.Parsed["DNSSEC"])
	}
}

func TestParseIPWhois(t *testing.T) {
	result := &WhoisResult{RawData: strings.Join([]string{
		"NetRange: 8.8.8.0 - 8.8.8.255",
		"CIDR: 8.8.8.0/24",
		"OrgName: Google LLC",
		"Country: US",
		"Abuse-Contact: abuse@example.com",
		"RegDate: 2000-01-01",
		"",
	}, "\n"), Parsed: make(map[string]string)}

	parseIPWhois(result)

	if result.Parsed["IP Range"] == "" {
		t.Error("Parsed[IP Range] should be set")
	}
	if result.Parsed["CIDR"] != "8.8.8.0/24" {
		t.Errorf("Parsed[CIDR] = %q", result.Parsed["CIDR"])
	}
	if result.Parsed["Organization"] != "Google LLC" {
		t.Errorf("Parsed[Organization] = %q", result.Parsed["Organization"])
	}
	if result.Parsed["Created"] != "2000-01-01" {
		t.Errorf("Parsed[Created] = %q", result.Parsed["Created"])
	}
}

func TestParseASNWhois(t *testing.T) {
	result := &WhoisResult{RawData: strings.Join([]string{
		"aut-num: AS15169",
		"as-name: GOOGLE",
		"descr: Google LLC",
		"country: US",
		"mnt-by: MAINT-GOOGLE",
		"source: RADB",
		"",
	}, "\n"), Parsed: make(map[string]string)}

	parseASNWhois(result)

	if result.Parsed["ASN"] != "AS15169" {
		t.Errorf("Parsed[ASN] = %q", result.Parsed["ASN"])
	}
	if result.Parsed["AS Name"] != "GOOGLE" {
		t.Errorf("Parsed[AS Name] = %q", result.Parsed["AS Name"])
	}
	if result.Parsed["Maintained By"] != "MAINT-GOOGLE" {
		t.Errorf("Parsed[Maintained By] = %q", result.Parsed["Maintained By"])
	}
}

func TestDisplayFunctions(t *testing.T) {
	// Smoke tests: verify these don't panic across all query types and the
	// error path.
	DisplayResult(WhoisResult{Query: "example.com", QueryType: "domain", Registrar: "X", Parsed: map[string]string{}})
	DisplayResult(WhoisResult{Query: "8.8.8.8", QueryType: "ip", Parsed: map[string]string{"Organization": "X"}})
	DisplayResult(WhoisResult{Query: "AS15169", QueryType: "asn", Parsed: map[string]string{"ASN": "AS15169"}})
	DisplayResult(WhoisResult{Query: "bad", QueryType: "domain", Error: errTest{}})
	DisplayRaw(WhoisResult{Query: "example.com", RawData: "raw data here"})
	DisplayRaw(WhoisResult{Query: "example.com", Error: errTest{}})
}

type errTest struct{}

func (errTest) Error() string { return "test error" }
