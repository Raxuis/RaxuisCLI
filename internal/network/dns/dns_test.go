package dns

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// dnsLabels encodes a dotted domain name as DNS wire-format labels.
func dnsLabels(name string) []byte {
	var buf []byte
	for _, part := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		buf = append(buf, byte(len(part)))
		buf = append(buf, []byte(part)...)
	}
	buf = append(buf, 0x00)
	return buf
}

// questionEnd returns the byte offset just past the single question's
// QNAME+QTYPE+QCLASS (i.e. right after byte 12's start), ignoring any
// trailing bytes from additional records (e.g. an EDNS0 OPT pseudo-record
// modern resolvers append, which real queries commonly include).
func questionEnd(query []byte) int {
	i := 12
	for i < len(query) && query[i] != 0 {
		i += int(query[i]) + 1
	}
	i++    // terminating zero byte
	i += 4 // QTYPE + QCLASS
	if i > len(query) {
		return len(query)
	}
	return i
}

// parseQType extracts the QTYPE from a well-formed single-question DNS query.
func parseQType(query []byte) uint16 {
	end := questionEnd(query)
	if end < 4 {
		return 0
	}
	return binary.BigEndian.Uint16(query[end-4 : end-2])
}

// buildDNSResponse builds a minimal, valid single-answer DNS response for
// the given query, using rdataFor to produce the RDATA for whatever QTYPE
// was actually requested. Only the real question section is echoed back -
// any trailing additional records (e.g. EDNS0 OPT) in the query are dropped,
// since ARCOUNT is always declared as 0 here.
func buildDNSResponse(query []byte, rdataFor map[uint16][]byte) []byte {
	if len(query) < 12 {
		return nil
	}
	qtype := parseQType(query)
	question := query[12:questionEnd(query)]

	rdata, ok := rdataFor[qtype]
	if !ok {
		// NXDOMAIN-ish: no answer records.
		resp := append([]byte{}, query[0:2]...)
		resp = append(resp, 0x81, 0x83, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
		resp = append(resp, question...)
		return resp
	}

	resp := append([]byte{}, query[0:2]...) // ID
	resp = append(resp, 0x81, 0x80)         // flags: response, recursion available, no error
	resp = append(resp, 0x00, 0x01)         // QDCOUNT
	resp = append(resp, 0x00, 0x01)         // ANCOUNT
	resp = append(resp, 0x00, 0x00)         // NSCOUNT
	resp = append(resp, 0x00, 0x00)         // ARCOUNT
	resp = append(resp, question...)        // question section, echoed verbatim

	resp = append(resp, 0xC0, 0x0C)                  // answer NAME: pointer to question name
	resp = append(resp, byte(qtype>>8), byte(qtype)) // TYPE
	resp = append(resp, 0x00, 0x01)                  // CLASS IN
	resp = append(resp, 0x00, 0x00, 0x01, 0x2C)      // TTL 300
	resp = append(resp, byte(len(rdata)>>8), byte(len(rdata)))
	resp = append(resp, rdata...)

	return resp
}

// startFakeDNSServer starts a UDP server answering every query with a
// response built from rdataFor (keyed by QTYPE). It returns the server's
// "host:port" address, suitable for LookupOptions.Nameserver.
func startFakeDNSServer(t *testing.T, rdataFor map[uint16][]byte) string {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start fake DNS server: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	go func() {
		buf := make([]byte, 512)
		for {
			n, addr, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			resp := buildDNSResponse(buf[:n], rdataFor)
			if resp != nil {
				conn.WriteTo(resp, addr)
			}
		}
	}()

	return conn.LocalAddr().String()
}

const (
	qtypeA     = 1
	qtypeNS    = 2
	qtypeCNAME = 5
	qtypeMX    = 15
	qtypeTXT   = 16
	qtypeAAAA  = 28
	qtypePTR   = 12
)

func TestLookupA(t *testing.T) {
	server := startFakeDNSServer(t, map[uint16][]byte{
		qtypeA: net.ParseIP("93.184.216.34").To4(),
	})

	results := Lookup(LookupOptions{Domain: "example.com", RecordType: TypeA, Nameserver: server, Timeout: 3})
	if len(results) != 1 {
		t.Fatalf("Lookup(A) = %d results, want 1", len(results))
	}
	if results[0].Error != nil {
		t.Fatalf("Lookup(A) returned error: %v", results[0].Error)
	}
	if len(results[0].Records) != 1 || results[0].Records[0] != "93.184.216.34" {
		t.Errorf("Lookup(A) records = %v, want [93.184.216.34]", results[0].Records)
	}
}

func TestLookupAAAA(t *testing.T) {
	server := startFakeDNSServer(t, map[uint16][]byte{
		qtypeAAAA: net.ParseIP("2001:db8::1").To16(),
	})

	results := Lookup(LookupOptions{Domain: "example.com", RecordType: TypeAAAA, Nameserver: server, Timeout: 3})
	if len(results) != 1 || results[0].Error != nil {
		t.Fatalf("Lookup(AAAA) = %+v", results)
	}
	if len(results[0].Records) != 1 || results[0].Records[0] != "2001:db8::1" {
		t.Errorf("Lookup(AAAA) records = %v, want [2001:db8::1]", results[0].Records)
	}
}

func TestLookupCNAME(t *testing.T) {
	server := startFakeDNSServer(t, map[uint16][]byte{
		qtypeCNAME: dnsLabels("target.example.net"),
	})

	results := Lookup(LookupOptions{Domain: "www.example.com", RecordType: TypeCNAME, Nameserver: server, Timeout: 3})
	if len(results) != 1 || results[0].Error != nil {
		t.Fatalf("Lookup(CNAME) = %+v", results)
	}
	if len(results[0].Records) != 1 || results[0].Records[0] != "target.example.net." {
		t.Errorf("Lookup(CNAME) records = %v, want [target.example.net.]", results[0].Records)
	}
}

func TestLookupMX(t *testing.T) {
	rdata := append([]byte{0x00, 0x0A}, dnsLabels("mail.example.com")...)
	server := startFakeDNSServer(t, map[uint16][]byte{qtypeMX: rdata})

	results := Lookup(LookupOptions{Domain: "example.com", RecordType: TypeMX, Nameserver: server, Timeout: 3})
	if len(results) != 1 || results[0].Error != nil {
		t.Fatalf("Lookup(MX) = %+v", results)
	}
	if len(results[0].Records) != 1 || !strings.Contains(results[0].Records[0], "mail.example.com") {
		t.Errorf("Lookup(MX) records = %v, want it to mention mail.example.com", results[0].Records)
	}
}

func TestLookupNS(t *testing.T) {
	server := startFakeDNSServer(t, map[uint16][]byte{qtypeNS: dnsLabels("ns1.example.com")})

	results := Lookup(LookupOptions{Domain: "example.com", RecordType: TypeNS, Nameserver: server, Timeout: 3})
	if len(results) != 1 || results[0].Error != nil {
		t.Fatalf("Lookup(NS) = %+v", results)
	}
	if len(results[0].Records) != 1 || results[0].Records[0] != "ns1.example.com." {
		t.Errorf("Lookup(NS) records = %v, want [ns1.example.com.]", results[0].Records)
	}
}

func TestLookupTXT(t *testing.T) {
	txt := "v=spf1 include:_spf.example.com ~all"
	rdata := append([]byte{byte(len(txt))}, []byte(txt)...)
	server := startFakeDNSServer(t, map[uint16][]byte{qtypeTXT: rdata})

	results := Lookup(LookupOptions{Domain: "example.com", RecordType: TypeTXT, Nameserver: server, Timeout: 3})
	if len(results) != 1 || results[0].Error != nil {
		t.Fatalf("Lookup(TXT) = %+v", results)
	}
	if len(results[0].Records) != 1 || results[0].Records[0] != txt {
		t.Errorf("Lookup(TXT) records = %v, want [%s]", results[0].Records, txt)
	}
}

func TestLookupSOAUsesNS(t *testing.T) {
	server := startFakeDNSServer(t, map[uint16][]byte{qtypeNS: dnsLabels("ns1.example.com")})

	results := Lookup(LookupOptions{Domain: "example.com", RecordType: TypeSOA, Nameserver: server, Timeout: 3})
	if len(results) != 1 || results[0].Error != nil {
		t.Fatalf("Lookup(SOA) = %+v", results)
	}
	if len(results[0].Records) != 1 || !strings.Contains(results[0].Records[0], "ns1.example.com") {
		t.Errorf("Lookup(SOA) records = %v, want it to mention ns1.example.com", results[0].Records)
	}
}

func TestLookupANYAggregatesTypes(t *testing.T) {
	server := startFakeDNSServer(t, map[uint16][]byte{
		qtypeA:  net.ParseIP("93.184.216.34").To4(),
		qtypeNS: dnsLabels("ns1.example.com"),
		// AAAA, CNAME, MX, TXT intentionally absent - the fake server returns
		// NXDOMAIN-shaped responses (no answers) for those, which Lookup
		// should silently skip for TypeANY.
	})

	results := Lookup(LookupOptions{Domain: "example.com", RecordType: TypeANY, Nameserver: server, Timeout: 3})
	if len(results) == 0 {
		t.Fatal("Lookup(ANY) returned no results")
	}
	foundA, foundNS := false, false
	for _, r := range results {
		if r.RecordType == TypeA {
			foundA = true
		}
		if r.RecordType == TypeNS {
			foundNS = true
		}
	}
	if !foundA || !foundNS {
		t.Errorf("Lookup(ANY) results = %+v, want both A and NS present", results)
	}
}

func TestLookupErrorPropagates(t *testing.T) {
	// No fake server at all: nameserver points at a closed UDP port, which on
	// a connected UDP socket makes the query time out or fail quickly.
	conn, _ := net.ListenPacket("udp", "127.0.0.1:0")
	addr := conn.LocalAddr().String()
	conn.Close()

	results := Lookup(LookupOptions{Domain: "example.com", RecordType: TypeA, Nameserver: addr, Timeout: 1})
	if len(results) != 1 || results[0].Error == nil {
		t.Errorf("Lookup against a closed resolver should report an error, got %+v", results)
	}
}

func TestReverseLookup(t *testing.T) {
	server := startFakeDNSServer(t, map[uint16][]byte{qtypePTR: dnsLabels("host.example.com")})

	result := ReverseLookup("93.184.216.34", server, 3)
	if result.Error != nil {
		t.Fatalf("ReverseLookup returned error: %v", result.Error)
	}
	if len(result.Hostname) != 1 || result.Hostname[0] != "host.example.com." {
		t.Errorf("ReverseLookup hostnames = %v, want [host.example.com.]", result.Hostname)
	}
}

func TestGetResolverDefaultAndCustom(t *testing.T) {
	if getResolver("", 5) != net.DefaultResolver {
		t.Error("getResolver(\"\") should return net.DefaultResolver")
	}
	custom := getResolver("127.0.0.1", 5)
	if custom == net.DefaultResolver {
		t.Error("getResolver(nameserver) should return a custom resolver, not the default")
	}
	if !custom.PreferGo {
		t.Error("custom resolver should set PreferGo")
	}
}

func TestBuildAXFRQuery(t *testing.T) {
	query := buildAXFRQuery("example.com")

	if len(query) < 12 {
		t.Fatalf("buildAXFRQuery produced too short a query: %d bytes", len(query))
	}
	// QTYPE for AXFR (252) should appear right before the final QCLASS bytes.
	qtype := binary.BigEndian.Uint16(query[len(query)-4 : len(query)-2])
	if qtype != 252 {
		t.Errorf("AXFR query QTYPE = %d, want 252", qtype)
	}
	if !bytes.Contains(query, dnsLabels("example.com")) {
		t.Error("AXFR query should contain the encoded QNAME for example.com")
	}
}

func TestAttemptAXFRRefused(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start listener: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		lenBuf := make([]byte, 2)
		io.ReadFull(conn, lenBuf)
		qlen := int(lenBuf[0])<<8 | int(lenBuf[1])
		query := make([]byte, qlen)
		io.ReadFull(conn, query)

		// Respond REFUSED (RCODE=5).
		resp := append([]byte{}, query[0:2]...)
		resp = append(resp, 0x81, 0x85, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
		respLen := uint16(len(resp))
		conn.Write([]byte{byte(respLen >> 8), byte(respLen & 0xff)})
		conn.Write(resp)
	}()

	result := AttemptAXFR("example.com", ln.Addr().String(), 3)
	if result.Success {
		t.Error("AttemptAXFR should not report success for a REFUSED response")
	}
	if result.Error == nil {
		t.Error("AttemptAXFR should report an error for a REFUSED response")
	}
}

func TestAttemptAXFRSuccess(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start listener: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		lenBuf := make([]byte, 2)
		io.ReadFull(conn, lenBuf)
		qlen := int(lenBuf[0])<<8 | int(lenBuf[1])
		query := make([]byte, qlen)
		io.ReadFull(conn, query)

		// Respond NOERROR (RCODE=0).
		resp := append([]byte{}, query[0:2]...)
		resp = append(resp, 0x81, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
		respLen := uint16(len(resp))
		conn.Write([]byte{byte(respLen >> 8), byte(respLen & 0xff)})
		conn.Write(resp)
	}()

	result := AttemptAXFR("example.com", ln.Addr().String(), 3)
	if !result.Success {
		t.Errorf("AttemptAXFR should report success for a NOERROR response, got error: %v", result.Error)
	}
}

func TestAttemptAXFRConnectionFailure(t *testing.T) {
	conn, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := conn.Addr().String()
	conn.Close()

	result := AttemptAXFR("example.com", addr, 1)
	if result.Error == nil {
		t.Error("AttemptAXFR against a closed port should return an error")
	}
}

func TestBruteSubdomains(t *testing.T) {
	server := startFakeDNSServer(t, map[uint16][]byte{qtypeA: net.ParseIP("10.0.0.1").To4()})

	dir := t.TempDir()
	wordlistPath := filepath.Join(dir, "words.txt")
	content := "www\n# comment\nmail\n\nadmin\n"
	if err := os.WriteFile(wordlistPath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write wordlist: %v", err)
	}

	result := BruteSubdomains("example.com", wordlistPath, server, 3, 4)
	if result.Total != 3 {
		t.Errorf("Total = %d, want 3", result.Total)
	}
	if result.Found != 3 {
		t.Errorf("Found = %d, want 3 (fake server answers every query)", result.Found)
	}
	// Sorted alphabetically.
	if len(result.Subdomains) != 3 || result.Subdomains[0].Subdomain != "admin.example.com" {
		t.Errorf("Subdomains = %+v, want sorted starting with admin.example.com", result.Subdomains)
	}
}

func TestBruteSubdomainsMissingWordlist(t *testing.T) {
	result := BruteSubdomains("example.com", "/nonexistent/wordlist.txt", "", 1, 1)
	if result.Total != 0 {
		t.Errorf("Total = %d, want 0 for a missing wordlist", result.Total)
	}
}

func TestDisplayFunctions(t *testing.T) {
	orig := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	defer func() { os.Stdout = orig }()
	go io.Copy(io.Discard, r)

	DisplayLookupResults([]LookupResult{
		{Domain: "example.com", RecordType: TypeA, Records: []string{"1.2.3.4"}},
		{Domain: "example.com", RecordType: TypeMX, Error: errDNSTest{}},
		{Domain: "example.com", RecordType: TypeTXT},
	})
	DisplayReverseResult(ReverseResult{IP: "1.2.3.4", Hostname: []string{"host.example.com"}})
	DisplayReverseResult(ReverseResult{IP: "1.2.3.4", Error: errDNSTest{}})
	DisplayReverseResult(ReverseResult{IP: "1.2.3.4"})
	DisplayAXFRResult(AXFRResult{Domain: "example.com", Server: "ns1", Success: true, Records: []string{"info"}})
	DisplayAXFRResult(AXFRResult{Domain: "example.com", Server: "ns1", Error: errDNSTest{}})
	DisplayBruteResult(BruteResult{Domain: "example.com", Total: 2, Found: 0})
	DisplayBruteResult(BruteResult{Domain: "example.com", Total: 2, Found: 1, Subdomains: []SubdomainResult{{Subdomain: "www.example.com", IPs: []string{"1.2.3.4"}}}})

	w.Close()
	time.Sleep(10 * time.Millisecond)
}

type errDNSTest struct{}

func (errDNSTest) Error() string { return "dns test error" }
