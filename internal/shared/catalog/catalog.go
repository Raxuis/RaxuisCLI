// Package catalog provides deterministic metadata for every public CLI command.
package catalog

import (
	"fmt"
	"sort"
	"strings"
)

//go:generate go run ./gen -root ../../..

// Maturity describes how complete and dependable a command implementation is.
type Maturity string

const (
	MaturityStable        Maturity = "stable"
	MaturityExperimental  Maturity = "experimental"
	MaturityInformational Maturity = "informational"
)

// SafetyLevel describes the operational risk of invoking a command.
type SafetyLevel string

const (
	SafetySafe      SafetyLevel = "safe"
	SafetyPassive   SafetyLevel = "passive"
	SafetyActive    SafetyLevel = "active"
	SafetyDangerous SafetyLevel = "dangerous"
)

// Entry is the user-facing metadata for one visible Cobra command.
type Entry struct {
	Path       string
	Summary    string
	Category   string
	Maturity   Maturity
	Safety     SafetyLevel
	TUIAllowed bool
}

const (
	// BeginMarker and EndMarker delimit documentation owned by the generator.
	BeginMarker = "<!-- BEGIN GENERATED COMMAND CATALOG -->"
	EndMarker   = "<!-- END GENERATED COMMAND CATALOG -->"
)

type commandSpec struct {
	Path    string
	Summary string
}

var commandSpecs = []commandSpec{
	{Path: "raxuiscli", Summary: "A powerful CLI toolkit"},
	{Path: "raxuiscli audit", Summary: "Passive security audits with versioned reports"},
	{Path: "raxuiscli audit dns", Summary: "Audit a domain's DNS/email posture and produce a versioned report"},
	{Path: "raxuiscli audit tls", Summary: "Audit TLS/SSL posture and produce a versioned report"},
	{Path: "raxuiscli audit web", Summary: "Passively inspect HTTP security headers and TLS certificates"},
	{Path: "raxuiscli certinfo", Summary: "Analyze X.509 certificates"},
	{Path: "raxuiscli certinfo chain", Summary: "Display full certificate chain"},
	{Path: "raxuiscli certinfo compare", Summary: "Compare two certificates"},
	{Path: "raxuiscli certinfo san", Summary: "Extract Subject Alternative Names"},
	{Path: "raxuiscli certinfo validate", Summary: "Validate certificate"},
	{Path: "raxuiscli cipher", Summary: "Classical cipher operations (XOR, Vigenere, frequency analysis)"},
	{Path: "raxuiscli cipher atbash", Summary: "Atbash cipher (A=Z, B=Y, ...)"},
	{Path: "raxuiscli cipher caesar", Summary: "Caesar cipher encrypt/decrypt/brute-force"},
	{Path: "raxuiscli cipher detect", Summary: "Detect cipher type"},
	{Path: "raxuiscli cipher freq", Summary: "Frequency analysis of text"},
	{Path: "raxuiscli cipher rot13", Summary: "ROT13 encode/decode"},
	{Path: "raxuiscli cipher vigenere", Summary: "Vigenere cipher encrypt/decrypt"},
	{Path: "raxuiscli cipher vigenere-crack", Summary: "Crack Vigenere cipher using Kasiski examination"},
	{Path: "raxuiscli cipher xor", Summary: "XOR encrypt/decrypt with key"},
	{Path: "raxuiscli cipher xor-brute", Summary: "Brute force XOR encryption"},
	{Path: "raxuiscli cloud", Summary: "Cloud infrastructure enumeration"},
	{Path: "raxuiscli cloud aws", Summary: "AWS enumeration"},
	{Path: "raxuiscli cloud aws metadata", Summary: "Check AWS metadata service"},
	{Path: "raxuiscli cloud aws s3", Summary: "Enumerate S3 buckets"},
	{Path: "raxuiscli cloud azure", Summary: "Azure enumeration"},
	{Path: "raxuiscli cloud azure blob", Summary: "Enumerate Azure blob storage"},
	{Path: "raxuiscli cloud azure metadata", Summary: "Check Azure metadata service"},
	{Path: "raxuiscli cloud gcp", Summary: "GCP enumeration"},
	{Path: "raxuiscli cloud gcp bucket", Summary: "Enumerate GCP storage buckets"},
	{Path: "raxuiscli cloud gcp metadata", Summary: "Check GCP metadata service"},
	{Path: "raxuiscli cloud metadata", Summary: "Check cloud metadata service"},
	{Path: "raxuiscli compare", Summary: "Compare two versioned audit reports"},
	{Path: "raxuiscli completion", Summary: "Generate the autocompletion script for the specified shell"},
	{Path: "raxuiscli completion bash", Summary: "Generate the autocompletion script for bash"},
	{Path: "raxuiscli completion fish", Summary: "Generate the autocompletion script for fish"},
	{Path: "raxuiscli completion powershell", Summary: "Generate the autocompletion script for powershell"},
	{Path: "raxuiscli completion zsh", Summary: "Generate the autocompletion script for zsh"},
	{Path: "raxuiscli container", Summary: "Container security assessment"},
	{Path: "raxuiscli container check", Summary: "Full container security check"},
	{Path: "raxuiscli container detect", Summary: "Detect container environment"},
	{Path: "raxuiscli container escape", Summary: "Check container escape vectors"},
	{Path: "raxuiscli container secrets", Summary: "Find container secrets"},
	{Path: "raxuiscli cookie", Summary: "Cookie decoding and analysis"},
	{Path: "raxuiscli cookie analyze", Summary: "Analyze cookie security"},
	{Path: "raxuiscli cookie bulk", Summary: "Analyze multiple cookies"},
	{Path: "raxuiscli cookie decode", Summary: "Decode cookie value"},
	{Path: "raxuiscli cookie detect", Summary: "Detect session type"},
	{Path: "raxuiscli cookie express", Summary: "Decode Express.js session cookie"},
	{Path: "raxuiscli cookie flask", Summary: "Decode Flask session cookie"},
	{Path: "raxuiscli cookie sensitive", Summary: "Check for sensitive data"},
	{Path: "raxuiscli creds", Summary: "Credential extraction and manipulation"},
	{Path: "raxuiscli creds combo", Summary: "Generate credential combinations"},
	{Path: "raxuiscli creds convert", Summary: "Convert credential format"},
	{Path: "raxuiscli creds decode", Summary: "Decode encoded credentials"},
	{Path: "raxuiscli creds extract", Summary: "Extract credentials from file"},
	{Path: "raxuiscli creds merge", Summary: "Merge and deduplicate credential files"},
	{Path: "raxuiscli demo", Summary: "Run safe local demonstrations without public network access"},
	{Path: "raxuiscli demo web", Summary: "Audit an intentionally weak local HTTPS fixture"},
	{Path: "raxuiscli dns", Summary: "DNS lookup and analysis tools"},
	{Path: "raxuiscli dns axfr", Summary: "Attempt DNS zone transfer"},
	{Path: "raxuiscli dns brute", Summary: "Bruteforce subdomains"},
	{Path: "raxuiscli dns lookup", Summary: "Perform DNS lookup"},
	{Path: "raxuiscli dns reverse", Summary: "Perform reverse DNS lookup"},
	{Path: "raxuiscli encode", Summary: "Encode text in various formats"},
	{Path: "raxuiscli encode decode", Summary: "Decode text from various formats"},
	{Path: "raxuiscli encode rot-brute", Summary: "Brute force all ROT-N values"},
	{Path: "raxuiscli entropy", Summary: "Calculate file entropy"},
	{Path: "raxuiscli exfil", Summary: "Data exfiltration helpers"},
	{Path: "raxuiscli exfil chunk", Summary: "Split file into chunks"},
	{Path: "raxuiscli exfil dns", Summary: "Generate DNS exfiltration queries"},
	{Path: "raxuiscli exfil encode", Summary: "Encode file for exfiltration"},
	{Path: "raxuiscli exfil receiver", Summary: "Generate receiver script"},
	{Path: "raxuiscli exfil script", Summary: "Generate exfiltration script"},
	{Path: "raxuiscli files", Summary: "File operations"},
	{Path: "raxuiscli files checksum", Summary: "Calculate file checksums"},
	{Path: "raxuiscli files compress", Summary: "Compress files"},
	{Path: "raxuiscli files decrypt", Summary: "Decrypt a file"},
	{Path: "raxuiscli files encrypt", Summary: "Encrypt a file"},
	{Path: "raxuiscli files extract", Summary: "Extract archive"},
	{Path: "raxuiscli files find", Summary: "Find files"},
	{Path: "raxuiscli files shred", Summary: "Securely delete files"},
	{Path: "raxuiscli fuzz", Summary: "Web fuzzing tools (directory, parameter, vhost)"},
	{Path: "raxuiscli fuzz dir", Summary: "Directory/file brute force"},
	{Path: "raxuiscli fuzz param", Summary: "Parameter discovery"},
	{Path: "raxuiscli fuzz vhost", Summary: "Virtual host discovery"},
	{Path: "raxuiscli hash", Summary: "Hash text or files"},
	{Path: "raxuiscli hash crack", Summary: "Crack hash using wordlist"},
	{Path: "raxuiscli hash identify", Summary: "Identify hash type"},
	{Path: "raxuiscli help", Summary: "Help about any command"},
	{Path: "raxuiscli hexdump", Summary: "Display file contents in hex and ASCII"},
	{Path: "raxuiscli http", Summary: "HTTP request tools and security header analysis"},
	{Path: "raxuiscli http curl", Summary: "Generate curl command"},
	{Path: "raxuiscli http delete", Summary: "Perform HTTP DELETE request"},
	{Path: "raxuiscli http get", Summary: "Perform HTTP GET request"},
	{Path: "raxuiscli http head", Summary: "Perform HTTP HEAD request"},
	{Path: "raxuiscli http headers", Summary: "Analyze security headers"},
	{Path: "raxuiscli http options", Summary: "Perform HTTP OPTIONS request"},
	{Path: "raxuiscli http post", Summary: "Perform HTTP POST request"},
	{Path: "raxuiscli http put", Summary: "Perform HTTP PUT request"},
	{Path: "raxuiscli http trace", Summary: "Trace redirects"},
	{Path: "raxuiscli interactive", Summary: "Launch the guided terminal interface"},
	{Path: "raxuiscli jwt", Summary: "JWT token operations (decode, forge, crack, attack)"},
	{Path: "raxuiscli jwt check", Summary: "Check JWT for vulnerabilities"},
	{Path: "raxuiscli jwt crack", Summary: "Brute force JWT secret"},
	{Path: "raxuiscli jwt decode", Summary: "Decode JWT without verification"},
	{Path: "raxuiscli jwt forge", Summary: "Create a new JWT token"},
	{Path: "raxuiscli jwt none-attack", Summary: "Exploit algorithm 'none' vulnerability"},
	{Path: "raxuiscli jwt verify", Summary: "Verify JWT signature"},
	{Path: "raxuiscli k8s", Summary: "Kubernetes security assessment"},
	{Path: "raxuiscli k8s check", Summary: "Full Kubernetes security check"},
	{Path: "raxuiscli k8s commands", Summary: "Show useful kubectl commands"},
	{Path: "raxuiscli k8s detect", Summary: "Detect Kubernetes environment"},
	{Path: "raxuiscli k8s enum", Summary: "Enumerate accessible resources"},
	{Path: "raxuiscli k8s privesc", Summary: "Check privilege escalation paths"},
	{Path: "raxuiscli k8s secrets", Summary: "List accessible secrets"},
	{Path: "raxuiscli kerberos", Summary: "Kerberos attack helpers"},
	{Path: "raxuiscli kerberos asrep", Summary: "AS-REP Roasting commands"},
	{Path: "raxuiscli kerberos golden", Summary: "Golden ticket commands"},
	{Path: "raxuiscli kerberos parse", Summary: "Parse Kerberos hash"},
	{Path: "raxuiscli kerberos roast", Summary: "Kerberoasting commands"},
	{Path: "raxuiscli kerberos silver", Summary: "Silver ticket commands"},
	{Path: "raxuiscli keygen", Summary: "Generate cryptographic keys and certificates"},
	{Path: "raxuiscli keygen aes", Summary: "Generate AES key"},
	{Path: "raxuiscli keygen cert", Summary: "Generate self-signed certificate"},
	{Path: "raxuiscli keygen ecdsa", Summary: "Generate ECDSA key pair"},
	{Path: "raxuiscli keygen ed25519", Summary: "Generate Ed25519 key pair"},
	{Path: "raxuiscli keygen random", Summary: "Generate random bytes"},
	{Path: "raxuiscli keygen rsa", Summary: "Generate RSA key pair"},
	{Path: "raxuiscli keygen ssh", Summary: "Generate SSH key pair"},
	{Path: "raxuiscli ldap", Summary: "Active Directory LDAP enumeration"},
	{Path: "raxuiscli ldap enum", Summary: "Full AD enumeration"},
	{Path: "raxuiscli ldap test", Summary: "Test LDAP connectivity"},
	{Path: "raxuiscli ldap users", Summary: "Enumerate AD users"},
	{Path: "raxuiscli metadata", Summary: "Extract file metadata"},
	{Path: "raxuiscli metadata strip", Summary: "Strip metadata from a file"},
	{Path: "raxuiscli ntlm", Summary: "NTLM hash operations"},
	{Path: "raxuiscli ntlm crack", Summary: "Crack NTLM hash"},
	{Path: "raxuiscli ntlm hash", Summary: "Generate NTLM hash"},
	{Path: "raxuiscli ntlm identify", Summary: "Identify hash type"},
	{Path: "raxuiscli ntlm parse", Summary: "Parse NTLM dump format"},
	{Path: "raxuiscli ntlm pth", Summary: "Generate pass-the-hash commands"},
	{Path: "raxuiscli obfuscate", Summary: "Payload obfuscation"},
	{Path: "raxuiscli obfuscate bash", Summary: "Obfuscate Bash commands"},
	{Path: "raxuiscli obfuscate ps", Summary: "Obfuscate PowerShell"},
	{Path: "raxuiscli obfuscate shellcode", Summary: "Obfuscate shellcode"},
	{Path: "raxuiscli obfuscate shellcode-hex", Summary: "Obfuscate shellcode from hex string"},
	{Path: "raxuiscli obfuscate string", Summary: "Obfuscate string"},
	{Path: "raxuiscli persist", Summary: "Persistence mechanism helpers"},
	{Path: "raxuiscli persist check", Summary: "Check existing persistence"},
	{Path: "raxuiscli persist cron", Summary: "Generate cron persistence"},
	{Path: "raxuiscli persist launchd", Summary: "Generate launchd plist (macOS)"},
	{Path: "raxuiscli persist list", Summary: "List persistence techniques"},
	{Path: "raxuiscli persist systemd", Summary: "Generate systemd service"},
	{Path: "raxuiscli pivot", Summary: "Network pivoting and proxying"},
	{Path: "raxuiscli pivot forward", Summary: "TCP port forwarding"},
	{Path: "raxuiscli pivot socks5", Summary: "Start SOCKS5 proxy"},
	{Path: "raxuiscli pivot test", Summary: "Test remote connectivity"},
	{Path: "raxuiscli poison", Summary: "Network poisoning helpers"},
	{Path: "raxuiscli poison analyze", Summary: "Analyze network for poisoning opportunities"},
	{Path: "raxuiscli poison arp", Summary: "ARP poisoning commands"},
	{Path: "raxuiscli poison dhcp", Summary: "DHCP poisoning information"},
	{Path: "raxuiscli poison llmnr", Summary: "LLMNR poisoning commands"},
	{Path: "raxuiscli poison mdns", Summary: "mDNS poisoning commands"},
	{Path: "raxuiscli poison nbtns", Summary: "NBT-NS poisoning commands"},
	{Path: "raxuiscli poison protocols", Summary: "List poisoning protocols"},
	{Path: "raxuiscli poison responder", Summary: "Responder command generator"},
	{Path: "raxuiscli ports", Summary: "Check open ports on a host"},
	{Path: "raxuiscli privesc", Summary: "Privilege escalation enumeration"},
	{Path: "raxuiscli privesc capabilities", Summary: "Check Linux capabilities"},
	{Path: "raxuiscli privesc check", Summary: "Run all privilege escalation checks"},
	{Path: "raxuiscli privesc cron", Summary: "Check cron jobs"},
	{Path: "raxuiscli privesc info", Summary: "Display system information"},
	{Path: "raxuiscli privesc passwords", Summary: "Check password files"},
	{Path: "raxuiscli privesc sudo", Summary: "Check sudo configuration"},
	{Path: "raxuiscli privesc suid", Summary: "Check SUID/SGID binaries"},
	{Path: "raxuiscli privesc writable", Summary: "Check writable paths"},
	{Path: "raxuiscli pwgen", Summary: "Generate secure passwords"},
	{Path: "raxuiscli pwgen generate", Summary: "Generate password(s)"},
	{Path: "raxuiscli recon", Summary: "Banner grabbing and service detection"},
	{Path: "raxuiscli smb", Summary: "SMB enumeration and analysis"},
	{Path: "raxuiscli smb null", Summary: "Test null session"},
	{Path: "raxuiscli smb scan", Summary: "Scan SMB service"},
	{Path: "raxuiscli smb shares", Summary: "Enumerate SMB shares"},
	{Path: "raxuiscli strings", Summary: "Extract printable strings from files"},
	{Path: "raxuiscli tlsscan", Summary: "Audit a server's TLS/SSL posture"},
	{Path: "raxuiscli todo", Summary: "Manage your todo list"},
	{Path: "raxuiscli todo add", Summary: "Add a new todo item"},
	{Path: "raxuiscli todo complete", Summary: "Mark a todo item as complete"},
	{Path: "raxuiscli todo incomplete", Summary: "Mark a todo item as incomplete"},
	{Path: "raxuiscli todo list", Summary: "List all todo items"},
	{Path: "raxuiscli tunnel", Summary: "Network tunneling utilities"},
	{Path: "raxuiscli tunnel decode", Summary: "Decode tunneled data"},
	{Path: "raxuiscli tunnel dns", Summary: "DNS tunneling information"},
	{Path: "raxuiscli tunnel encode", Summary: "Encode data for tunneling"},
	{Path: "raxuiscli tunnel tcp", Summary: "TCP port forwarding"},
	{Path: "raxuiscli version", Summary: "Print version, commit and build information"},
	{Path: "raxuiscli vuln", Summary: "Vulnerability scanning and testing"},
	{Path: "raxuiscli vuln cors", Summary: "Test for CORS misconfiguration"},
	{Path: "raxuiscli vuln graphql", Summary: "Test GraphQL endpoint security"},
	{Path: "raxuiscli vuln headers", Summary: "Check security headers"},
	{Path: "raxuiscli vuln host", Summary: "Test for Host header injection"},
	{Path: "raxuiscli vuln lfi", Summary: "Test for Local File Inclusion vulnerabilities"},
	{Path: "raxuiscli vuln nosqli", Summary: "Test for NoSQL injection"},
	{Path: "raxuiscli vuln payloads", Summary: "List vulnerability payloads"},
	{Path: "raxuiscli vuln race", Summary: "Test for race condition vulnerabilities"},
	{Path: "raxuiscli vuln scan", Summary: "Quick vulnerability scan"},
	{Path: "raxuiscli vuln sqli", Summary: "Test for SQL injection vulnerabilities"},
	{Path: "raxuiscli vuln xss", Summary: "Test for XSS vulnerabilities"},
	{Path: "raxuiscli vuln xxe", Summary: "Test for XXE vulnerabilities"},
	{Path: "raxuiscli whois", Summary: "WHOIS lookup for domains, IPs, and ASNs"},
}

var entries = buildEntries(commandSpecs)

func buildEntries(specs []commandSpec) []Entry {
	result := make([]Entry, 0, len(specs))
	for _, spec := range specs {
		result = append(result, Entry{
			Path:       spec.Path,
			Summary:    spec.Summary,
			Category:   categoryFor(spec.Path),
			Maturity:   maturityFor(spec.Path),
			Safety:     safetyFor(spec.Path),
			TUIAllowed: spec.Path == "raxuiscli audit web" || spec.Path == "raxuiscli compare" || spec.Path == "raxuiscli demo web",
		})
	}
	return result
}

func maturityFor(path string) Maturity {
	switch path {
	case "raxuiscli", "raxuiscli audit", "raxuiscli audit dns", "raxuiscli audit tls", "raxuiscli audit web", "raxuiscli compare", "raxuiscli demo", "raxuiscli demo web", "raxuiscli interactive",
		"raxuiscli completion", "raxuiscli completion bash", "raxuiscli completion fish", "raxuiscli completion powershell", "raxuiscli completion zsh", "raxuiscli help":
		return MaturityStable
	case "raxuiscli http curl", "raxuiscli k8s commands", "raxuiscli kerberos asrep", "raxuiscli kerberos golden", "raxuiscli kerberos roast", "raxuiscli kerberos silver", "raxuiscli ntlm pth", "raxuiscli persist list", "raxuiscli poison arp", "raxuiscli poison dhcp", "raxuiscli poison llmnr", "raxuiscli poison mdns", "raxuiscli poison nbtns", "raxuiscli poison protocols", "raxuiscli poison responder", "raxuiscli tunnel dns", "raxuiscli vuln payloads":
		return MaturityInformational
	default:
		return MaturityExperimental
	}
}

func categoryFor(path string) string {
	parts := strings.Fields(path)
	if len(parts) == 1 {
		return "core"
	}
	switch parts[1] {
	case "completion", "help":
		return "core"
	case "audit", "compare", "demo", "interactive":
		return "audit & reporting"
	case "dns", "recon", "whois":
		return "network"
	case "certinfo", "cipher", "jwt", "keygen", "tlsscan":
		return "cryptography"
	case "cloud", "container", "k8s":
		return "infrastructure"
	case "cookie", "fuzz", "http", "vuln":
		return "web security"
	case "creds", "exfil", "kerberos", "ldap", "ntlm", "obfuscate", "persist", "pivot", "poison", "privesc", "smb", "tunnel":
		return "offensive security"
	default:
		return "utilities"
	}
}

// safetyOverrides classifies invocations by actual behavior, not family.
// Entries that read local state only (no network action) are passive;
// entries that compute/transform/format text with no I/O are safe.
var safetyOverrides = map[string]SafetyLevel{
	"raxuiscli http curl":        SafetySafe,
	"raxuiscli k8s commands":     SafetyPassive,
	"raxuiscli kerberos asrep":   SafetySafe,
	"raxuiscli kerberos golden":  SafetySafe,
	"raxuiscli kerberos parse":   SafetySafe,
	"raxuiscli kerberos roast":   SafetySafe,
	"raxuiscli kerberos silver":  SafetySafe,
	"raxuiscli ntlm hash":        SafetySafe,
	"raxuiscli ntlm identify":    SafetySafe,
	"raxuiscli ntlm parse":       SafetySafe,
	"raxuiscli ntlm pth":         SafetySafe,
	"raxuiscli persist cron":     SafetySafe,
	"raxuiscli persist launchd":  SafetySafe,
	"raxuiscli persist list":     SafetySafe,
	"raxuiscli persist systemd":  SafetySafe,
	"raxuiscli poison arp":       SafetySafe,
	"raxuiscli poison dhcp":      SafetySafe,
	"raxuiscli poison llmnr":     SafetySafe,
	"raxuiscli poison mdns":      SafetySafe,
	"raxuiscli poison nbtns":     SafetySafe,
	"raxuiscli poison protocols": SafetySafe,
	"raxuiscli poison responder": SafetySafe,
	"raxuiscli tunnel decode":    SafetySafe,
	"raxuiscli tunnel dns":       SafetySafe,
	"raxuiscli tunnel encode":    SafetySafe,
	"raxuiscli vuln payloads":    SafetySafe,
}

// safetyFor returns the SafetyLevel for a command path, checking overrides first,
// then special cases, then family-level classification by prefix.
func safetyFor(path string) SafetyLevel {
	if override, ok := safetyOverrides[path]; ok {
		return override
	}

	if path == "raxuiscli audit web" {
		return SafetyPassive
	}

	// Safe: root command and utilities that only transform/format data without I/O.
	if path == "raxuiscli" {
		return SafetySafe
	}
	safePrefixes := []string{
		"raxuiscli compare", "raxuiscli demo", "raxuiscli interactive",
		"raxuiscli cipher", "raxuiscli certinfo", "raxuiscli keygen",
		"raxuiscli cookie", "raxuiscli encode", "raxuiscli entropy",
		"raxuiscli hash", "raxuiscli hexdump", "raxuiscli metadata",
		"raxuiscli pwgen", "raxuiscli strings", "raxuiscli todo", "raxuiscli version",
	}
	if hasPrefix(path, safePrefixes) {
		return SafetySafe
	}

	// Dangerous: offensive/system commands.
	dangerousPrefixes := []string{
		"raxuiscli creds", "raxuiscli exfil",
		"raxuiscli kerberos", "raxuiscli ldap", "raxuiscli ntlm",
		"raxuiscli obfuscate", "raxuiscli persist", "raxuiscli pivot",
		"raxuiscli poison", "raxuiscli privesc", "raxuiscli smb", "raxuiscli tunnel",
	}
	if hasPrefix(path, dangerousPrefixes) || path == "raxuiscli files shred" {
		return SafetyDangerous
	}

	// Active: network testing and scanning.
	activePrefixes := []string{
		"raxuiscli dns axfr", "raxuiscli dns brute",
		"raxuiscli fuzz", "raxuiscli vuln",
		"raxuiscli cloud", "raxuiscli container", "raxuiscli k8s", "raxuiscli ports",
		"raxuiscli http post", "raxuiscli http put", "raxuiscli http delete",
		"raxuiscli http options", "raxuiscli jwt none-attack",
		"raxuiscli tlsscan", "raxuiscli audit tls", "raxuiscli audit dns",
	}
	if hasPrefix(path, activePrefixes) {
		return SafetyActive
	}

	// Passive: information gathering only.
	passivePrefixes := []string{
		"raxuiscli dns", "raxuiscli whois", "raxuiscli recon", "raxuiscli http",
	}
	if hasPrefix(path, passivePrefixes) {
		return SafetyPassive
	}

	return SafetySafe
}

// hasPrefix returns true if path matches any string exactly or has it as a prefix.
func hasPrefix(path string, candidates []string) bool {
	for _, candidate := range candidates {
		if strings.HasPrefix(path, candidate) {
			return true
		}
	}
	return false
}

// All returns the command catalog in path order. The returned slice is a copy.
func All() []Entry {
	result := append([]Entry(nil), entries...)
	sort.Slice(result, func(i, j int) bool { return result[i].Path < result[j].Path })
	return result
}

// Lookup returns metadata for path.
func Lookup(path string) (Entry, bool) {
	for _, entry := range entries {
		if entry.Path == path {
			return entry, true
		}
	}
	return Entry{}, false
}

// Validate checks the catalog's completeness-independent invariants.
func Validate(items []Entry) error {
	seen := make(map[string]struct{}, len(items))
	for index, entry := range items {
		if strings.TrimSpace(entry.Path) == "" {
			return fmt.Errorf("entry %d has an empty path", index)
		}
		if entry.Path != strings.TrimSpace(entry.Path) || strings.Contains(entry.Path, "  ") {
			return fmt.Errorf("entry %q has a non-canonical path", entry.Path)
		}
		if _, exists := seen[entry.Path]; exists {
			return fmt.Errorf("duplicate command path %q", entry.Path)
		}
		seen[entry.Path] = struct{}{}
		if strings.TrimSpace(entry.Summary) == "" {
			return fmt.Errorf("entry %q has an empty summary", entry.Path)
		}
		if strings.TrimSpace(entry.Category) == "" {
			return fmt.Errorf("entry %q has an empty category", entry.Path)
		}
		switch entry.Maturity {
		case MaturityStable, MaturityExperimental, MaturityInformational:
		default:
			return fmt.Errorf("entry %q has invalid maturity %q", entry.Path, entry.Maturity)
		}
		switch entry.Safety {
		case SafetySafe, SafetyPassive, SafetyActive, SafetyDangerous:
		default:
			return fmt.Errorf("entry %q has invalid safety level %q", entry.Path, entry.Safety)
		}
		if entry.TUIAllowed && (entry.Safety == SafetyActive || entry.Safety == SafetyDangerous) {
			return fmt.Errorf("entry %q cannot be TUI-enabled at safety level %q", entry.Path, entry.Safety)
		}
	}
	return nil
}

// RenderReadmeStatus renders the compact, generated README status section.
func RenderReadmeStatus(items []Entry) (string, error) {
	if err := Validate(items); err != nil {
		return "", err
	}
	type counts struct {
		stable, experimental, informational int
	}
	byCategory := make(map[string]counts)
	for _, entry := range items {
		count := byCategory[entry.Category]
		switch entry.Maturity {
		case MaturityStable:
			count.stable++
		case MaturityExperimental:
			count.experimental++
		case MaturityInformational:
			count.informational++
		}
		byCategory[entry.Category] = count
	}
	categories := make([]string, 0, len(byCategory))
	for category := range byCategory {
		categories = append(categories, category)
	}
	sort.Strings(categories)

	var output strings.Builder
	output.WriteString("This table is generated from the command catalog. `stable` means the implementation is supported; `experimental` means it may be incomplete or change; `informational` means it primarily provides guidance or generated examples.\n\n")
	output.WriteString("| Category | Stable | Experimental | Informational | Total |\n")
	output.WriteString("|---|---:|---:|---:|---:|\n")
	for _, category := range categories {
		count := byCategory[category]
		fmt.Fprintf(&output, "| %s | %d | %d | %d | %d |\n", escapeTableCell(category), count.stable, count.experimental, count.informational, count.stable+count.experimental+count.informational)
	}
	return strings.TrimSuffix(output.String(), "\n"), nil
}

// RenderRoadmapStatus renders the detailed, generated ROADMAP status section.
func RenderRoadmapStatus(items []Entry) (string, error) {
	if err := Validate(items); err != nil {
		return "", err
	}
	items = append([]Entry(nil), items...)
	sort.Slice(items, func(i, j int) bool { return items[i].Path < items[j].Path })

	var output strings.Builder
	output.WriteString("## Command maturity catalog\n\n")
	output.WriteString("Ce tableau est généré depuis les métadonnées validées du binaire. Une commande `experimental` peut être incomplète; une commande `informational` fournit surtout des conseils ou exemples. `TUI: yes` est réservé aux parcours explicitement sûrs de l’interface guidée.\n\n")
	output.WriteString("| Command | Summary | Category | Maturity | Safety | TUI |\n")
	output.WriteString("|---|---|---|---|---|:---:|\n")
	for _, entry := range items {
		tui := "no"
		if entry.TUIAllowed {
			tui = "yes"
		}
		fmt.Fprintf(&output, "| `%s` | %s | %s | `%s` | `%s` | %s |\n",
			escapeTableCell(entry.Path), escapeTableCell(entry.Summary), escapeTableCell(entry.Category), entry.Maturity, entry.Safety, tui)
	}
	return strings.TrimSuffix(output.String(), "\n"), nil
}

// ReplaceGeneratedBlock replaces exactly one delimited generated block while
// preserving all author-maintained content byte-for-byte.
func ReplaceGeneratedBlock(document, generated string) (string, error) {
	if strings.Count(document, BeginMarker) != 1 || strings.Count(document, EndMarker) != 1 {
		return "", fmt.Errorf("document must contain exactly one %q and one %q marker", BeginMarker, EndMarker)
	}
	begin := strings.Index(document, BeginMarker)
	end := strings.Index(document, EndMarker)
	if begin > end {
		return "", fmt.Errorf("generated command catalog markers are reversed")
	}
	contentStart := begin + len(BeginMarker)
	newline := "\n"
	if strings.Contains(document, "\r\n") {
		newline = "\r\n"
	}
	generated = strings.ReplaceAll(strings.TrimSpace(generated), "\n", newline)
	return document[:contentStart] + newline + generated + newline + document[end:], nil
}

func escapeTableCell(value string) string {
	return strings.ReplaceAll(strings.ReplaceAll(value, "|", "\\|"), "\n", " ")
}
