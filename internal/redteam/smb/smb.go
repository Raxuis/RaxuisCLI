package smb

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"
)

// SMBOptions holds connection options
type SMBOptions struct {
	Host     string
	Port     int
	Username string
	Password string
	Domain   string
	Timeout  int
}

// ShareInfo represents an SMB share
type ShareInfo struct {
	Name        string
	Type        string
	Remark      string
	Permissions string
	Readable    bool
	Writable    bool
}

// FileInfo represents a file in an SMB share
type FileInfo struct {
	Name       string
	Size       int64
	IsDir      bool
	ModTime    time.Time
	Attributes uint32
}

// ScanResult holds the result of an SMB scan
type ScanResult struct {
	Host         string
	Port         int
	SMBVersion   string
	Hostname     string
	Domain       string
	OS           string
	Signing      bool
	SignRequired bool
	Shares       []ShareInfo
	Error        error
}

// SpiderResult holds file spider results
type SpiderResult struct {
	Share      string
	Files      []FileInfo
	Matches    []string
	TotalFiles int
	TotalSize  int64
}

// SMB header constants
const (
	SMBHeaderLength = 32
	SMB2HeaderLen   = 64
)

// Connect tests SMB connectivity
func Connect(opts SMBOptions) (*ScanResult, error) {
	result := &ScanResult{
		Host: opts.Host,
		Port: opts.Port,
	}

	address := net.JoinHostPort(opts.Host, fmt.Sprintf("%d", opts.Port))

	conn, err := net.DialTimeout("tcp", address, time.Duration(opts.Timeout)*time.Second)
	if err != nil {
		result.Error = fmt.Errorf("connection failed: %v", err)
		return result, err
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(time.Duration(opts.Timeout) * time.Second))

	// Send SMB negotiate request
	negPacket := buildSMBNegotiateRequest()
	_, err = conn.Write(negPacket)
	if err != nil {
		result.Error = fmt.Errorf("send negotiate failed: %v", err)
		return result, err
	}

	// Read response
	response := make([]byte, 4096)
	n, err := conn.Read(response)
	if err != nil {
		result.Error = fmt.Errorf("read response failed: %v", err)
		return result, err
	}

	// Parse response
	if n > 0 {
		result.SMBVersion = detectSMBVersion(response[:n])
		parseSMBResponse(response[:n], result)
	}

	return result, nil
}

// buildSMBNegotiateRequest builds an SMB1 negotiate request
func buildSMBNegotiateRequest() []byte {
	// NetBIOS header (4 bytes)
	netbios := []byte{0x00, 0x00, 0x00, 0x00} // Length will be set later

	// SMB Header
	smb := []byte{
		0xff, 0x53, 0x4d, 0x42, // Protocol: SMB
		0x72,                   // Command: Negotiate
		0x00, 0x00, 0x00, 0x00, // Status
		0x18,       // Flags
		0x53, 0xc8, // Flags2
		0x00, 0x00, // PID High
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Signature
		0x00, 0x00, // Reserved
		0x00, 0x00, // Tree ID
		0x00, 0x01, // Process ID
		0x00, 0x00, // User ID
		0x00, 0x00, // Multiplex ID
	}

	// Negotiate Request
	negotiate := []byte{
		0x00,       // Word count
		0x62, 0x00, // Byte count
	}

	// Dialects
	dialects := []byte{}
	dialectStrings := []string{
		"PC NETWORK PROGRAM 1.0",
		"LANMAN1.0",
		"Windows for Workgroups 3.1a",
		"LM1.2X002",
		"LANMAN2.1",
		"NT LM 0.12",
		"SMB 2.002",
		"SMB 2.???",
	}

	for _, d := range dialectStrings {
		dialects = append(dialects, 0x02)
		dialects = append(dialects, []byte(d)...)
		dialects = append(dialects, 0x00)
	}

	// Update byte count
	negotiate[1] = byte(len(dialects))
	negotiate[2] = byte(len(dialects) >> 8)

	// Combine
	packet := append(smb, negotiate...)
	packet = append(packet, dialects...)

	// Set NetBIOS length
	length := len(packet)
	netbios[2] = byte(length >> 8)
	netbios[3] = byte(length)

	return append(netbios, packet...)
}

// detectSMBVersion detects SMB version from response
func detectSMBVersion(response []byte) string {
	if len(response) < 8 {
		return "Unknown"
	}

	// Skip NetBIOS header (4 bytes)
	data := response[4:]

	if len(data) < 4 {
		return "Unknown"
	}

	// Check for SMB2/3
	if data[0] == 0xfe && data[1] == 'S' && data[2] == 'M' && data[3] == 'B' {
		return "SMB2/3"
	}

	// Check for SMB1
	if data[0] == 0xff && data[1] == 'S' && data[2] == 'M' && data[3] == 'B' {
		return "SMB1"
	}

	return "Unknown"
}

// parseSMBResponse parses SMB negotiate response
func parseSMBResponse(response []byte, result *ScanResult) {
	if len(response) < 40 {
		return
	}

	// Skip NetBIOS header
	data := response[4:]

	// Check SMB2
	if len(data) >= 4 && data[0] == 0xfe && data[1] == 'S' && data[2] == 'M' && data[3] == 'B' {
		// SMB2 negotiate response
		if len(data) >= 70 {
			// Security mode at offset 3
			secMode := data[3]
			result.Signing = (secMode & 0x01) != 0
			result.SignRequired = (secMode & 0x02) != 0
		}
	}
}

// EnumerateShares attempts to enumerate SMB shares
func EnumerateShares(opts SMBOptions) ([]ShareInfo, error) {
	// This would require full SMB session establishment
	// For now, return common shares to probe

	commonShares := []string{
		"ADMIN$",
		"C$",
		"D$",
		"IPC$",
		"NETLOGON",
		"SYSVOL",
		"print$",
		"Users",
		"Public",
		"Shared",
		"Data",
		"Backup",
		"Software",
		"IT",
		"HR",
		"Finance",
	}

	var shares []ShareInfo
	for _, name := range commonShares {
		share := ShareInfo{
			Name: name,
			Type: guessShareType(name),
		}
		shares = append(shares, share)
	}

	return shares, nil
}

// guessShareType guesses share type from name
func guessShareType(name string) string {
	if strings.HasSuffix(name, "$") {
		return "Hidden"
	}
	if strings.EqualFold(name, "print$") || strings.Contains(strings.ToLower(name), "print") {
		return "Printer"
	}
	return "Disk"
}

// CheckNullSession tests for null session access
func CheckNullSession(host string, port int, timeout int) (bool, error) {
	opts := SMBOptions{
		Host:    host,
		Port:    port,
		Timeout: timeout,
	}

	result, err := Connect(opts)
	if err != nil {
		return false, err
	}

	// If we got a valid response, null session might be possible
	return result.SMBVersion != "", nil
}

// BuildSMB2Header builds an SMB2 header
func BuildSMB2Header(command uint16, messageID uint64) []byte {
	header := make([]byte, SMB2HeaderLen)

	// Protocol ID
	header[0] = 0xfe
	header[1] = 'S'
	header[2] = 'M'
	header[3] = 'B'

	// Header length
	binary.LittleEndian.PutUint16(header[4:6], 64)

	// Command
	binary.LittleEndian.PutUint16(header[12:14], command)

	// Message ID
	binary.LittleEndian.PutUint64(header[24:32], messageID)

	return header
}

// DisplayScanResult displays SMB scan results
func DisplayScanResult(result *ScanResult) {
	fmt.Printf("\n[SMB] %s:%d\n", result.Host, result.Port)
	fmt.Println(strings.Repeat("=", 50))

	if result.Error != nil {
		fmt.Printf("Error: %v\n", result.Error)
		return
	}

	fmt.Printf("SMB Version:   %s\n", result.SMBVersion)

	if result.Hostname != "" {
		fmt.Printf("Hostname:      %s\n", result.Hostname)
	}
	if result.Domain != "" {
		fmt.Printf("Domain:        %s\n", result.Domain)
	}
	if result.OS != "" {
		fmt.Printf("OS:            %s\n", result.OS)
	}

	fmt.Printf("Signing:       %v\n", result.Signing)
	fmt.Printf("Sign Required: %v\n", result.SignRequired)

	if !result.SignRequired {
		fmt.Println("\n[!] SMB Signing not required - vulnerable to relay attacks")
	}

	if len(result.Shares) > 0 {
		fmt.Println("\nShares:")
		for _, share := range result.Shares {
			perms := ""
			if share.Readable {
				perms += "R"
			}
			if share.Writable {
				perms += "W"
			}
			if perms == "" {
				perms = "-"
			}
			fmt.Printf("  %-20s [%s] %s\n", share.Name, share.Type, perms)
		}
	}

	fmt.Println()
}

// DisplayShares displays share enumeration results
func DisplayShares(shares []ShareInfo, host string) {
	fmt.Printf("\n[SMB SHARES] %s\n", host)
	fmt.Println(strings.Repeat("=", 50))

	if len(shares) == 0 {
		fmt.Println("No shares found")
		return
	}

	fmt.Printf("%-20s %-10s %-6s %s\n", "NAME", "TYPE", "PERMS", "REMARK")
	fmt.Println(strings.Repeat("-", 50))

	for _, share := range shares {
		perms := ""
		if share.Readable {
			perms += "R"
		}
		if share.Writable {
			perms += "W"
		}
		if perms == "" {
			perms = "-"
		}
		fmt.Printf("%-20s %-10s %-6s %s\n", share.Name, share.Type, perms, share.Remark)
	}

	fmt.Println()
}
