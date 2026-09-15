package recon

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"
)

// ServiceResult holds the result of service reconnaissance
type ServiceResult struct {
	Host         string
	Port         int
	Protocol     string
	Banner       string
	Service      string
	Version      string
	TLS          bool
	TLSVersion   string
	Error        error
	ResponseTime time.Duration
}

// ReconOptions holds options for reconnaissance
type ReconOptions struct {
	Host    string
	Ports   []int
	Timeout int
	TLS     bool
}

// CommonPorts defines well-known ports with their typical services
var CommonPorts = map[int]string{
	21:    "ftp",
	22:    "ssh",
	23:    "telnet",
	25:    "smtp",
	53:    "dns",
	80:    "http",
	110:   "pop3",
	111:   "rpc",
	135:   "msrpc",
	139:   "netbios",
	143:   "imap",
	443:   "https",
	445:   "smb",
	465:   "smtps",
	587:   "submission",
	993:   "imaps",
	995:   "pop3s",
	1433:  "mssql",
	1521:  "oracle",
	3306:  "mysql",
	3389:  "rdp",
	5432:  "postgres",
	5900:  "vnc",
	6379:  "redis",
	8080:  "http-proxy",
	8443:  "https-alt",
	27017: "mongodb",
}

// ServiceSignatures maps patterns to service/version info
var ServiceSignatures = []struct {
	Pattern *regexp.Regexp
	Service string
	Extract func(string) string
}{
	// SSH
	{
		Pattern: regexp.MustCompile(`^SSH-(\d+\.\d+)-(.+)`),
		Service: "ssh",
		Extract: func(s string) string {
			re := regexp.MustCompile(`SSH-[\d.]+-(\S+)`)
			if m := re.FindStringSubmatch(s); len(m) > 1 {
				return m[1]
			}
			return ""
		},
	},
	// FTP
	{
		Pattern: regexp.MustCompile(`^220.*FTP|^220.*ftp|^220-`),
		Service: "ftp",
		Extract: func(s string) string {
			re := regexp.MustCompile(`220[- ](.+)`)
			if m := re.FindStringSubmatch(s); len(m) > 1 {
				return strings.TrimSpace(m[1])
			}
			return ""
		},
	},
	// SMTP
	{
		Pattern: regexp.MustCompile(`^220.*SMTP|^220.*ESMTP|^220.*mail`),
		Service: "smtp",
		Extract: func(s string) string {
			re := regexp.MustCompile(`220[- ](.+)`)
			if m := re.FindStringSubmatch(s); len(m) > 1 {
				return strings.TrimSpace(m[1])
			}
			return ""
		},
	},
	// HTTP
	{
		Pattern: regexp.MustCompile(`^HTTP/\d\.\d`),
		Service: "http",
		Extract: func(s string) string {
			lines := strings.Split(s, "\n")
			for _, line := range lines {
				if strings.HasPrefix(strings.ToLower(line), "server:") {
					return strings.TrimSpace(strings.TrimPrefix(line, "Server:"))
				}
			}
			return ""
		},
	},
	// MySQL
	{
		Pattern: regexp.MustCompile(`mysql|MariaDB`),
		Service: "mysql",
		Extract: func(s string) string {
			re := regexp.MustCompile(`(\d+\.\d+\.\d+[-\w]*)`)
			if m := re.FindStringSubmatch(s); len(m) > 1 {
				return m[1]
			}
			return ""
		},
	},
	// Redis
	{
		Pattern: regexp.MustCompile(`-ERR|^\+PONG|\$\d+\r\nredis`),
		Service: "redis",
		Extract: func(s string) string { return "" },
	},
	// MongoDB
	{
		Pattern: regexp.MustCompile(`MongoDB|ismaster`),
		Service: "mongodb",
		Extract: func(s string) string { return "" },
	},
	// PostgreSQL
	{
		Pattern: regexp.MustCompile(`PostgreSQL|FATAL:`),
		Service: "postgres",
		Extract: func(s string) string { return "" },
	},
	// POP3
	{
		Pattern: regexp.MustCompile(`^\+OK.*POP3|^\+OK.*pop`),
		Service: "pop3",
		Extract: func(s string) string {
			re := regexp.MustCompile(`\+OK\s+(.+)`)
			if m := re.FindStringSubmatch(s); len(m) > 1 {
				return strings.TrimSpace(m[1])
			}
			return ""
		},
	},
	// IMAP
	{
		Pattern: regexp.MustCompile(`^\* OK.*IMAP|^\* OK.*imap`),
		Service: "imap",
		Extract: func(s string) string {
			re := regexp.MustCompile(`\* OK\s+(.+)`)
			if m := re.FindStringSubmatch(s); len(m) > 1 {
				return strings.TrimSpace(m[1])
			}
			return ""
		},
	},
	// Telnet
	{
		Pattern: regexp.MustCompile(`login:|Login:|Username:|PASSWORD`),
		Service: "telnet",
		Extract: func(s string) string { return "" },
	},
	// RDP
	{
		Pattern: regexp.MustCompile(`^\x03\x00`),
		Service: "rdp",
		Extract: func(s string) string { return "Microsoft Terminal Services" },
	},
}

// BannerGrab performs banner grabbing on a single target
func BannerGrab(host string, port int, timeout int, useTLS bool) ServiceResult {
	result := ServiceResult{
		Host:     host,
		Port:     port,
		Protocol: "tcp",
	}

	address := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	start := time.Now()

	var conn net.Conn
	var err error

	// Determine if we should use TLS
	if useTLS || shouldUseTLS(port) {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS10,
		}

		conn, err = tls.DialWithDialer(
			&net.Dialer{Timeout: time.Duration(timeout) * time.Second},
			"tcp",
			address,
			tlsConfig,
		)

		if err == nil {
			result.TLS = true
			if tlsConn, ok := conn.(*tls.Conn); ok {
				state := tlsConn.ConnectionState()
				result.TLSVersion = getTLSVersionName(state.Version)
			}
		}
	}

	// If TLS failed or wasn't attempted, try plain connection
	if conn == nil {
		conn, err = net.DialTimeout("tcp", address, time.Duration(timeout)*time.Second)
	}

	if err != nil {
		result.Error = err
		return result
	}
	defer conn.Close()

	result.ResponseTime = time.Since(start)

	// Set read deadline
	_ = conn.SetDeadline(time.Now().Add(time.Duration(timeout) * time.Second))

	// Try to get banner based on port type
	banner := grabBanner(conn, port)
	result.Banner = banner

	// Identify service
	service, version := identifyService(banner, port)
	result.Service = service
	result.Version = version

	return result
}

// grabBanner reads banner from connection, sending probe if needed
func grabBanner(conn net.Conn, port int) string {
	// Some services require us to send data first
	probe := getProbe(port)
	if probe != "" {
		_, _ = conn.Write([]byte(probe))
	}

	// Read response
	buf := make([]byte, 4096)
	var response strings.Builder

	// Read with timeout
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))

	for {
		n, err := conn.Read(buf)
		if n > 0 {
			response.Write(buf[:n])
		}
		if err != nil || n == 0 {
			break
		}
		if response.Len() > 4096 {
			break
		}
	}

	return strings.TrimSpace(response.String())
}

// getProbe returns the appropriate probe for a port
func getProbe(port int) string {
	switch port {
	case 80, 8080, 8000, 8888:
		return "HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n"
	case 443, 8443:
		return "HEAD / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
	case 6379:
		return "PING\r\n"
	case 27017:
		// MongoDB ismaster query (simplified)
		return ""
	default:
		return ""
	}
}

// shouldUseTLS determines if TLS should be used for a port
func shouldUseTLS(port int) bool {
	tlsPorts := map[int]bool{
		443:  true,
		465:  true,
		636:  true,
		993:  true,
		995:  true,
		8443: true,
	}
	return tlsPorts[port]
}

// getTLSVersionName returns human-readable TLS version
func getTLSVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("0x%04x", version)
	}
}

// identifyService identifies the service and version from banner
func identifyService(banner string, port int) (service string, version string) {
	// First try pattern matching
	for _, sig := range ServiceSignatures {
		if sig.Pattern.MatchString(banner) {
			service = sig.Service
			version = sig.Extract(banner)
			return
		}
	}

	// Fall back to port-based identification
	if portService, ok := CommonPorts[port]; ok {
		service = portService
	} else {
		service = "unknown"
	}

	return service, version
}

// ReconMultiple performs reconnaissance on multiple ports
func ReconMultiple(opts ReconOptions) []ServiceResult {
	var results []ServiceResult
	var wg sync.WaitGroup
	var mu sync.Mutex

	// Limit concurrent connections
	semaphore := make(chan struct{}, 10)

	for _, port := range opts.Ports {
		wg.Add(1)
		semaphore <- struct{}{}

		go func(p int) {
			defer wg.Done()
			defer func() { <-semaphore }()

			result := BannerGrab(opts.Host, p, opts.Timeout, opts.TLS)

			mu.Lock()
			results = append(results, result)
			mu.Unlock()
		}(port)
	}

	wg.Wait()

	return results
}

// DisplayResult displays a single recon result
func DisplayResult(result ServiceResult) {
	fmt.Fprintf(stdoutW, "\n[RECON] %s:%d\n", result.Host, result.Port)
	fmt.Fprintln(stdoutW, strings.Repeat("-", 50))

	if result.Error != nil {
		fmt.Fprintf(stdoutW, "  Status:  CLOSED/FILTERED\n")
		fmt.Fprintf(stdoutW, "  Error:   %v\n", result.Error)
		return
	}

	fmt.Fprintf(stdoutW, "  Status:  OPEN\n")
	fmt.Fprintf(stdoutW, "  Service: %s\n", result.Service)

	if result.Version != "" {
		fmt.Fprintf(stdoutW, "  Version: %s\n", result.Version)
	}

	if result.TLS {
		fmt.Fprintf(stdoutW, "  TLS:     Yes (%s)\n", result.TLSVersion)
	}

	fmt.Fprintf(stdoutW, "  Latency: %v\n", result.ResponseTime.Round(time.Millisecond))

	if result.Banner != "" {
		fmt.Fprintln(stdoutW, "\n  Banner:")
		// Format banner nicely
		lines := strings.Split(result.Banner, "\n")
		for i, line := range lines {
			if i >= 10 {
				fmt.Fprintf(stdoutW, "    ... (%d more lines)\n", len(lines)-10)
				break
			}
			// Sanitize line for display
			line = sanitizeBanner(line)
			if len(line) > 80 {
				line = line[:77] + "..."
			}
			fmt.Fprintf(stdoutW, "    %s\n", line)
		}
	}

	fmt.Fprintln(stdoutW)
}

// DisplayResults displays multiple recon results
func DisplayResults(results []ServiceResult) {
	if len(results) == 0 {
		fmt.Fprintln(stdoutW, "No results")
		return
	}

	// Count open ports
	openPorts := 0
	for _, r := range results {
		if r.Error == nil {
			openPorts++
		}
	}

	fmt.Fprintf(stdoutW, "\n[RECON SUMMARY] %s\n", results[0].Host)
	fmt.Fprintln(stdoutW, strings.Repeat("=", 60))
	fmt.Fprintf(stdoutW, "Ports scanned: %d | Open: %d | Closed/Filtered: %d\n",
		len(results), openPorts, len(results)-openPorts)
	fmt.Fprintln(stdoutW, strings.Repeat("=", 60))

	// Display open ports first
	for _, result := range results {
		if result.Error == nil {
			displayCompactResult(result)
		}
	}

	// Then closed/filtered
	closedPorts := []int{}
	for _, result := range results {
		if result.Error != nil {
			closedPorts = append(closedPorts, result.Port)
		}
	}

	if len(closedPorts) > 0 {
		fmt.Fprintf(stdoutW, "\nClosed/Filtered ports: ")
		for i, port := range closedPorts {
			if i > 0 {
				fmt.Fprint(stdoutW, ", ")
			}
			fmt.Fprint(stdoutW, port)
		}
		fmt.Fprintln(stdoutW)
	}

	fmt.Fprintln(stdoutW)
}

// displayCompactResult shows a single line result
func displayCompactResult(result ServiceResult) {
	tlsInfo := ""
	if result.TLS {
		tlsInfo = fmt.Sprintf(" [%s]", result.TLSVersion)
	}

	version := ""
	if result.Version != "" {
		version = " (" + result.Version + ")"
	}

	fmt.Fprintf(stdoutW, "  %-6d %-12s%s%s\n", result.Port, result.Service, version, tlsInfo)
}

// sanitizeBanner removes non-printable characters from banner
func sanitizeBanner(s string) string {
	var result strings.Builder
	for _, r := range s {
		if r >= 32 && r < 127 {
			result.WriteRune(r)
		} else if r == '\t' {
			result.WriteString("    ")
		}
	}
	return result.String()
}

// ParsePorts parses port specification string
func ParsePorts(portSpec string) ([]int, error) {
	var ports []int
	seen := make(map[int]bool)

	parts := strings.Split(portSpec, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)

		if strings.Contains(part, "-") {
			// Range
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) != 2 {
				return nil, fmt.Errorf("invalid port range: %s", part)
			}

			var start, end int
			_, err := fmt.Sscanf(rangeParts[0], "%d", &start)
			if err != nil {
				return nil, fmt.Errorf("invalid port: %s", rangeParts[0])
			}
			_, err = fmt.Sscanf(rangeParts[1], "%d", &end)
			if err != nil {
				return nil, fmt.Errorf("invalid port: %s", rangeParts[1])
			}

			if start > end {
				start, end = end, start
			}

			for p := start; p <= end; p++ {
				if !seen[p] && p > 0 && p <= 65535 {
					ports = append(ports, p)
					seen[p] = true
				}
			}
		} else {
			// Single port
			var p int
			_, err := fmt.Sscanf(part, "%d", &p)
			if err != nil {
				return nil, fmt.Errorf("invalid port: %s", part)
			}
			if !seen[p] && p > 0 && p <= 65535 {
				ports = append(ports, p)
				seen[p] = true
			}
		}
	}

	return ports, nil
}

// GetCommonPorts returns a list of commonly used ports
func GetCommonPorts() []int {
	return []int{21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017}
}

// ScannerReadLine reads a line from a connection using bufio
func ScannerReadLine(conn net.Conn) (string, error) {
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	return strings.TrimSpace(line), err
}
