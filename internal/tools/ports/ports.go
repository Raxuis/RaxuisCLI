package ports

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Options struct {
	Host      string
	PortRange string
	Timeout   int
	ScanType  string
}

type ScanResult struct {
	Port    int
	Status  string
	Service string
}

type PortScanner struct {
	host     string
	timeout  time.Duration
	scanType string
	results  []ScanResult
	mutex    sync.Mutex
}

func Scan(opts Options) {
	scanner := &PortScanner{
		host:     opts.Host,
		timeout:  time.Duration(opts.Timeout) * time.Second,
		scanType: strings.ToLower(opts.ScanType),
		results:  make([]ScanResult, 0),
	}

	portRange := expandPresetRanges(opts.PortRange)

	fmt.Fprintf(stdoutW, "🔍 Scanning %s ports on %s...\n", strings.ToUpper(scanner.scanType), scanner.host)
	fmt.Fprintf(stdoutW, "📊 Port range: %s\n", portRange)
	fmt.Fprintf(stdoutW, "⏱️  Timeout: %d seconds\n", opts.Timeout)
	fmt.Fprintln(stdoutW, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	ports, err := parsePortRange(portRange)
	if err != nil {
		fmt.Fprintf(stdoutW, "❌ Error parsing port range: %v\n", err)
		return
	}

	startTime := time.Now()
	scanner.scanPorts(ports)
	duration := time.Since(startTime)

	scanner.displayResults(duration, len(ports))
}

func expandPresetRanges(portRange string) string {
	presets := map[string]string{
		"common":   "21,22,23,25,53,80,110,135,139,143,443,993,995,1433,3306,3389,5432,8080",
		"web":      "80,443,8000,8080,8443,8888,9000,9090",
		"database": "1433,3306,5432,6379,27017",
		"dev":      "3000,3001,4000,5000,8000,8080,8888,9000",
		"system":   "21,22,23,25,53,80,135,139,443,445",
		"all":      "1-65535",
		"extended": "1-10000",
	}

	if expandedRange, exists := presets[strings.ToLower(portRange)]; exists {
		return expandedRange
	}
	return portRange
}
func parsePortRange(portRange string) ([]int, error) {
	var ports []int

	if strings.Contains(portRange, ",") {
		// Gestion des ports multiples séparés par des virgules (ex: "22,80,443")
		portStrs := strings.Split(portRange, ",")
		for _, portStr := range portStrs {
			portStr = strings.TrimSpace(portStr)
			if strings.Contains(portStr, "-") {
				rangePorts, err := parseRange(portStr)
				if err != nil {
					return nil, err
				}
				ports = append(ports, rangePorts...)
			} else {
				port, err := strconv.Atoi(portStr)
				if err != nil {
					return nil, fmt.Errorf("invalid port number: %s", portStr)
				}
				if !isValidPort(port) {
					return nil, fmt.Errorf("port %d is out of valid range (1-65535)", port)
				}
				ports = append(ports, port)
			}
		}
	} else if strings.Contains(portRange, "-") {
		// Gestion des plages (ex: "1-1024")
		return parseRange(portRange)
	} else {
		// Port unique
		port, err := strconv.Atoi(portRange)
		if err != nil {
			return nil, fmt.Errorf("invalid port number: %s", portRange)
		}
		if !isValidPort(port) {
			return nil, fmt.Errorf("port %d is out of valid range (1-65535)", port)
		}
		ports = append(ports, port)
	}

	return ports, nil
}

func parseRange(portRange string) ([]int, error) {
	parts := strings.Split(portRange, "-")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid port range format: %s", portRange)
	}

	startPort, err := strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil {
		return nil, fmt.Errorf("invalid start port: %s", parts[0])
	}

	endPort, err := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err != nil {
		return nil, fmt.Errorf("invalid end port: %s", parts[1])
	}

	if startPort > endPort {
		return nil, fmt.Errorf("start port (%d) cannot be greater than end port (%d)", startPort, endPort)
	}

	if !isValidPort(startPort) || !isValidPort(endPort) {
		return nil, fmt.Errorf("ports must be in range 1-65535")
	}

	var ports []int
	for port := startPort; port <= endPort; port++ {
		ports = append(ports, port)
	}

	return ports, nil
}

func isValidPort(port int) bool {
	return port >= 1 && port <= 65535
}

func (ps *PortScanner) scanPorts(ports []int) {
	// Limitation le nombre de goroutines pour éviter de surcharger le système
	const maxGoroutines = 100
	semaphore := make(chan struct{}, maxGoroutines)
	var wg sync.WaitGroup

	for _, port := range ports {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			result := ps.scanPort(p)
			if result.Status == "open" {
				ps.mutex.Lock()
				ps.results = append(ps.results, result)
				ps.mutex.Unlock()

				// Affichage en temps réel des ports ouverts
				fmt.Fprintf(stdoutW, "✅ Port %d/%s: %s %s\n", p, ps.scanType, result.Status, result.Service)
			}
		}(port)
	}

	wg.Wait()
}

func (ps *PortScanner) scanPort(port int) ScanResult {
	target := fmt.Sprintf("%s:%d", ps.host, port)
	result := ScanResult{
		Port:    port,
		Status:  "closed",
		Service: getServiceName(port),
	}

	switch ps.scanType {
	case "tcp":
		result.Status = ps.scanTCP(target)
	case "udp":
		result.Status = ps.scanUDP(target)
	default:
		result.Status = ps.scanTCP(target)
	}

	return result
}

func (ps *PortScanner) scanTCP(target string) string {
	conn, err := net.DialTimeout("tcp", target, ps.timeout)
	if err != nil {
		return "closed"
	}
	defer func(conn net.Conn) {
		err := conn.Close()
		if err != nil {
			fmt.Fprintf(stdoutW, "Error closing connection: %v\n", err)
		}
	}(conn)
	return "open"
}

func (ps *PortScanner) scanUDP(target string) string {
	conn, err := net.DialTimeout("udp", target, ps.timeout)
	if err != nil {
		return "closed"
	}
	defer func(conn net.Conn) {
		err := conn.Close()
		if err != nil {
			fmt.Fprintf(stdoutW, "Error closing connection: %v\n", err)
		}
	}(conn)

	_, err = conn.Write([]byte{})
	if err != nil {
		return "closed"
	}

	err = conn.SetReadDeadline(time.Now().Add(ps.timeout))
	if err != nil {
		return "closed"
	}
	buffer := make([]byte, 1024)
	_, err = conn.Read(buffer)

	// Si on reçoit une réponse ou pas d'erreur, le port pourrait être ouvert
	if err != nil {
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			return "open|filtered"
		}
		return "closed"
	}

	return "open"
}

func getServiceName(port int) string {
	commonServices := map[int]string{
		21:    "(FTP)",
		22:    "(SSH)",
		23:    "(Telnet)",
		25:    "(SMTP)",
		53:    "(DNS)",
		80:    "(HTTP)",
		110:   "(POP3)",
		135:   "(RPC)",
		139:   "(NetBIOS)",
		143:   "(IMAP)",
		443:   "(HTTPS)",
		445:   "(SMB)",
		993:   "(IMAPS)",
		995:   "(POP3S)",
		1433:  "(MSSQL)",
		3000:  "(Node.js/Next.js/React Dev)",
		3001:  "(Node.js Dev)",
		3306:  "(MySQL)",
		3389:  "(RDP)",
		4000:  "(Dev Server)",
		4200:  "(Default Angular Dev Server)",
		5000:  "(Dev Server)",
		5432:  "(PostgreSQL)",
		6379:  "(Redis)",
		8000:  "(HTTP-Alt)",
		8080:  "(HTTP-Alt)",
		8443:  "(HTTPS-Alt)",
		8888:  "(HTTP-Alt)",
		9000:  "(Dev Server)",
		9200:  "(Elasticsearch)",
		27017: "(MongoDB)",
	}

	if service, exists := commonServices[port]; exists {
		return service
	}
	return ""
}

func (ps *PortScanner) displayResults(duration time.Duration, totalPorts int) {
	fmt.Fprintln(stdoutW, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Fprintf(stdoutW, "📈 Scan completed in %v\n", duration.Round(time.Millisecond))
	fmt.Fprintf(stdoutW, "🎯 Scanned %d ports\n", totalPorts)
	fmt.Fprintf(stdoutW, "🔓 Found %d open ports\n", len(ps.results))

	if len(ps.results) == 0 {
		fmt.Fprintln(stdoutW, "🚫 No open ports found")
		return
	}

	fmt.Fprintln(stdoutW, "\n📋 Summary of open ports:")
	fmt.Fprintln(stdoutW, "━━━━━━━━━━━━━━━━━━━━━━━━")
	for _, result := range ps.results {
		fmt.Fprintf(stdoutW, "Port %-6d: %s %s\n", result.Port, result.Status, result.Service)
	}
}
