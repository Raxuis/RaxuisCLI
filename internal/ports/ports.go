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

	fmt.Printf("🔍 Scanning %s ports on %s...\n", strings.ToUpper(scanner.scanType), scanner.host)
	fmt.Printf("📊 Port range: %s\n", opts.PortRange)
	fmt.Printf("⏱️  Timeout: %d seconds\n", opts.Timeout)
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	ports, err := parsePortRange(opts.PortRange)
	if err != nil {
		fmt.Printf("❌ Error parsing port range: %v\n", err)
		return
	}

	startTime := time.Now()
	scanner.scanPorts(ports)
	duration := time.Since(startTime)

	scanner.displayResults(duration, len(ports))
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
				fmt.Printf("✅ Port %d/%s: %s %s\n", p, ps.scanType, result.Status, result.Service)
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
			fmt.Printf("Error closing connection: %v\n", err)
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
			fmt.Printf("Error closing connection: %v\n", err)
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
		21:   "(FTP)",
		22:   "(SSH)",
		23:   "(Telnet)",
		25:   "(SMTP)",
		53:   "(DNS)",
		80:   "(HTTP)",
		110:  "(POP3)",
		143:  "(IMAP)",
		443:  "(HTTPS)",
		993:  "(IMAPS)",
		995:  "(POP3S)",
		1433: "(MSSQL)",
		3306: "(MySQL)",
		3389: "(RDP)",
		5432: "(PostgreSQL)",
		6379: "(Redis)",
		8080: "(HTTP-Alt)",
		9200: "(Elasticsearch)",
	}

	if service, exists := commonServices[port]; exists {
		return service
	}
	return ""
}

func (ps *PortScanner) displayResults(duration time.Duration, totalPorts int) {
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Printf("📈 Scan completed in %v\n", duration.Round(time.Millisecond))
	fmt.Printf("🎯 Scanned %d ports\n", totalPorts)
	fmt.Printf("🔓 Found %d open ports\n", len(ps.results))

	if len(ps.results) == 0 {
		fmt.Println("🚫 No open ports found")
		return
	}

	fmt.Println("\n📋 Summary of open ports:")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━")
	for _, result := range ps.results {
		fmt.Printf("Port %-6d: %s %s\n", result.Port, result.Status, result.Service)
	}
}
