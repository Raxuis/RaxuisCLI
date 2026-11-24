package ports

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Raxuis/RaxuisCLI/internal/shared/netutil"
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
	host        string
	timeout     time.Duration
	scanType    string
	results     []ScanResult
	ctx         context.Context
	concurrency int
	mutex       sync.Mutex
}

func Scan(opts Options) {
	start := time.Now()
	fmt.Fprintf(stdoutW, "🔍 Scanning %s ports on %s...\n", strings.ToUpper(opts.ScanType), opts.Host)
	fmt.Fprintf(stdoutW, "📊 Port range: %s\n", expandPresetRanges(opts.PortRange))
	fmt.Fprintf(stdoutW, "⏱️  Timeout: %v\n", netutil.Timeout(opts.Timeout))
	results, err := ScanResults(opts)
	if err != nil {
		fmt.Fprintf(stdoutW, "Error scanning ports: %v\n", err)
		return
	}
	scanner := &PortScanner{results: results}
	parsed, _ := parsePortRange(expandPresetRanges(opts.PortRange))
	scanner.displayResults(time.Since(start), len(parsed))
}

// ScanResults runs the scan without printing and returns open or ambiguous UDP results.
func ScanResults(opts Options) ([]ScanResult, error) {
	return ScanResultsContext(context.Background(), opts)
}

// ScanResultsContext runs a bounded, cancellable scan without printing.
func ScanResultsContext(ctx context.Context, opts Options) ([]ScanResult, error) {
	host, err := netutil.NormalizeHost(opts.Host)
	if err != nil {
		return nil, err
	}
	scanType := strings.ToLower(strings.TrimSpace(opts.ScanType))
	if scanType == "" {
		scanType = "tcp"
	}
	if scanType != "tcp" && scanType != "udp" {
		return nil, fmt.Errorf("unsupported scan type: %s", scanType)
	}
	ports, err := parsePortRange(expandPresetRanges(opts.PortRange))
	if err != nil {
		return nil, err
	}
	scanner := &PortScanner{host: host, timeout: netutil.Timeout(opts.Timeout), scanType: scanType, results: make([]ScanResult, 0), ctx: ctx}
	scanner.scanPorts(ports)
	return scanner.results, ctx.Err()
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

	if expandedRange, exists := presets[strings.ToLower(strings.TrimSpace(portRange))]; exists {
		return expandedRange
	}
	return portRange
}
func parsePortRange(portRange string) ([]int, error) {
	return netutil.ParsePorts(portRange)
}

func isValidPort(port int) bool { return netutil.ValidPort(port) }

func (ps *PortScanner) scanPorts(ports []int) {
	ctx := ps.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	netutil.ForEach(ctx, netutil.UniquePorts(ports), ps.concurrency, func(port int) {
		result := ps.scanPort(port)
		if result.Status == "open" || result.Status == "open|filtered" {
			ps.mutex.Lock()
			ps.results = append(ps.results, result)
			ps.mutex.Unlock()
		}
	})
	sort.Slice(ps.results, func(i, j int) bool { return ps.results[i].Port < ps.results[j].Port })
}

func (ps *PortScanner) scanPort(port int) ScanResult {
	target := net.JoinHostPort(ps.host, strconv.Itoa(port))
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
	conn, err := netutil.Dial(ps.context(), "tcp", target, ps.timeout)
	if err != nil {
		return "closed"
	}
	defer conn.Close()
	return "open"
}

func (ps *PortScanner) scanUDP(target string) string {
	conn, err := netutil.Dial(ps.context(), "udp", target, ps.timeout)
	if err != nil {
		return "closed"
	}
	defer conn.Close()

	stop := context.AfterFunc(ps.context(), func() { _ = conn.Close() })
	defer stop()
	timeout := ps.timeout
	if timeout <= 0 {
		timeout = netutil.Timeout(0)
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))
	_, err = conn.Write([]byte{0})
	if err != nil {
		return "closed"
	}

	err = conn.SetReadDeadline(time.Now().Add(timeout))
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

func (ps *PortScanner) context() context.Context {
	if ps.ctx == nil {
		return context.Background()
	}
	return ps.ctx
}
