// Package scan performs concurrent host and TCP service discovery across a
// range of targets, tagging interesting services with the raxuiscli command
// to run next. It is a red-team attack-surface mapper built on plain TCP
// connect scans (no raw sockets, no external tooling).
package scan

import (
	"bytes"
	"fmt"
	"math/rand"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Raxuis/RaxuisCLI/internal/network/recon"
)

const maxHosts = 65536

// DefaultDiscoveryPorts are probed to decide whether a host is alive.
var DefaultDiscoveryPorts = []int{445, 139, 135, 22, 80, 443, 3389}

// DefaultTopPorts is a curated, red-team-relevant default port set.
var DefaultTopPorts = []int{
	21, 22, 23, 25, 53, 80, 88, 110, 111, 135, 139, 143, 161, 389, 443, 445,
	464, 465, 587, 593, 636, 993, 995, 1433, 1521, 2049, 3268, 3269, 3306,
	3389, 5432, 5601, 5985, 5986, 6379, 8000, 8080, 8443, 8888, 9200, 9300,
	11211, 27017,
}

// Options controls a scan run.
type Options struct {
	Targets        []string // expanded host list (IPs / hostnames)
	Ports          []int
	DiscoveryPorts []int
	Concurrency    int
	Timeout        int // seconds, per TCP connect
	Jitter         time.Duration
	SkipDiscovery  bool // scan every target directly, skip liveness probe
	Banner         bool // grab banners for service/version detection
}

// OpenPort is a single open TCP port with red-team context.
type OpenPort struct {
	Port     int
	Service  string
	Version  string
	Banner   string
	TLS      bool
	Tag      string // "ad", "lateral", "db", "unauth", "web", "recon" or ""
	NextStep string // suggested follow-up (often a raxuiscli command)
}

// HostResult holds the open ports discovered on one host.
type HostResult struct {
	IP        string
	Hostname  string
	OpenPorts []OpenPort
}

// Result is the full outcome of a scan run.
type Result struct {
	Targets    int
	AliveHosts int
	Hosts      []HostResult
	Duration   time.Duration
}

// Run executes host discovery (unless skipped) then a TCP connect scan of the
// alive hosts, returning the annotated results.
func Run(opts Options) *Result {
	start := time.Now()
	if opts.Concurrency <= 0 {
		opts.Concurrency = 100
	}
	if len(opts.DiscoveryPorts) == 0 {
		opts.DiscoveryPorts = DefaultDiscoveryPorts
	}
	if len(opts.Ports) == 0 {
		opts.Ports = DefaultTopPorts
	}

	res := &Result{Targets: len(opts.Targets)}

	alive := opts.Targets
	if !opts.SkipDiscovery {
		alive = discoverHosts(opts)
	}
	sortIPs(alive)
	res.AliveHosts = len(alive)

	for _, ip := range alive {
		hr := HostResult{IP: ip}
		if names, err := net.LookupAddr(ip); err == nil && len(names) > 0 {
			hr.Hostname = strings.TrimSuffix(names[0], ".")
		}
		hr.OpenPorts = scanHost(ip, opts)
		res.Hosts = append(res.Hosts, hr)
	}

	res.Duration = time.Since(start)
	return res
}

func discoverHosts(opts Options) []string {
	sem := make(chan struct{}, opts.Concurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var alive []string

	for _, ip := range opts.Targets {
		wg.Add(1)
		sem <- struct{}{}
		go func(ip string) {
			defer wg.Done()
			defer func() { <-sem }()
			if hostAlive(ip, opts) {
				mu.Lock()
				alive = append(alive, ip)
				mu.Unlock()
			}
		}(ip)
	}
	wg.Wait()
	return alive
}

func hostAlive(ip string, opts Options) bool {
	for _, p := range opts.DiscoveryPorts {
		jitterSleep(opts.Jitter)
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, strconv.Itoa(p)), opts.discoveryTimeout())
		if err == nil {
			_ = conn.Close()
			return true
		}
	}
	return false
}

func scanHost(ip string, opts Options) []OpenPort {
	sem := make(chan struct{}, opts.Concurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var open []OpenPort

	for _, port := range opts.Ports {
		wg.Add(1)
		sem <- struct{}{}
		go func(port int) {
			defer wg.Done()
			defer func() { <-sem }()

			jitterSleep(opts.Jitter)
			conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, strconv.Itoa(port)), opts.connectTimeout())
			if err != nil {
				return
			}
			_ = conn.Close()

			op := OpenPort{Port: port}
			if opts.Banner {
				sr := recon.BannerGrab(ip, port, opts.Timeout, false)
				op.Service, op.Version, op.Banner, op.TLS = sr.Service, sr.Version, sr.Banner, sr.TLS
			}
			if op.Service == "" || op.Service == "unknown" {
				if s, ok := recon.CommonPorts[port]; ok {
					op.Service = s
				} else {
					op.Service = "unknown"
				}
			}
			op.Tag, op.NextStep = annotate(ip, port, op.Service)

			mu.Lock()
			open = append(open, op)
			mu.Unlock()
		}(port)
	}
	wg.Wait()

	sort.Slice(open, func(i, j int) bool { return open[i].Port < open[j].Port })
	return open
}

// annotate maps an open port to a red-team tag and a suggested next action.
func annotate(ip string, port int, _ string) (tag, next string) {
	switch port {
	case 88:
		return "ad", "→ raxuiscli kerberos asrep -d <domain>"
	case 389, 3268:
		return "ad", "→ raxuiscli ldap enum -H " + ip
	case 636, 3269:
		return "ad", "→ raxuiscli ldap enum -H " + ip + " (LDAPS)"
	case 445:
		return "ad", "→ raxuiscli smb null -H " + ip
	case 139:
		return "ad", "→ raxuiscli smb shares -H " + ip
	case 5985:
		return "lateral", "[WinRM] evil-winrm / lateral movement target"
	case 5986:
		return "lateral", "[WinRM over TLS] lateral movement target"
	case 3389:
		return "lateral", "[RDP] password-spray / stolen-cred target"
	case 1433:
		return "db", "[MSSQL] creds → xp_cmdshell later"
	case 3306:
		return "db", "[MySQL] creds target"
	case 5432:
		return "db", "[PostgreSQL] creds target"
	case 1521:
		return "db", "[Oracle TNS] creds target"
	case 6379:
		return "unauth", "[!] Redis — often unauthenticated, connect directly"
	case 27017:
		return "unauth", "[!] MongoDB — often unauthenticated"
	case 9200, 9300:
		return "unauth", "[!] Elasticsearch — REST API often exposed"
	case 11211:
		return "unauth", "[!] Memcached — no auth / amplification"
	case 2049:
		return "unauth", "[NFS] showmount -e " + ip
	case 21:
		return "recon", "[FTP] anonymous login? → raxuiscli recon " + ip + ":21"
	case 23:
		return "recon", "[Telnet] cleartext credentials"
	case 22:
		return "recon", "[SSH] key / credential target"
	case 25, 465, 587:
		return "recon", "[SMTP] user enumeration (VRFY / RCPT TO)"
	case 53:
		return "recon", "→ raxuiscli dns axfr <domain> --server " + ip
	case 161:
		return "recon", "[SNMP] community-string brute (UDP)"
	case 80, 8000, 8080, 8888:
		return "web", "→ raxuiscli http headers http://" + ip + ":" + strconv.Itoa(port)
	case 443, 8443:
		return "web", "→ raxuiscli tlsscan " + ip + ":" + strconv.Itoa(port)
	}
	return "", ""
}

// ParseTargets expands a comma-separated list of IPs, hostnames and IPv4 CIDRs
// into a de-duplicated target list.
func ParseTargets(spec string) ([]string, error) {
	var out []string
	seen := make(map[string]bool)

	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "/") {
			ips, err := expandCIDR(part)
			if err != nil {
				return nil, err
			}
			for _, ip := range ips {
				if !seen[ip] {
					seen[ip] = true
					out = append(out, ip)
				}
			}
			continue
		}
		if !seen[part] {
			seen[part] = true
			out = append(out, part)
		}
	}

	if len(out) == 0 {
		return nil, fmt.Errorf("no valid targets in %q", spec)
	}
	return out, nil
}

func expandCIDR(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	if ip.To4() == nil {
		return nil, fmt.Errorf("only IPv4 CIDR expansion is supported: %s", cidr)
	}

	cur := ip.Mask(ipnet.Mask).To4()
	tmp := make(net.IP, len(cur))
	copy(tmp, cur)

	var ips []string
	for ipnet.Contains(tmp) {
		ips = append(ips, tmp.String())
		if len(ips) > maxHosts {
			return nil, fmt.Errorf("CIDR %s is too large (>%d hosts); narrow the range", cidr, maxHosts)
		}
		inc(tmp)
	}

	// Drop network and broadcast addresses for /30 and larger blocks.
	if ones, bits := ipnet.Mask.Size(); bits == 32 && ones <= 30 && len(ips) >= 2 {
		ips = ips[1 : len(ips)-1]
	}
	return ips, nil
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] != 0 {
			break
		}
	}
}

func sortIPs(ips []string) {
	sort.Slice(ips, func(i, j int) bool {
		a, b := net.ParseIP(ips[i]), net.ParseIP(ips[j])
		if a == nil || b == nil {
			return ips[i] < ips[j]
		}
		return bytes.Compare(a.To16(), b.To16()) < 0
	})
}

func jitterSleep(d time.Duration) {
	if d <= 0 {
		return
	}
	time.Sleep(time.Duration(rand.Int63n(int64(d))))
}

func (o Options) connectTimeout() time.Duration {
	if o.Timeout <= 0 {
		return 2 * time.Second
	}
	return time.Duration(o.Timeout) * time.Second
}

// discoveryTimeout is capped shorter than the full connect timeout so liveness
// probing over dead hosts stays fast.
func (o Options) discoveryTimeout() time.Duration {
	if t := o.connectTimeout(); t < time.Second {
		return t
	}
	return time.Second
}
