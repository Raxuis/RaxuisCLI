package pivot

import (
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// ProxyType represents the type of proxy
type ProxyType string

const (
	SOCKS5Proxy  ProxyType = "socks5"
	HTTPProxy    ProxyType = "http"
	ForwardProxy ProxyType = "forward"
	ReverseProxy ProxyType = "reverse"
)

// ProxyOptions holds proxy configuration
type ProxyOptions struct {
	Type       ProxyType
	ListenAddr string
	TargetAddr string
	Username   string
	Password   string
	Timeout    int
}

// SOCKS5Server represents a SOCKS5 proxy server
type SOCKS5Server struct {
	listenAddr string
	username   string
	password   string
	listener   net.Listener
	running    bool
	mu         sync.Mutex
	conns      map[string]net.Conn
}

// PortForward represents a port forward
type PortForward struct {
	localAddr  string
	remoteAddr string
	listener   net.Listener
	running    bool
	mu         sync.Mutex
}

// NewSOCKS5Server creates a new SOCKS5 server
func NewSOCKS5Server(addr, username, password string) *SOCKS5Server {
	return &SOCKS5Server{
		listenAddr: addr,
		username:   username,
		password:   password,
		conns:      make(map[string]net.Conn),
	}
}

// Start starts the SOCKS5 server
func (s *SOCKS5Server) Start() error {
	listener, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen: %v", err)
	}

	s.mu.Lock()
	s.listener = listener
	s.running = true
	s.mu.Unlock()

	go func() {
		for s.running {
			conn, err := listener.Accept()
			if err != nil {
				if s.running {
					continue
				}
				return
			}

			go s.handleConnection(conn)
		}
	}()

	return nil
}

// handleConnection handles a SOCKS5 connection
func (s *SOCKS5Server) handleConnection(conn net.Conn) {
	defer conn.Close()

	// Set timeout
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

	// Read version and methods
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil || n < 2 {
		return
	}

	// Check SOCKS version
	if buf[0] != 0x05 {
		return
	}

	// Authentication
	if s.username != "" {
		// Require username/password auth
		_, _ = conn.Write([]byte{0x05, 0x02}) // Username/password auth

		// Read auth request
		n, err = conn.Read(buf)
		if err != nil || n < 3 {
			return
		}

		// Parse username/password
		if buf[0] != 0x01 {
			return
		}
		userLen := int(buf[1])
		if n < 2+userLen+1 {
			return
		}
		user := string(buf[2 : 2+userLen])
		passLen := int(buf[2+userLen])
		if n < 3+userLen+passLen {
			return
		}
		pass := string(buf[3+userLen : 3+userLen+passLen])

		// Verify credentials
		if user != s.username || pass != s.password {
			_, _ = conn.Write([]byte{0x01, 0x01}) // Auth failed
			return
		}

		_, _ = conn.Write([]byte{0x01, 0x00}) // Auth success
	} else {
		// No auth required
		_, _ = conn.Write([]byte{0x05, 0x00})
	}

	// Read request
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	n, err = conn.Read(buf)
	if err != nil || n < 7 {
		return
	}

	// Parse request
	if buf[0] != 0x05 || buf[1] != 0x01 {
		// Only support CONNECT
		_, _ = conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	// Parse address
	var targetAddr string
	switch buf[3] {
	case 0x01: // IPv4
		targetAddr = fmt.Sprintf("%d.%d.%d.%d:%d",
			buf[4], buf[5], buf[6], buf[7],
			int(buf[8])<<8|int(buf[9]))
	case 0x03: // Domain
		domainLen := int(buf[4])
		domain := string(buf[5 : 5+domainLen])
		port := int(buf[5+domainLen])<<8 | int(buf[6+domainLen])
		targetAddr = fmt.Sprintf("%s:%d", domain, port)
	case 0x04: // IPv6
		// IPv6 support
		ip := net.IP(buf[4:20])
		port := int(buf[20])<<8 | int(buf[21])
		targetAddr = fmt.Sprintf("[%s]:%d", ip.String(), port)
	default:
		_, _ = conn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	// Connect to target
	targetConn, err := net.DialTimeout("tcp", targetAddr, 10*time.Second)
	if err != nil {
		_, _ = conn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer targetConn.Close()

	// Send success response
	_, _ = conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

	// Clear deadline for proxying
	_ = conn.SetDeadline(time.Time{})
	_ = targetConn.SetDeadline(time.Time{})

	// Proxy data
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		_, _ = io.Copy(targetConn, conn)
	}()

	go func() {
		defer wg.Done()
		_, _ = io.Copy(conn, targetConn)
	}()

	wg.Wait()
}

// Stop stops the SOCKS5 server
func (s *SOCKS5Server) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.running = false
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

// NewPortForward creates a new port forward
func NewPortForward(localAddr, remoteAddr string) *PortForward {
	return &PortForward{
		localAddr:  localAddr,
		remoteAddr: remoteAddr,
	}
}

// Start starts port forwarding
func (p *PortForward) Start() error {
	listener, err := net.Listen("tcp", p.localAddr)
	if err != nil {
		return fmt.Errorf("failed to listen: %v", err)
	}

	p.mu.Lock()
	p.listener = listener
	p.running = true
	p.mu.Unlock()

	go func() {
		for p.running {
			conn, err := listener.Accept()
			if err != nil {
				if p.running {
					continue
				}
				return
			}

			go p.handleForward(conn)
		}
	}()

	return nil
}

// handleForward handles a forwarded connection
func (p *PortForward) handleForward(clientConn net.Conn) {
	defer clientConn.Close()

	targetConn, err := net.DialTimeout("tcp", p.remoteAddr, 10*time.Second)
	if err != nil {
		return
	}
	defer targetConn.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		_, _ = io.Copy(targetConn, clientConn)
	}()

	go func() {
		defer wg.Done()
		_, _ = io.Copy(clientConn, targetConn)
	}()

	wg.Wait()
}

// Stop stops port forwarding
func (p *PortForward) Stop() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.running = false
	if p.listener != nil {
		return p.listener.Close()
	}
	return nil
}

// ReversePortForward handles reverse port forwarding
type ReversePortForward struct {
	controlAddr string
	localPort   int
}

// NewReversePortForward creates a reverse port forward
func NewReversePortForward(controlAddr string, localPort int) *ReversePortForward {
	return &ReversePortForward{
		controlAddr: controlAddr,
		localPort:   localPort,
	}
}

// DisplayProxyInfo displays proxy information
func DisplayProxyInfo(proxyType ProxyType, listenAddr string, auth bool) {
	fmt.Printf("\n[PIVOT] %s Proxy\n", proxyType)
	fmt.Println("========================")
	fmt.Printf("Type:    %s\n", proxyType)
	fmt.Printf("Listen:  %s\n", listenAddr)
	fmt.Printf("Auth:    %v\n", auth)

	switch proxyType {
	case SOCKS5Proxy:
		fmt.Println("\nUsage:")
		fmt.Printf("  curl --socks5 %s http://target\n", listenAddr)
		fmt.Printf("  proxychains -q ./tool\n")
		fmt.Printf("  ssh -D %s user@host (creates SOCKS proxy)\n", listenAddr)
	case ForwardProxy:
		fmt.Println("\nUsage:")
		fmt.Printf("  nc %s\n", listenAddr)
	}

	fmt.Println()
}

// DisplayForwardInfo displays port forward information
func DisplayForwardInfo(localAddr, remoteAddr string) {
	fmt.Println("\n[PIVOT] Port Forward")
	fmt.Println("====================")
	fmt.Printf("Local:   %s\n", localAddr)
	fmt.Printf("Remote:  %s\n", remoteAddr)
	fmt.Println("\nTraffic Flow:")
	fmt.Printf("  Client -> %s -> %s\n", localAddr, remoteAddr)
	fmt.Println()
}

// TestConnectivity tests if a remote address is reachable
func TestConnectivity(addr string, timeout int) error {
	conn, err := net.DialTimeout("tcp", addr, time.Duration(timeout)*time.Second)
	if err != nil {
		return err
	}
	conn.Close()
	return nil
}
