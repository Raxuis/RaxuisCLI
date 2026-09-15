package tunnel

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

// TunnelType represents the type of tunnel
type TunnelType string

const (
	TunnelDNS  TunnelType = "dns"
	TunnelICMP TunnelType = "icmp"
	TunnelHTTP TunnelType = "http"
)

// TunnelOptions holds tunnel configuration
type TunnelOptions struct {
	Type       TunnelType
	LocalAddr  string
	RemoteAddr string
	Domain     string
	Encoding   string // "base64", "hex", "raw"
	Delay      int    // Delay between requests in ms
	ChunkSize  int
}

// DNSTunnel represents a DNS tunnel
type DNSTunnel struct {
	domain    string
	encoding  string
	chunkSize int
}

// HTTPTunnel represents an HTTP-based data tunnel
type HTTPTunnel struct {
	url       string
	encoding  string
	chunkSize int
	delay     int
}

// NewDNSTunnel creates a new DNS tunnel
func NewDNSTunnel(domain string, encoding string, chunkSize int) *DNSTunnel {
	if chunkSize == 0 {
		chunkSize = 60 // Max subdomain length
	}
	if encoding == "" {
		encoding = "base64"
	}

	return &DNSTunnel{
		domain:    domain,
		encoding:  encoding,
		chunkSize: chunkSize,
	}
}

// Encode encodes data for DNS tunnel
func (t *DNSTunnel) Encode(data []byte) []string {
	var chunks []string
	var encoded string

	switch t.encoding {
	case "hex":
		encoded = hex.EncodeToString(data)
	case "base64":
		// Use URL-safe base64 and replace = with -
		encoded = base64.URLEncoding.EncodeToString(data)
		encoded = strings.ReplaceAll(encoded, "=", "-")
	default:
		encoded = string(data)
	}

	// Split into DNS-safe chunks
	for len(encoded) > 0 {
		size := t.chunkSize
		if size > len(encoded) {
			size = len(encoded)
		}
		chunks = append(chunks, encoded[:size])
		encoded = encoded[size:]
	}

	return chunks
}

// Decode decodes data from DNS tunnel
func (t *DNSTunnel) Decode(chunks []string) ([]byte, error) {
	encoded := strings.Join(chunks, "")

	switch t.encoding {
	case "hex":
		return hex.DecodeString(encoded)
	case "base64":
		encoded = strings.ReplaceAll(encoded, "-", "=")
		return base64.URLEncoding.DecodeString(encoded)
	default:
		return []byte(encoded), nil
	}
}

// BuildQuery builds a DNS query for the data
func (t *DNSTunnel) BuildQuery(data []byte, seqNum int) string {
	chunks := t.Encode(data)

	if len(chunks) == 0 {
		return ""
	}

	// Format: seq.chunk.domain
	query := fmt.Sprintf("%d.%s.%s", seqNum, chunks[0], t.domain)
	return query
}

// SendData sends data through DNS queries
func (t *DNSTunnel) SendData(data []byte) error {
	chunks := t.Encode(data)

	for i, chunk := range chunks {
		query := fmt.Sprintf("%d.%s.%s", i, chunk, t.domain)

		// Perform DNS lookup. The error is expected and ignored: the data is in
		// the query itself, and the receiving end reads queries, not responses.
		_, _ = net.LookupHost(query)

		// Small delay to avoid rate limiting
		time.Sleep(10 * time.Millisecond)
	}

	return nil
}

// NewHTTPTunnel creates a new HTTP tunnel
func NewHTTPTunnel(url string, encoding string, chunkSize int, delay int) *HTTPTunnel {
	if chunkSize == 0 {
		chunkSize = 1024
	}
	if encoding == "" {
		encoding = "base64"
	}

	return &HTTPTunnel{
		url:       url,
		encoding:  encoding,
		chunkSize: chunkSize,
		delay:     delay,
	}
}

// Encode encodes data for HTTP transport
func (t *HTTPTunnel) Encode(data []byte) string {
	switch t.encoding {
	case "hex":
		return hex.EncodeToString(data)
	case "base64":
		return base64.StdEncoding.EncodeToString(data)
	default:
		return string(data)
	}
}

// Decode decodes data from HTTP transport
func (t *HTTPTunnel) Decode(encoded string) ([]byte, error) {
	switch t.encoding {
	case "hex":
		return hex.DecodeString(encoded)
	case "base64":
		return base64.StdEncoding.DecodeString(encoded)
	default:
		return []byte(encoded), nil
	}
}

// ChunkData splits data into chunks for transmission
func ChunkData(data []byte, chunkSize int) [][]byte {
	var chunks [][]byte

	for len(data) > 0 {
		size := chunkSize
		if size > len(data) {
			size = len(data)
		}
		chunks = append(chunks, data[:size])
		data = data[size:]
	}

	return chunks
}

// EncodeForDNS encodes data to be DNS-safe (alphanumeric + hyphen)
func EncodeForDNS(data []byte) string {
	// Use base32 for DNS-safe encoding
	encoded := base64.URLEncoding.EncodeToString(data)
	// Replace non-DNS characters
	encoded = strings.ReplaceAll(encoded, "+", "0")
	encoded = strings.ReplaceAll(encoded, "/", "1")
	encoded = strings.ReplaceAll(encoded, "=", "")
	return strings.ToLower(encoded)
}

// DecodeFromDNS decodes DNS-safe encoded data
func DecodeFromDNS(encoded string) ([]byte, error) {
	// Reverse the encoding
	encoded = strings.ToUpper(encoded)
	encoded = strings.ReplaceAll(encoded, "0", "+")
	encoded = strings.ReplaceAll(encoded, "1", "/")

	// Add padding
	switch len(encoded) % 4 {
	case 2:
		encoded += "=="
	case 3:
		encoded += "="
	}

	return base64.URLEncoding.DecodeString(encoded)
}

// TCPProxy creates a TCP proxy/forwarder
type TCPProxy struct {
	localAddr  string
	remoteAddr string
	running    bool
	listener   net.Listener
	mu         sync.Mutex
}

// NewTCPProxy creates a new TCP proxy
func NewTCPProxy(localAddr, remoteAddr string) *TCPProxy {
	return &TCPProxy{
		localAddr:  localAddr,
		remoteAddr: remoteAddr,
	}
}

// Start starts the TCP proxy
func (p *TCPProxy) Start() error {
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

			go p.handleConnection(conn)
		}
	}()

	return nil
}

// handleConnection handles a proxied connection
func (p *TCPProxy) handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	remoteConn, err := net.Dial("tcp", p.remoteAddr)
	if err != nil {
		return
	}
	defer remoteConn.Close()

	// Bidirectional copy
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		_, _ = io.Copy(remoteConn, clientConn)
	}()

	go func() {
		defer wg.Done()
		_, _ = io.Copy(clientConn, remoteConn)
	}()

	wg.Wait()
}

// Stop stops the TCP proxy
func (p *TCPProxy) Stop() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.running = false
	if p.listener != nil {
		return p.listener.Close()
	}
	return nil
}

// DataChunk represents a chunk of tunneled data
type DataChunk struct {
	Sequence int
	Total    int
	Data     []byte
	Checksum uint32
}

// EncodeChunk encodes a data chunk for transmission
func EncodeChunk(chunk DataChunk, encoding string) string {
	// Format: seq|total|checksum|data
	header := fmt.Sprintf("%d|%d|%d|", chunk.Sequence, chunk.Total, chunk.Checksum)

	var encodedData string
	switch encoding {
	case "hex":
		encodedData = hex.EncodeToString(chunk.Data)
	case "base64":
		encodedData = base64.StdEncoding.EncodeToString(chunk.Data)
	default:
		encodedData = string(chunk.Data)
	}

	return header + encodedData
}

// DecodeChunk decodes a transmitted chunk
func DecodeChunk(encoded string, encoding string) (*DataChunk, error) {
	parts := strings.SplitN(encoded, "|", 4)
	if len(parts) != 4 {
		return nil, fmt.Errorf("invalid chunk format")
	}

	chunk := &DataChunk{}
	_, _ = fmt.Sscanf(parts[0], "%d", &chunk.Sequence)
	_, _ = fmt.Sscanf(parts[1], "%d", &chunk.Total)
	_, _ = fmt.Sscanf(parts[2], "%d", &chunk.Checksum)

	var err error
	switch encoding {
	case "hex":
		chunk.Data, err = hex.DecodeString(parts[3])
	case "base64":
		chunk.Data, err = base64.StdEncoding.DecodeString(parts[3])
	default:
		chunk.Data = []byte(parts[3])
	}

	return chunk, err
}

// SimpleChecksum calculates a simple checksum
func SimpleChecksum(data []byte) uint32 {
	var sum uint32
	for _, b := range data {
		sum += uint32(b)
	}
	return sum
}

// DisplayTunnelInfo displays tunnel information
func DisplayTunnelInfo(tunnelType TunnelType, local, remote string) {
	fmt.Fprintf(stdoutW, "\n[TUNNEL] %s\n", strings.ToUpper(string(tunnelType)))
	fmt.Fprintln(stdoutW, strings.Repeat("=", 50))
	fmt.Fprintf(stdoutW, "Type:   %s\n", tunnelType)
	fmt.Fprintf(stdoutW, "Local:  %s\n", local)
	fmt.Fprintf(stdoutW, "Remote: %s\n", remote)
	fmt.Fprintln(stdoutW)
}
