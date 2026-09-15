package exfil

import (
	"bytes"
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

func TestEncodeForDNS(t *testing.T) {
	data := []byte("secret")
	encoded := EncodeForDNS(data)
	if encoded == "" {
		t.Errorf("EncodeForDNS() returned empty string")
	}
	for _, c := range encoded {
		if c == '+' || c == '/' || c == '=' {
			t.Errorf("EncodeForDNS() contains invalid DNS char: %c", c)
		}
	}
}

func TestEncodeForHTTP(t *testing.T) {
	data := []byte("secret data")
	encoded := EncodeForHTTP(data)
	if encoded == "" {
		t.Errorf("EncodeForHTTP() returned empty string")
	}
}

func TestChunkFile(t *testing.T) {
	data := []byte("this is sensitive data that needs to be exfiltrated")
	chunks := ChunkFile(data, 10)
	if len(chunks) == 0 {
		t.Errorf("ChunkFile() returned empty chunks")
	}
	var reassembled []byte
	for _, chunk := range chunks {
		reassembled = append(reassembled, chunk...)
	}
	if !bytes.Equal(reassembled, data) {
		t.Errorf("ChunkFile() reassembled data mismatch")
	}
}
