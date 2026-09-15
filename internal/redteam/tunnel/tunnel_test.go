package tunnel

import (
	"bytes"
	"testing"
)

func TestChunkData(t *testing.T) {
	tests := []struct {
		name      string
		data      []byte
		chunkSize int
		wantCount int
		wantLen   []int
	}{
		{"empty", []byte{}, 10, 0, []int{}},
		{"single chunk", []byte{1, 2, 3}, 10, 1, []int{3}},
		{"multiple chunks", []byte{1, 2, 3, 4, 5}, 2, 3, []int{2, 2, 1}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ChunkData(tt.data, tt.chunkSize)
			if len(got) != tt.wantCount {
				t.Errorf("ChunkData() returned %d chunks, want %d", len(got), tt.wantCount)
			}
			for i, chunk := range got {
				if len(chunk) != tt.wantLen[i] {
					t.Errorf("chunk %d len = %d, want %d", i, len(chunk), tt.wantLen[i])
				}
			}
		})
	}
}

func TestEncodeForDNS(t *testing.T) {
	data := []byte("hello")
	got := EncodeForDNS(data)
	if got == "" {
		t.Errorf("EncodeForDNS() returned empty string")
	}
	for _, c := range got {
		if c == '+' || c == '/' || c == '=' {
			t.Errorf("EncodeForDNS() contains invalid DNS char: %c", c)
		}
	}
}

func TestDecodeFromDNS(t *testing.T) {
	original := []byte("hello")
	encoded := EncodeForDNS(original)
	got, err := DecodeFromDNS(encoded)
	if err != nil {
		t.Errorf("DecodeFromDNS() error = %v", err)
	}
	if !bytes.Equal(got, original) {
		t.Errorf("DecodeFromDNS() = %q, want %q", got, original)
	}
}

func TestEncodeChunk(t *testing.T) {
	chunk := DataChunk{
		Sequence: 1,
		Total:    3,
		Checksum: 12345,
		Data:     []byte("test"),
	}
	tests := []struct {
		name     string
		encoding string
	}{
		{"hex", "hex"},
		{"base64", "base64"},
		{"raw", "raw"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := EncodeChunk(chunk, tt.encoding)
			if !bytes.Contains([]byte(got), []byte("1|3|12345|")) {
				t.Errorf("EncodeChunk() missing header: %q", got)
			}
		})
	}
}

func TestDecodeChunk(t *testing.T) {
	original := DataChunk{
		Sequence: 1,
		Total:    3,
		Checksum: 12345,
		Data:     []byte("test"),
	}
	encoded := EncodeChunk(original, "hex")
	got, err := DecodeChunk(encoded, "hex")
	if err != nil {
		t.Errorf("DecodeChunk() error = %v", err)
		return
	}
	if got.Sequence != original.Sequence || got.Total != original.Total {
		t.Errorf("DecodeChunk() metadata mismatch: %+v", got)
	}
	if !bytes.Equal(got.Data, original.Data) {
		t.Errorf("DecodeChunk() data = %q, want %q", got.Data, original.Data)
	}
}

func TestSimpleChecksum(t *testing.T) {
	data := []byte{1, 2, 3, 4, 5}
	got := SimpleChecksum(data)
	if got != 15 {
		t.Errorf("SimpleChecksum() = %d, want 15", got)
	}
}

func TestNewDNSTunnel(t *testing.T) {
	tunnel := NewDNSTunnel("example.com", "base64", 60)
	if tunnel.domain != "example.com" {
		t.Errorf("domain = %q, want example.com", tunnel.domain)
	}
	if tunnel.encoding != "base64" {
		t.Errorf("encoding = %q, want base64", tunnel.encoding)
	}
}

func TestDNSTunnelEncodeDecode(t *testing.T) {
	tunnel := NewDNSTunnel("example.com", "base64", 60)
	original := []byte("secret data here")
	chunks := tunnel.Encode(original)
	if len(chunks) == 0 {
		t.Errorf("Encode() returned empty chunks")
	}
	decoded, err := tunnel.Decode(chunks)
	if err != nil {
		t.Errorf("Decode() error = %v", err)
	}
	if !bytes.Equal(decoded, original) {
		t.Errorf("roundtrip failed: got %q, want %q", decoded, original)
	}
}

func TestDNSTunnelBuildQuery(t *testing.T) {
	tunnel := NewDNSTunnel("example.com", "hex", 60)
	data := []byte("test")
	got := tunnel.BuildQuery(data, 0)
	if !bytes.Contains([]byte(got), []byte("example.com")) {
		t.Errorf("BuildQuery() missing domain: %q", got)
	}
}

func TestNewHTTPTunnel(t *testing.T) {
	tunnel := NewHTTPTunnel("http://example.com/upload", "base64", 1024, 100)
	if tunnel.url != "http://example.com/upload" {
		t.Errorf("url = %q", tunnel.url)
	}
}

func TestHTTPTunnelEncodeDecode(t *testing.T) {
	tunnel := NewHTTPTunnel("http://example.com", "hex", 1024, 100)
	original := []byte("payload data")
	encoded := tunnel.Encode(original)
	decoded, err := tunnel.Decode(encoded)
	if err != nil {
		t.Errorf("Decode() error = %v", err)
	}
	if !bytes.Equal(decoded, original) {
		t.Errorf("roundtrip failed")
	}
}
