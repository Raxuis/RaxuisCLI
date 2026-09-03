package hash

import "testing"

func TestHashKnownVectors(t *testing.T) {
	tests := []struct {
		input string
		algo  Algorithm
		want  string
	}{
		{"", AlgoMD5, "d41d8cd98f00b204e9800998ecf8427e"},
		{"hello", AlgoMD5, "5d41402abc4b2a76b9719d911017c592"},
		{"hello", AlgoSHA1, "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"},
		{"hello", AlgoSHA256, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"},
	}

	for _, tt := range tests {
		result, err := Hash(tt.input, tt.algo, false)
		if err != nil {
			t.Fatalf("Hash(%q, %s) returned error: %v", tt.input, tt.algo, err)
		}
		if result.Hash != tt.want {
			t.Errorf("Hash(%q, %s) = %q, want %q", tt.input, tt.algo, result.Hash, tt.want)
		}
	}
}

func TestHashUnsupportedAlgorithm(t *testing.T) {
	_, err := Hash("test", "bogus", false)
	if err == nil {
		t.Error("Hash with unsupported algorithm should return an error")
	}
}

func TestHashIsDeterministic(t *testing.T) {
	a, err := Hash("consistent input", AlgoSHA256, false)
	if err != nil {
		t.Fatalf("Hash returned error: %v", err)
	}
	b, err := Hash("consistent input", AlgoSHA256, false)
	if err != nil {
		t.Fatalf("Hash returned error: %v", err)
	}
	if a.Hash != b.Hash {
		t.Errorf("Hash should be deterministic: got %q and %q", a.Hash, b.Hash)
	}
}

func TestHashAllReturnsAllAlgorithms(t *testing.T) {
	results, err := HashAll("test", false)
	if err != nil {
		t.Fatalf("HashAll returned error: %v", err)
	}

	for _, algo := range GetSupportedAlgorithms() {
		if _, ok := results[algo]; !ok {
			t.Errorf("HashAll result missing algorithm %s", algo)
		}
	}
}

func TestIdentifyByLength(t *testing.T) {
	tests := []struct {
		hash string
		want []Algorithm
	}{
		{"5d41402abc4b2a76b9719d911017c5920", nil},                          // 33 chars, no match
		{"5d41402abc4b2a76b9719d911017c592", []Algorithm{AlgoMD5}},          // 32 chars
		{"aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d", []Algorithm{AlgoSHA1}}, // 40 chars
	}

	for _, tt := range tests {
		result := Identify(tt.hash)
		if len(result.Algorithms) != len(tt.want) {
			t.Errorf("Identify(%q) algorithms = %v, want %v", tt.hash, result.Algorithms, tt.want)
			continue
		}
		for i := range tt.want {
			if result.Algorithms[i] != tt.want[i] {
				t.Errorf("Identify(%q) algorithms = %v, want %v", tt.hash, result.Algorithms, tt.want)
			}
		}
	}
}

func TestIdentifyNonHexString(t *testing.T) {
	result := Identify("not a hash at all!")
	if result.Algorithms != nil {
		t.Errorf("Identify on non-hex string should return nil algorithms, got %v", result.Algorithms)
	}
}

func TestHashFileMissingFile(t *testing.T) {
	_, err := Hash("/nonexistent/path/to/file", AlgoMD5, true)
	if err == nil {
		t.Error("Hash on missing file should return an error")
	}
}
