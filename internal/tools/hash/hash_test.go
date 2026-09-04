package hash

import (
	"os"
	"path/filepath"
	"testing"
)

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

func writeWordlist(t *testing.T, words ...string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "wordlist.txt")
	content := ""
	for _, w := range words {
		content += w + "\n"
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write wordlist: %v", err)
	}
	return path
}

func TestCrackFindsMatch(t *testing.T) {
	wordlist := writeWordlist(t, "wrong1", "wrong2", "hello", "wrong3")

	targetHash, err := Hash("hello", AlgoMD5, false)
	if err != nil {
		t.Fatalf("Hash returned error: %v", err)
	}

	result, err := Crack(targetHash.Hash, AlgoMD5, wordlist)
	if err != nil {
		t.Fatalf("Crack returned error: %v", err)
	}
	if !result.Found {
		t.Fatal("Crack should have found the matching word")
	}
	if result.Plaintext != "hello" {
		t.Errorf("Crack plaintext = %q, want %q", result.Plaintext, "hello")
	}
	if result.Attempts != 3 {
		t.Errorf("Crack attempts = %d, want 3 (stops at the match)", result.Attempts)
	}
}

func TestCrackNoMatch(t *testing.T) {
	wordlist := writeWordlist(t, "wrong1", "wrong2")

	result, err := Crack("deadbeefdeadbeefdeadbeefdeadbeef", AlgoMD5, wordlist)
	if err != nil {
		t.Fatalf("Crack returned error: %v", err)
	}
	if result.Found {
		t.Error("Crack should not have found a match")
	}
	if result.Attempts != 2 {
		t.Errorf("Crack attempts = %d, want 2", result.Attempts)
	}
}

func TestCrackMissingWordlist(t *testing.T) {
	if _, err := Crack("abc", AlgoMD5, "/nonexistent/wordlist.txt"); err == nil {
		t.Error("Crack with a missing wordlist should return an error")
	}
}

func TestCrackWithProgressReportsAndFinds(t *testing.T) {
	words := make([]string, 0, 20001)
	for i := 0; i < 20000; i++ {
		words = append(words, "filler")
	}
	words = append(words, "target-word")
	wordlist := writeWordlist(t, words...)

	targetHash, err := Hash("target-word", AlgoSHA256, false)
	if err != nil {
		t.Fatalf("Hash returned error: %v", err)
	}

	var progressCalls int
	result, err := CrackWithProgress(targetHash.Hash, AlgoSHA256, wordlist, func(attempts int) {
		progressCalls++
	})
	if err != nil {
		t.Fatalf("CrackWithProgress returned error: %v", err)
	}
	if !result.Found || result.Plaintext != "target-word" {
		t.Errorf("CrackWithProgress result = %+v, want Found with plaintext target-word", result)
	}
	if progressCalls == 0 {
		t.Error("expected the progress callback to be invoked at least once over 20000+ attempts")
	}
}

func TestCrackWithProgressMissingWordlist(t *testing.T) {
	if _, err := CrackWithProgress("abc", AlgoMD5, "/nonexistent/wordlist.txt", nil); err == nil {
		t.Error("CrackWithProgress with a missing wordlist should return an error")
	}
}

func TestHashFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sample.txt")
	if err := os.WriteFile(path, []byte("hello"), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	got, err := HashFile(path, AlgoMD5)
	if err != nil {
		t.Fatalf("HashFile returned error: %v", err)
	}
	want := "5d41402abc4b2a76b9719d911017c592"
	if got != want {
		t.Errorf("HashFile(md5) = %q, want %q", got, want)
	}
}

func TestHashFileAllAlgorithms(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sample.txt")
	os.WriteFile(path, []byte("data"), 0644)

	for _, algo := range GetSupportedAlgorithms() {
		if _, err := HashFile(path, algo); err != nil {
			t.Errorf("HashFile(%s) returned error: %v", algo, err)
		}
	}
}

func TestHashFileUnsupportedAlgorithm(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sample.txt")
	os.WriteFile(path, []byte("data"), 0644)

	if _, err := HashFile(path, "bogus"); err == nil {
		t.Error("HashFile with an unsupported algorithm should return an error")
	}
}

func TestHashFileMissing(t *testing.T) {
	if _, err := HashFile("/nonexistent/file", AlgoMD5); err == nil {
		t.Error("HashFile on a missing file should return an error")
	}
}
