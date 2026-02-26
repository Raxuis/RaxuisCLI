package hash

import (
	"bufio"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"os"
	"regexp"
	"strings"

	"golang.org/x/crypto/blake2b"
)

// Algorithm represents a hashing algorithm
type Algorithm string

const (
	AlgoMD5    Algorithm = "md5"
	AlgoSHA1   Algorithm = "sha1"
	AlgoSHA256 Algorithm = "sha256"
	AlgoSHA512 Algorithm = "sha512"
	AlgoBlake2 Algorithm = "blake2"
)

// HashResult holds the result of a hash operation
type HashResult struct {
	Input     string
	Algorithm Algorithm
	Hash      string
	IsFile    bool
}

// IdentifyResult holds the result of hash identification
type IdentifyResult struct {
	Hash       string
	Algorithms []Algorithm
	Length     int
}

// CrackResult holds the result of a crack attempt
type CrackResult struct {
	Hash      string
	Algorithm Algorithm
	Found     bool
	Plaintext string
	Attempts  int
}

// Hash computes the hash of a string or file
func Hash(input string, algo Algorithm, isFile bool) (*HashResult, error) {
	var data []byte
	var err error

	if isFile {
		data, err = os.ReadFile(input)
		if err != nil {
			return nil, fmt.Errorf("error reading file: %w", err)
		}
	} else {
		data = []byte(input)
	}

	hashStr, err := computeHash(data, algo)
	if err != nil {
		return nil, err
	}

	return &HashResult{
		Input:     input,
		Algorithm: algo,
		Hash:      hashStr,
		IsFile:    isFile,
	}, nil
}

// HashAll computes hash with all supported algorithms
func HashAll(input string, isFile bool) (map[Algorithm]string, error) {
	var data []byte
	var err error

	if isFile {
		data, err = os.ReadFile(input)
		if err != nil {
			return nil, fmt.Errorf("error reading file: %w", err)
		}
	} else {
		data = []byte(input)
	}

	results := make(map[Algorithm]string)
	algos := []Algorithm{AlgoMD5, AlgoSHA1, AlgoSHA256, AlgoSHA512, AlgoBlake2}

	for _, algo := range algos {
		hashStr, err := computeHash(data, algo)
		if err != nil {
			continue
		}
		results[algo] = hashStr
	}

	return results, nil
}

// computeHash computes the hash of data using the specified algorithm
func computeHash(data []byte, algo Algorithm) (string, error) {
	var h hash.Hash

	switch algo {
	case AlgoMD5:
		h = md5.New()
	case AlgoSHA1:
		h = sha1.New()
	case AlgoSHA256:
		h = sha256.New()
	case AlgoSHA512:
		h = sha512.New()
	case AlgoBlake2:
		var err error
		h, err = blake2b.New256(nil)
		if err != nil {
			return "", err
		}
	default:
		return "", fmt.Errorf("unsupported algorithm: %s", algo)
	}

	h.Write(data)
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Identify attempts to identify the hash type based on length and format
func Identify(hashStr string) *IdentifyResult {
	// Clean the hash
	hashStr = strings.TrimSpace(hashStr)
	hashStr = strings.ToLower(hashStr)

	// Check if it's a valid hex string
	if !isValidHex(hashStr) {
		return &IdentifyResult{
			Hash:       hashStr,
			Algorithms: nil,
			Length:     len(hashStr),
		}
	}

	result := &IdentifyResult{
		Hash:   hashStr,
		Length: len(hashStr),
	}

	// Identify based on length
	switch len(hashStr) {
	case 32:
		result.Algorithms = []Algorithm{AlgoMD5}
	case 40:
		result.Algorithms = []Algorithm{AlgoSHA1}
	case 64:
		result.Algorithms = []Algorithm{AlgoSHA256, AlgoBlake2}
	case 128:
		result.Algorithms = []Algorithm{AlgoSHA512}
	default:
		result.Algorithms = nil
	}

	return result
}

// isValidHex checks if a string is valid hexadecimal
func isValidHex(s string) bool {
	match, _ := regexp.MatchString("^[a-fA-F0-9]+$", s)
	return match
}

// Crack attempts to crack a hash using a wordlist
func Crack(hashStr string, algo Algorithm, wordlistPath string) (*CrackResult, error) {
	hashStr = strings.TrimSpace(strings.ToLower(hashStr))

	result := &CrackResult{
		Hash:      hashStr,
		Algorithm: algo,
		Found:     false,
		Attempts:  0,
	}

	file, err := os.Open(wordlistPath)
	if err != nil {
		return nil, fmt.Errorf("error opening wordlist: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	// Increase buffer size for long lines
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		word := scanner.Text()
		result.Attempts++

		computed, err := computeHash([]byte(word), algo)
		if err != nil {
			continue
		}

		if computed == hashStr {
			result.Found = true
			result.Plaintext = word
			return result, nil
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading wordlist: %w", err)
	}

	return result, nil
}

// CrackWithProgress attempts to crack a hash and reports progress
func CrackWithProgress(hashStr string, algo Algorithm, wordlistPath string, progressFn func(attempts int)) (*CrackResult, error) {
	hashStr = strings.TrimSpace(strings.ToLower(hashStr))

	result := &CrackResult{
		Hash:      hashStr,
		Algorithm: algo,
		Found:     false,
		Attempts:  0,
	}

	file, err := os.Open(wordlistPath)
	if err != nil {
		return nil, fmt.Errorf("error opening wordlist: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		word := scanner.Text()
		result.Attempts++

		// Report progress every 10000 attempts
		if progressFn != nil && result.Attempts%10000 == 0 {
			progressFn(result.Attempts)
		}

		computed, err := computeHash([]byte(word), algo)
		if err != nil {
			continue
		}

		if computed == hashStr {
			result.Found = true
			result.Plaintext = word
			return result, nil
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading wordlist: %w", err)
	}

	return result, nil
}

// HashFile computes the hash of a file efficiently (for large files)
func HashFile(path string, algo Algorithm) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	var h hash.Hash

	switch algo {
	case AlgoMD5:
		h = md5.New()
	case AlgoSHA1:
		h = sha1.New()
	case AlgoSHA256:
		h = sha256.New()
	case AlgoSHA512:
		h = sha512.New()
	case AlgoBlake2:
		var err error
		h, err = blake2b.New256(nil)
		if err != nil {
			return "", err
		}
	default:
		return "", fmt.Errorf("unsupported algorithm: %s", algo)
	}

	if _, err := io.Copy(h, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

// GetSupportedAlgorithms returns a list of supported algorithms
func GetSupportedAlgorithms() []Algorithm {
	return []Algorithm{AlgoMD5, AlgoSHA1, AlgoSHA256, AlgoSHA512, AlgoBlake2}
}
