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
	Hash   string
	Length int
	Format string // "hex", "base64", "structured", "unknown"
	// Algorithms is the crackable subset (algorithms this tool can brute-force),
	// kept for backward compatibility with the crack auto-detection path.
	Algorithms []Algorithm
	// Candidates is the full, ranked identification (most likely first),
	// each carrying hashcat/john hints — the useful list for CTF work.
	Candidates []Candidate
}

// Candidate describes one possible hash type match.
type Candidate struct {
	Name        string
	HashcatMode string // hashcat -m value, empty when unsupported
	JohnFormat  string // john --format value, empty when unsupported
	Confidence  string // "certain", "probable" or "possible"
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

// Identify attempts to identify the hash type from its structure, length and
// character set. It returns a ranked list of candidates (Candidates) plus the
// crackable subset (Algorithms) used by the wordlist cracker.
func Identify(hashStr string) *IdentifyResult {
	raw := strings.TrimSpace(hashStr)
	result := &IdentifyResult{
		Hash:   raw,
		Length: len(raw),
		Format: "unknown",
	}

	// 1. Structured / prefixed formats — matched by signature, highest confidence.
	if sigs := identifyBySignature(raw); len(sigs) > 0 {
		result.Format = "structured"
		result.Candidates = sigs
		return result
	}

	lower := strings.ToLower(raw)

	// 2. Plain hex digests — disambiguated by length.
	if isValidHex(lower) {
		result.Format = "hex"
		result.Candidates = identifyHexByLength(len(lower))
		result.Algorithms = crackableByLength(len(lower))
		return result
	}

	// 3. Non-hex fallbacks (base64, JWT, ...).
	if cands := identifyNonHex(raw); len(cands) > 0 {
		result.Format = "base64"
		result.Candidates = cands
	}
	return result
}

// identifyBySignature matches structured formats (bcrypt, *crypt, LDAP, Django,
// Kerberos, MSSQL, MySQL 4.1+, ...) by their leading marker.
func identifyBySignature(h string) []Candidate {
	hl := strings.ToLower(h)
	switch {
	case strings.HasPrefix(h, "$2a$"), strings.HasPrefix(h, "$2b$"),
		strings.HasPrefix(h, "$2x$"), strings.HasPrefix(h, "$2y$"):
		return []Candidate{{"bcrypt (Blowfish)", "3200", "bcrypt", "certain"}}
	case strings.HasPrefix(h, "$apr1$"):
		return []Candidate{{"Apache apr1 MD5", "1600", "md5crypt", "certain"}}
	case strings.HasPrefix(h, "$1$"):
		return []Candidate{{"md5crypt (Unix, FreeBSD)", "500", "md5crypt", "certain"}}
	case strings.HasPrefix(h, "$5$"):
		return []Candidate{{"sha256crypt (Unix)", "7400", "sha256crypt", "certain"}}
	case strings.HasPrefix(h, "$6$"):
		return []Candidate{{"sha512crypt (Unix)", "1800", "sha512crypt", "certain"}}
	case strings.HasPrefix(h, "$argon2id$"):
		return []Candidate{{"Argon2id", "34000", "argon2", "certain"}}
	case strings.HasPrefix(h, "$argon2i$"):
		return []Candidate{{"Argon2i", "", "argon2", "certain"}}
	case strings.HasPrefix(h, "$argon2d$"):
		return []Candidate{{"Argon2d", "", "argon2", "certain"}}
	case strings.HasPrefix(h, "$P$"), strings.HasPrefix(h, "$H$"):
		return []Candidate{{"phpass (WordPress, phpBB3, Joomla)", "400", "phpass", "certain"}}
	case strings.HasPrefix(h, "$S$"):
		return []Candidate{{"Drupal 7 (phpass SHA-512)", "7900", "drupal7", "certain"}}
	case strings.HasPrefix(hl, "{ssha256}"):
		return []Candidate{{"LDAP SSHA-256 (base64)", "1411", "SSHA256", "certain"}}
	case strings.HasPrefix(hl, "{ssha512}"):
		return []Candidate{{"LDAP SSHA-512 (base64)", "1711", "SSHA512", "certain"}}
	case strings.HasPrefix(hl, "{ssha}"):
		return []Candidate{{"LDAP SSHA (salted SHA-1, base64)", "111", "Salted-SHA1", "certain"}}
	case strings.HasPrefix(hl, "{sha}"):
		return []Candidate{{"LDAP SHA-1 (base64)", "101", "nsldap", "certain"}}
	case strings.HasPrefix(hl, "{smd5}"):
		return []Candidate{{"LDAP SMD5 (salted MD5, base64)", "", "", "certain"}}
	case strings.HasPrefix(h, "pbkdf2_sha256$"):
		return []Candidate{{"Django PBKDF2-HMAC-SHA256", "10000", "django", "certain"}}
	case strings.HasPrefix(h, "pbkdf2_sha512$"):
		return []Candidate{{"PBKDF2-HMAC-SHA512", "12100", "", "certain"}}
	case strings.HasPrefix(h, "$pbkdf2-sha256$"):
		return []Candidate{{"PBKDF2-HMAC-SHA256 (passlib)", "10900", "", "certain"}}
	case strings.HasPrefix(h, "sha1$"):
		return []Candidate{{"Django (SHA-1)", "124", "django", "certain"}}
	case strings.HasPrefix(h, "sha256$"):
		return []Candidate{{"Django (SHA-256)", "", "django", "certain"}}
	case strings.HasPrefix(h, "md5$"):
		return []Candidate{{"Django (salted MD5)", "10", "django", "certain"}}
	case strings.HasPrefix(h, "$krb5tgs$"):
		return []Candidate{{"Kerberoast TGS-REP (Kerberos 5)", "13100", "krb5tgs", "certain"}}
	case strings.HasPrefix(h, "$krb5asrep$"):
		return []Candidate{{"AS-REP Roast (Kerberos 5)", "18200", "krb5asrep", "certain"}}
	case strings.HasPrefix(h, "$NT$"):
		return []Candidate{{"NTLM (John $NT$ form)", "1000", "nt", "certain"}}
	case strings.HasPrefix(hl, "$dcc2$"):
		return []Candidate{{"Domain Cached Credentials 2 (MS-Cache v2)", "2100", "mscash2", "certain"}}
	case strings.HasPrefix(h, "$ml$"):
		return []Candidate{{"macOS 10.8+ PBKDF2-SHA512", "7100", "PBKDF2-HMAC-SHA512", "certain"}}
	case strings.HasPrefix(h, "0x0100"):
		return []Candidate{{"MSSQL 2005 (SHA-1)", "132", "mssql05", "certain"}}
	case strings.HasPrefix(h, "0x0200"):
		return []Candidate{{"MSSQL 2012/2014 (SHA-512)", "1731", "mssql12", "certain"}}
	case isMySQL41(h):
		return []Candidate{{"MySQL 4.1+/5.x (SHA-1(SHA-1(pass)))", "300", "mysql-sha1", "certain"}}
	}
	return nil
}

// identifyHexByLength returns ranked candidates for a plain hex digest.
func identifyHexByLength(n int) []Candidate {
	switch n {
	case 8:
		return []Candidate{
			{"CRC-32", "11500", "", "possible"},
			{"Adler-32", "", "", "possible"},
		}
	case 16:
		return []Candidate{
			{"MySQL323 (pre-4.1)", "200", "mysql", "probable"},
			{"DES(Unix) / crypt", "1500", "descrypt", "possible"},
			{"Half MD5", "5100", "", "possible"},
		}
	case 32:
		return []Candidate{
			{"MD5", "0", "raw-md5", "probable"},
			{"NTLM", "1000", "nt", "probable"},
			{"MD4", "900", "raw-md4", "possible"},
			{"Double MD5 (md5(md5($p)))", "2600", "", "possible"},
			{"LM (if uppercase)", "3000", "lm", "possible"},
			{"RIPEMD-128 / Tiger-128 / Haval-128", "", "", "possible"},
		}
	case 40:
		return []Candidate{
			{"SHA-1", "100", "raw-sha1", "probable"},
			{"MySQL 4.1+ (unprefixed)", "300", "mysql-sha1", "possible"},
			{"RIPEMD-160", "6000", "ripemd-160", "possible"},
			{"SHA-0 / Tiger-160 / Haval-160", "", "", "possible"},
		}
	case 56:
		return []Candidate{
			{"SHA-224", "1300", "raw-sha224", "probable"},
			{"SHA3-224", "17300", "", "possible"},
			{"Keccak-224", "17700", "", "possible"},
		}
	case 64:
		return []Candidate{
			{"SHA-256", "1400", "raw-sha256", "probable"},
			{"SHA3-256", "17400", "", "possible"},
			{"Keccak-256", "17800", "", "possible"},
			{"BLAKE2b-256 / RIPEMD-256 / GOST", "", "", "possible"},
		}
	case 96:
		return []Candidate{
			{"SHA-384", "10800", "raw-sha384", "probable"},
			{"SHA3-384", "17500", "", "possible"},
			{"Keccak-384", "17900", "", "possible"},
		}
	case 128:
		return []Candidate{
			{"SHA-512", "1700", "raw-sha512", "probable"},
			{"SHA3-512", "17600", "", "possible"},
			{"Keccak-512", "18000", "", "possible"},
			{"Whirlpool / BLAKE2b-512", "6100", "whirlpool", "possible"},
		}
	default:
		return nil
	}
}

// crackableByLength mirrors the historical length->algorithm mapping and only
// lists algorithms the built-in wordlist cracker can compute.
func crackableByLength(n int) []Algorithm {
	switch n {
	case 32:
		return []Algorithm{AlgoMD5}
	case 40:
		return []Algorithm{AlgoSHA1}
	case 64:
		return []Algorithm{AlgoSHA256, AlgoBlake2}
	case 128:
		return []Algorithm{AlgoSHA512}
	default:
		return nil
	}
}

// identifyNonHex handles non-hex inputs such as base64 digests and JWTs.
func identifyNonHex(h string) []Candidate {
	if strings.Count(h, ".") == 2 && strings.HasPrefix(h, "eyJ") {
		return []Candidate{{"JWT (JSON Web Token) — try: raxuiscli jwt decode", "", "", "probable"}}
	}
	if isBase64ish(h) {
		switch len(h) {
		case 28: // 20 bytes -> SHA-1
			return []Candidate{{"Base64 SHA-1 digest", "", "", "possible"}}
		case 44: // 32 bytes -> SHA-256
			return []Candidate{{"Base64 SHA-256 digest", "", "", "possible"}}
		default:
			return []Candidate{{"Base64-encoded hash (Net-NTLMv2, salted digest, ...)", "", "", "possible"}}
		}
	}
	return nil
}

// isMySQL41 matches the MySQL 4.1+ "*" + 40 hex uppercase form.
func isMySQL41(s string) bool {
	if len(s) != 41 || s[0] != '*' {
		return false
	}
	return isValidHex(strings.ToLower(s[1:]))
}

var base64Re = regexp.MustCompile(`^[A-Za-z0-9+/_-]+={0,2}$`)

// isBase64ish reports whether s looks like a base64/base64url token.
func isBase64ish(s string) bool {
	return len(s) >= 8 && base64Re.MatchString(s)
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
