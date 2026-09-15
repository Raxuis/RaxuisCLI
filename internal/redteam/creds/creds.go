package creds

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
)

// Credential represents a parsed credential
type Credential struct {
	Username string
	Password string
	Domain   string
	Hash     string
	HashType string
	Email    string
	Source   string
	Line     int
}

// ExtractResult holds extraction results
type ExtractResult struct {
	Credentials []Credential
	Hashes      []HashEntry
	Emails      []string
	URLs        []string
	Stats       ExtractStats
}

// HashEntry represents a hash with metadata
type HashEntry struct {
	Hash     string
	Type     string
	Username string
	Source   string
}

// ExtractStats holds statistics
type ExtractStats struct {
	TotalLines  int
	Credentials int
	Hashes      int
	Emails      int
	URLs        int
}

// Patterns for credential extraction
var (
	// user:pass patterns
	UserPassPattern = regexp.MustCompile(`^([^:@\s]+):([^:@\s]+)$`)

	// user:pass@domain patterns
	UserPassDomainPattern = regexp.MustCompile(`^([^:@\s]+):([^:@\s]+)@([^:@\s]+)$`)

	// email:pass patterns
	EmailPassPattern = regexp.MustCompile(`^([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}):(.+)$`)

	// domain\user:pass patterns
	DomainUserPassPattern = regexp.MustCompile(`^([^\\]+)\\([^:]+):(.+)$`)

	// Hash patterns
	MD5Pattern    = regexp.MustCompile(`^[a-fA-F0-9]{32}$`)
	SHA1Pattern   = regexp.MustCompile(`^[a-fA-F0-9]{40}$`)
	SHA256Pattern = regexp.MustCompile(`^[a-fA-F0-9]{64}$`)
	SHA512Pattern = regexp.MustCompile(`^[a-fA-F0-9]{128}$`)
	NTLMPattern   = regexp.MustCompile(`^[a-fA-F0-9]{32}$`)
	BCryptPattern = regexp.MustCompile(`^\$2[ayb]\$.{56}$`)

	// NTLM hash dump patterns (user:uid:lmhash:nthash:::)
	NTLMDumpPattern = regexp.MustCompile(`^([^:]+):\d+:([a-fA-F0-9]{32}):([a-fA-F0-9]{32}):::$`)

	// /etc/shadow pattern
	ShadowPattern = regexp.MustCompile(`^([^:]+):(\$[0-9a-z]+\$[^:]+):`)

	// Email pattern
	EmailPattern = regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)

	// URL pattern
	URLPattern = regexp.MustCompile(`https?://[^\s<>"']+`)
)

// ExtractFromFile extracts credentials from a file
func ExtractFromFile(path string) (*ExtractResult, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	result := &ExtractResult{}
	seenCreds := make(map[string]bool)
	seenHashes := make(map[string]bool)
	seenEmails := make(map[string]bool)
	seenURLs := make(map[string]bool)

	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		result.Stats.TotalLines++

		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Try to parse as credential
		if cred := parseLine(line, lineNum); cred != nil {
			key := cred.Username + ":" + cred.Password + ":" + cred.Domain
			if !seenCreds[key] {
				seenCreds[key] = true
				cred.Source = path
				result.Credentials = append(result.Credentials, *cred)
				result.Stats.Credentials++
			}
		}

		// Try to extract hashes
		hashes := extractHashes(line, path)
		for _, h := range hashes {
			if !seenHashes[h.Hash] {
				seenHashes[h.Hash] = true
				result.Hashes = append(result.Hashes, h)
				result.Stats.Hashes++
			}
		}

		// Extract emails
		emails := EmailPattern.FindAllString(line, -1)
		for _, email := range emails {
			email = strings.ToLower(email)
			if !seenEmails[email] {
				seenEmails[email] = true
				result.Emails = append(result.Emails, email)
				result.Stats.Emails++
			}
		}

		// Extract URLs
		urls := URLPattern.FindAllString(line, -1)
		for _, u := range urls {
			if !seenURLs[u] {
				seenURLs[u] = true
				result.URLs = append(result.URLs, u)
				result.Stats.URLs++
			}
		}
	}

	return result, scanner.Err()
}

// parseLine parses a single line for credentials
func parseLine(line string, lineNum int) *Credential {
	cred := &Credential{Line: lineNum}

	// Try NTLM dump format
	if matches := NTLMDumpPattern.FindStringSubmatch(line); len(matches) == 4 {
		cred.Username = matches[1]
		cred.Hash = matches[3] // NT hash
		cred.HashType = "NTLM"
		return cred
	}

	// Try shadow format
	if matches := ShadowPattern.FindStringSubmatch(line); len(matches) == 3 {
		cred.Username = matches[1]
		cred.Hash = matches[2]
		cred.HashType = identifyShadowHash(matches[2])
		return cred
	}

	// Try domain\user:pass
	if matches := DomainUserPassPattern.FindStringSubmatch(line); len(matches) == 4 {
		cred.Domain = matches[1]
		cred.Username = matches[2]
		cred.Password = matches[3]
		return cred
	}

	// Try email:pass
	if matches := EmailPassPattern.FindStringSubmatch(line); len(matches) == 3 {
		cred.Email = matches[1]
		cred.Username = strings.Split(matches[1], "@")[0]
		cred.Password = matches[2]
		return cred
	}

	// Try user:pass@domain
	if matches := UserPassDomainPattern.FindStringSubmatch(line); len(matches) == 4 {
		cred.Username = matches[1]
		cred.Password = matches[2]
		cred.Domain = matches[3]
		return cred
	}

	// Try user:pass
	if matches := UserPassPattern.FindStringSubmatch(line); len(matches) == 3 {
		cred.Username = matches[1]
		cred.Password = matches[2]
		return cred
	}

	return nil
}

// extractHashes extracts hash values from a line
func extractHashes(line, source string) []HashEntry {
	var hashes []HashEntry

	// Check for standalone hashes
	words := strings.Fields(line)
	for _, word := range words {
		word = strings.Trim(word, "\"'`[](){}")

		if hashType := identifyHash(word); hashType != "" {
			hashes = append(hashes, HashEntry{
				Hash:   word,
				Type:   hashType,
				Source: source,
			})
		}
	}

	// Check for user:hash patterns
	if strings.Contains(line, ":") {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			hash := strings.TrimSpace(parts[1])
			if hashType := identifyHash(hash); hashType != "" {
				hashes = append(hashes, HashEntry{
					Hash:     hash,
					Type:     hashType,
					Username: strings.TrimSpace(parts[0]),
					Source:   source,
				})
			}
		}
	}

	return hashes
}

// identifyHash identifies the hash type
func identifyHash(s string) string {
	s = strings.TrimSpace(s)

	if BCryptPattern.MatchString(s) {
		return "bcrypt"
	}
	if strings.HasPrefix(s, "$") {
		return identifyShadowHash(s)
	}

	switch len(s) {
	case 32:
		if MD5Pattern.MatchString(s) {
			return "MD5/NTLM"
		}
	case 40:
		if SHA1Pattern.MatchString(s) {
			return "SHA1"
		}
	case 64:
		if SHA256Pattern.MatchString(s) {
			return "SHA256"
		}
	case 128:
		if SHA512Pattern.MatchString(s) {
			return "SHA512"
		}
	}

	return ""
}

// identifyShadowHash identifies shadow file hash type
func identifyShadowHash(hash string) string {
	if strings.HasPrefix(hash, "$1$") {
		return "MD5crypt"
	}
	if strings.HasPrefix(hash, "$5$") {
		return "SHA256crypt"
	}
	if strings.HasPrefix(hash, "$6$") {
		return "SHA512crypt"
	}
	if strings.HasPrefix(hash, "$2a$") || strings.HasPrefix(hash, "$2b$") || strings.HasPrefix(hash, "$2y$") {
		return "bcrypt"
	}
	if strings.HasPrefix(hash, "$y$") {
		return "yescrypt"
	}
	return "unknown"
}

// ConvertFormat converts credentials between formats
func ConvertFormat(creds []Credential, format string) []string {
	var output []string

	for _, cred := range creds {
		var line string

		switch format {
		case "userpass":
			if cred.Password != "" {
				line = fmt.Sprintf("%s:%s", cred.Username, cred.Password)
			}
		case "user":
			line = cred.Username
		case "pass":
			if cred.Password != "" {
				line = cred.Password
			}
		case "email":
			if cred.Email != "" {
				line = cred.Email
			}
		case "emailpass":
			if cred.Email != "" && cred.Password != "" {
				line = fmt.Sprintf("%s:%s", cred.Email, cred.Password)
			}
		case "domain":
			if cred.Domain != "" && cred.Username != "" && cred.Password != "" {
				line = fmt.Sprintf("%s\\%s:%s", cred.Domain, cred.Username, cred.Password)
			}
		case "hash":
			if cred.Hash != "" {
				line = fmt.Sprintf("%s:%s", cred.Username, cred.Hash)
			}
		case "hashcat":
			if cred.Hash != "" {
				line = cred.Hash
			}
		case "john":
			if cred.Hash != "" {
				line = fmt.Sprintf("%s:%s", cred.Username, cred.Hash)
			}
		default:
			line = fmt.Sprintf("%s:%s", cred.Username, cred.Password)
		}

		if line != "" {
			output = append(output, line)
		}
	}

	return output
}

// DecodeCredential attempts to decode an encoded credential
func DecodeCredential(encoded string) []DecodedResult {
	var results []DecodedResult

	// Try Base64
	if decoded, err := base64.StdEncoding.DecodeString(encoded); err == nil {
		if isPrintable(decoded) {
			results = append(results, DecodedResult{
				Method: "Base64",
				Value:  string(decoded),
			})
		}
	}

	// Try Base64 URL-safe
	if decoded, err := base64.URLEncoding.DecodeString(encoded); err == nil {
		if isPrintable(decoded) {
			results = append(results, DecodedResult{
				Method: "Base64-URL",
				Value:  string(decoded),
			})
		}
	}

	// Try URL decode
	if decoded, err := url.QueryUnescape(encoded); err == nil && decoded != encoded {
		results = append(results, DecodedResult{
			Method: "URL",
			Value:  decoded,
		})
	}

	// Try Hex
	if decoded, err := hex.DecodeString(encoded); err == nil {
		if isPrintable(decoded) {
			results = append(results, DecodedResult{
				Method: "Hex",
				Value:  string(decoded),
			})
		}
	}

	return results
}

// DecodedResult holds a decoded value
type DecodedResult struct {
	Method string
	Value  string
}

// isPrintable checks if bytes are printable
func isPrintable(data []byte) bool {
	for _, b := range data {
		if b < 32 || b > 126 {
			if b != '\n' && b != '\r' && b != '\t' {
				return false
			}
		}
	}
	return true
}

// GenerateCombo generates credential combinations
func GenerateCombo(users, passwords []string, domain string) []Credential {
	var creds []Credential

	for _, user := range users {
		for _, pass := range passwords {
			cred := Credential{
				Username: strings.TrimSpace(user),
				Password: strings.TrimSpace(pass),
				Domain:   domain,
			}
			creds = append(creds, cred)
		}
	}

	return creds
}

// MergeDedupe merges and deduplicates credentials
func MergeDedupe(credSets ...[]Credential) []Credential {
	seen := make(map[string]bool)
	var result []Credential

	for _, set := range credSets {
		for _, cred := range set {
			key := strings.ToLower(cred.Username + ":" + cred.Password + ":" + cred.Domain)
			if !seen[key] {
				seen[key] = true
				result = append(result, cred)
			}
		}
	}

	// Sort by username
	sort.Slice(result, func(i, j int) bool {
		return result[i].Username < result[j].Username
	})

	return result
}

// FilterByDomain filters credentials by domain
func FilterByDomain(creds []Credential, domain string) []Credential {
	var result []Credential
	domain = strings.ToLower(domain)

	for _, cred := range creds {
		if strings.ToLower(cred.Domain) == domain || cred.Domain == "" {
			result = append(result, cred)
		}
	}

	return result
}

// DisplayResult displays extraction results
func DisplayResult(result *ExtractResult, showAll bool) {
	fmt.Fprintln(stdoutW, "\n[CREDENTIAL EXTRACTION RESULTS]")
	fmt.Fprintln(stdoutW, strings.Repeat("=", 60))

	fmt.Fprintf(stdoutW, "\nStatistics:\n")
	fmt.Fprintf(stdoutW, "  Lines processed: %d\n", result.Stats.TotalLines)
	fmt.Fprintf(stdoutW, "  Credentials:     %d\n", result.Stats.Credentials)
	fmt.Fprintf(stdoutW, "  Hashes:          %d\n", result.Stats.Hashes)
	fmt.Fprintf(stdoutW, "  Emails:          %d\n", result.Stats.Emails)
	fmt.Fprintf(stdoutW, "  URLs:            %d\n", result.Stats.URLs)

	if len(result.Credentials) > 0 {
		fmt.Fprintln(stdoutW, "\n--- Credentials ---")
		limit := 20
		if showAll {
			limit = len(result.Credentials)
		}
		for i, cred := range result.Credentials {
			if i >= limit {
				fmt.Fprintf(stdoutW, "  ... and %d more\n", len(result.Credentials)-limit)
				break
			}
			displayCred(cred)
		}
	}

	if len(result.Hashes) > 0 {
		fmt.Fprintln(stdoutW, "\n--- Hashes ---")
		limit := 10
		if showAll {
			limit = len(result.Hashes)
		}
		for i, hash := range result.Hashes {
			if i >= limit {
				fmt.Fprintf(stdoutW, "  ... and %d more\n", len(result.Hashes)-limit)
				break
			}
			fmt.Fprintf(stdoutW, "  [%s] %s", hash.Type, truncateHash(hash.Hash))
			if hash.Username != "" {
				fmt.Fprintf(stdoutW, " (user: %s)", hash.Username)
			}
			fmt.Fprintln(stdoutW)
		}
	}

	if len(result.Emails) > 0 && showAll {
		fmt.Fprintln(stdoutW, "\n--- Emails ---")
		for _, email := range result.Emails {
			fmt.Fprintf(stdoutW, "  %s\n", email)
		}
	}

	fmt.Fprintln(stdoutW)
}

func displayCred(cred Credential) {
	if cred.Domain != "" {
		fmt.Fprintf(stdoutW, "  %s\\%s:%s\n", cred.Domain, cred.Username, maskPassword(cred.Password))
	} else if cred.Email != "" {
		fmt.Fprintf(stdoutW, "  %s:%s\n", cred.Email, maskPassword(cred.Password))
	} else if cred.Hash != "" {
		fmt.Fprintf(stdoutW, "  %s:%s [%s]\n", cred.Username, truncateHash(cred.Hash), cred.HashType)
	} else {
		fmt.Fprintf(stdoutW, "  %s:%s\n", cred.Username, maskPassword(cred.Password))
	}
}

func maskPassword(pass string) string {
	if len(pass) <= 2 {
		return "***"
	}
	return pass[:1] + strings.Repeat("*", len(pass)-2) + pass[len(pass)-1:]
}

func truncateHash(hash string) string {
	if len(hash) > 20 {
		return hash[:10] + "..." + hash[len(hash)-6:]
	}
	return hash
}

// WriteToFile writes credentials to a file
func WriteToFile(lines []string, path string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	for _, line := range lines {
		fmt.Fprintln(file, line)
	}

	return nil
}
