package obfuscate

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/rand"
	"strings"
	"unicode"
)

// ObfuscationType represents the type of obfuscation
type ObfuscationType string

const (
	TypePowerShell ObfuscationType = "powershell"
	TypeBash       ObfuscationType = "bash"
	TypePython     ObfuscationType = "python"
	TypeString     ObfuscationType = "string"
	TypeShellcode  ObfuscationType = "shellcode"
)

// ObfuscationResult holds the result of obfuscation
type ObfuscationResult struct {
	Original   string
	Obfuscated string
	Method     string
	Encoded    bool
}

// ObfuscatePowerShell obfuscates PowerShell code
func ObfuscatePowerShell(code string, level int) *ObfuscationResult {
	result := &ObfuscationResult{
		Original: code,
		Method:   "PowerShell",
	}

	obfuscated := code

	// Level 1: Variable renaming and string splitting
	if level >= 1 {
		obfuscated = psStringObfuscate(obfuscated)
	}

	// Level 2: Base64 encoding with IEX
	if level >= 2 {
		encoded := base64.StdEncoding.EncodeToString([]byte(obfuscated))
		obfuscated = fmt.Sprintf("IEX([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('%s')))", encoded)
		result.Encoded = true
	}

	// Level 3: Random case and tick insertion
	if level >= 3 {
		obfuscated = psRandomCase(obfuscated)
		obfuscated = psTickObfuscate(obfuscated)
	}

	result.Obfuscated = obfuscated
	return result
}

// psStringObfuscate splits strings in PowerShell
func psStringObfuscate(code string) string {
	// Simple implementation: wrap strings in concatenation
	// Example: "Hello" -> ('He'+'llo')
	var result strings.Builder
	inString := false
	var currentString strings.Builder

	for _, char := range code {
		if char == '"' || char == '\'' {
			if inString {
				// End of string, obfuscate it
				str := currentString.String()
				if len(str) > 4 {
					mid := len(str) / 2
					result.WriteString(fmt.Sprintf("('%s'+'%s')", str[:mid], str[mid:]))
				} else {
					result.WriteRune(char)
					result.WriteString(str)
					result.WriteRune(char)
				}
				currentString.Reset()
			}
			inString = !inString
		} else if inString {
			currentString.WriteRune(char)
		} else {
			result.WriteRune(char)
		}
	}

	if currentString.Len() > 0 {
		result.WriteString(currentString.String())
	}

	return result.String()
}

// psRandomCase applies random casing to PowerShell keywords
func psRandomCase(code string) string {
	var result strings.Builder

	for _, char := range code {
		if unicode.IsLetter(char) {
			if rand.Intn(2) == 0 {
				result.WriteRune(unicode.ToUpper(char))
			} else {
				result.WriteRune(unicode.ToLower(char))
			}
		} else {
			result.WriteRune(char)
		}
	}

	return result.String()
}

// psTickObfuscate inserts backticks into PowerShell code
func psTickObfuscate(code string) string {
	// Insert backticks before certain characters
	// This is valid in PowerShell and helps evade detection
	chars := []string{"e", "i", "a", "o", "n", "t", "r"}

	result := code
	for _, char := range chars {
		if rand.Intn(3) == 0 {
			result = strings.ReplaceAll(result, char, "`"+char)
		}
	}

	return result
}

// ObfuscateBash obfuscates Bash commands
func ObfuscateBash(code string, level int) *ObfuscationResult {
	result := &ObfuscationResult{
		Original: code,
		Method:   "Bash",
	}

	obfuscated := code

	// Level 1: Variable substitution
	if level >= 1 {
		obfuscated = bashVariableObfuscate(obfuscated)
	}

	// Level 2: Base64 encoding
	if level >= 2 {
		encoded := base64.StdEncoding.EncodeToString([]byte(obfuscated))
		obfuscated = fmt.Sprintf("echo %s | base64 -d | bash", encoded)
		result.Encoded = true
	}

	// Level 3: Hex encoding
	if level >= 3 {
		// Use $'...' with hex
		obfuscated = bashHexObfuscate(code)
	}

	result.Obfuscated = obfuscated
	return result
}

// bashVariableObfuscate uses variable substitution
func bashVariableObfuscate(code string) string {
	// Replace common commands with variables
	replacements := map[string]string{
		"curl":  "${c}${u}${r}${l}",
		"wget":  "${w}${g}${e}${t}",
		"bash":  "${b}${a}${s}${h}",
		"sh":    "${s}${h}",
		"nc":    "${n}${c}",
		"cat":   "${c}${a}${t}",
		"chmod": "${c}${h}${m}${o}${d}",
	}

	result := code
	var setup strings.Builder
	setup.WriteString("c=c;u=u;r=r;l=l;w=w;g=g;e=e;t=t;b=b;a=a;s=s;h=h;n=n;m=m;o=o;d=d;")

	for cmd, repl := range replacements {
		if strings.Contains(result, cmd) {
			result = strings.ReplaceAll(result, cmd, repl)
		}
	}

	if result != code {
		return setup.String() + result
	}
	return code
}

// bashHexObfuscate converts to hex representation
func bashHexObfuscate(code string) string {
	var hex strings.Builder
	hex.WriteString("$'")
	for _, b := range []byte(code) {
		hex.WriteString(fmt.Sprintf("\\x%02x", b))
	}
	hex.WriteString("'")
	return fmt.Sprintf("echo -e %s | bash", hex.String())
}

// ObfuscateString obfuscates a string using various methods
func ObfuscateString(s string, method string) *ObfuscationResult {
	result := &ObfuscationResult{
		Original: s,
		Method:   method,
	}

	switch method {
	case "reverse":
		runes := []rune(s)
		for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
			runes[i], runes[j] = runes[j], runes[i]
		}
		result.Obfuscated = string(runes)

	case "rot13":
		result.Obfuscated = rot13(s)

	case "base64":
		result.Obfuscated = base64.StdEncoding.EncodeToString([]byte(s))
		result.Encoded = true

	case "hex":
		result.Obfuscated = hex.EncodeToString([]byte(s))
		result.Encoded = true

	case "unicode":
		var buf strings.Builder
		for _, r := range s {
			buf.WriteString(fmt.Sprintf("\\u%04x", r))
		}
		result.Obfuscated = buf.String()

	case "decimal":
		var parts []string
		for _, b := range []byte(s) {
			parts = append(parts, fmt.Sprintf("%d", b))
		}
		result.Obfuscated = strings.Join(parts, ",")

	case "xor":
		key := byte(rand.Intn(255) + 1)
		var buf bytes.Buffer
		for _, b := range []byte(s) {
			buf.WriteByte(b ^ key)
		}
		result.Obfuscated = fmt.Sprintf("key=%d;data=%s", key, hex.EncodeToString(buf.Bytes()))
		result.Encoded = true

	default:
		result.Obfuscated = s
	}

	return result
}

// rot13 applies ROT13 cipher
func rot13(s string) string {
	var result strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
			result.WriteRune('a' + (r-'a'+13)%26)
		case r >= 'A' && r <= 'Z':
			result.WriteRune('A' + (r-'A'+13)%26)
		default:
			result.WriteRune(r)
		}
	}
	return result.String()
}

// ObfuscateShellcode obfuscates shellcode
func ObfuscateShellcode(shellcode []byte, method string) *ObfuscationResult {
	result := &ObfuscationResult{
		Original: hex.EncodeToString(shellcode),
		Method:   method,
		Encoded:  true,
	}

	switch method {
	case "xor":
		key := byte(rand.Intn(255) + 1)
		obfuscated := make([]byte, len(shellcode))
		for i, b := range shellcode {
			obfuscated[i] = b ^ key
		}
		result.Obfuscated = fmt.Sprintf("// XOR key: 0x%02x\n%s", key, formatCArray(obfuscated))

	case "base64":
		result.Obfuscated = base64.StdEncoding.EncodeToString(shellcode)

	case "uuid":
		// Format as UUIDs for APC injection
		result.Obfuscated = formatAsUUID(shellcode)

	case "ipv4":
		// Format as IPv4 addresses
		result.Obfuscated = formatAsIPv4(shellcode)

	case "mac":
		// Format as MAC addresses
		result.Obfuscated = formatAsMAC(shellcode)

	case "c-array":
		result.Obfuscated = formatCArray(shellcode)

	default:
		result.Obfuscated = hex.EncodeToString(shellcode)
	}

	return result
}

// formatCArray formats bytes as C array
func formatCArray(data []byte) string {
	var buf strings.Builder
	buf.WriteString("unsigned char buf[] = {\n    ")

	for i, b := range data {
		buf.WriteString(fmt.Sprintf("0x%02x", b))
		if i < len(data)-1 {
			buf.WriteString(", ")
		}
		if (i+1)%12 == 0 && i < len(data)-1 {
			buf.WriteString("\n    ")
		}
	}

	buf.WriteString("\n};")
	return buf.String()
}

// formatAsUUID formats bytes as UUIDs
func formatAsUUID(data []byte) string {
	var uuids []string

	// Pad to multiple of 16
	padded := make([]byte, ((len(data)+15)/16)*16)
	copy(padded, data)

	for i := 0; i < len(padded); i += 16 {
		uuid := fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
			padded[i:i+4],
			padded[i+4:i+6],
			padded[i+6:i+8],
			padded[i+8:i+10],
			padded[i+10:i+16])
		uuids = append(uuids, fmt.Sprintf("\"%s\"", uuid))
	}

	return "const char* uuids[] = {\n    " + strings.Join(uuids, ",\n    ") + "\n};"
}

// formatAsIPv4 formats bytes as IPv4 addresses
func formatAsIPv4(data []byte) string {
	var ips []string

	// Pad to multiple of 4
	padded := make([]byte, ((len(data)+3)/4)*4)
	copy(padded, data)

	for i := 0; i < len(padded); i += 4 {
		ip := fmt.Sprintf("\"%d.%d.%d.%d\"", padded[i], padded[i+1], padded[i+2], padded[i+3])
		ips = append(ips, ip)
	}

	return "const char* ips[] = {\n    " + strings.Join(ips, ",\n    ") + "\n};"
}

// formatAsMAC formats bytes as MAC addresses
func formatAsMAC(data []byte) string {
	var macs []string

	// Pad to multiple of 6
	padded := make([]byte, ((len(data)+5)/6)*6)
	copy(padded, data)

	for i := 0; i < len(padded); i += 6 {
		mac := fmt.Sprintf("\"%02X-%02X-%02X-%02X-%02X-%02X\"",
			padded[i], padded[i+1], padded[i+2],
			padded[i+3], padded[i+4], padded[i+5])
		macs = append(macs, mac)
	}

	return "const char* macs[] = {\n    " + strings.Join(macs, ",\n    ") + "\n};"
}

// DisplayResult displays obfuscation result
func DisplayResult(result *ObfuscationResult) {
	fmt.Printf("\n[OBFUSCATE] %s\n", result.Method)
	fmt.Println(strings.Repeat("=", 60))

	fmt.Println("\nOriginal:")
	if len(result.Original) > 200 {
		fmt.Printf("  %s... (%d bytes)\n", result.Original[:200], len(result.Original))
	} else {
		fmt.Printf("  %s\n", result.Original)
	}

	fmt.Println("\nObfuscated:")
	if len(result.Obfuscated) > 500 {
		fmt.Printf("  %s... (%d bytes)\n", result.Obfuscated[:500], len(result.Obfuscated))
	} else {
		fmt.Printf("  %s\n", result.Obfuscated)
	}

	if result.Encoded {
		fmt.Println("\n[*] Output is encoded")
	}

	fmt.Println()
}
