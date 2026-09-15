package obfuscate

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"os"
	"strings"
	"testing"
)

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}
	os.Stdout = w
	stdoutW = w
	fn()
	w.Close()
	os.Stdout = orig
	stdoutW = orig
	var buf bytes.Buffer
	buf.ReadFrom(r)
	return buf.String()
}

func TestObfuscatePowerShellLevels(t *testing.T) {
	code := `Write-Host "Hello World"`

	for level := 1; level <= 3; level++ {
		result := ObfuscatePowerShell(code, level)
		if result.Original != code {
			t.Errorf("level %d: Original = %q, want %q", level, result.Original, code)
		}
		if result.Obfuscated == "" {
			t.Errorf("level %d: Obfuscated should not be empty", level)
		}
	}
}

func TestObfuscatePowerShellLevel2IsBase64EncodedIEX(t *testing.T) {
	code := "whoami"
	result := ObfuscatePowerShell(code, 2)
	if !result.Encoded {
		t.Error("level 2 should set Encoded=true")
	}
	if !strings.Contains(result.Obfuscated, "IEX(") {
		t.Errorf("level 2 output should wrap in IEX(...), got: %s", result.Obfuscated)
	}
	if !strings.Contains(result.Obfuscated, "FromBase64String") {
		t.Errorf("level 2 output should reference FromBase64String, got: %s", result.Obfuscated)
	}
}

func TestObfuscateBashLevels(t *testing.T) {
	code := "curl http://example.com"
	for level := 1; level <= 3; level++ {
		result := ObfuscateBash(code, level)
		if result.Obfuscated == "" {
			t.Errorf("level %d: Obfuscated should not be empty", level)
		}
	}
}

func TestObfuscateBashLevel1VariableSubstitution(t *testing.T) {
	result := ObfuscateBash("curl http://x", 1)
	if strings.Contains(result.Obfuscated, "curl ") {
		t.Errorf("level 1 should replace 'curl' with variable substitution, got: %s", result.Obfuscated)
	}
	if !strings.Contains(result.Obfuscated, "${c}${u}${r}${l}") {
		t.Errorf("expected curl to become ${c}${u}${r}${l}, got: %s", result.Obfuscated)
	}
}

func TestObfuscateBashLevel1NoMatchingCommand(t *testing.T) {
	result := ObfuscateBash("echo hello", 1)
	if result.Obfuscated != "echo hello" {
		t.Errorf("with no replaceable command, output should be unchanged, got: %s", result.Obfuscated)
	}
}

func TestObfuscateBashLevel2Base64(t *testing.T) {
	result := ObfuscateBash("whoami", 2)
	if !result.Encoded {
		t.Error("level 2 should set Encoded=true")
	}
	if !strings.Contains(result.Obfuscated, "base64 -d") {
		t.Errorf("level 2 output should decode via base64, got: %s", result.Obfuscated)
	}
}

func TestObfuscateBashLevel3Hex(t *testing.T) {
	result := ObfuscateBash("id", 3)
	if !strings.Contains(result.Obfuscated, `\x69\x64`) { // hex for "id"
		t.Errorf("level 3 output should hex-encode the original code, got: %s", result.Obfuscated)
	}
}

func TestObfuscateStringMethods(t *testing.T) {
	s := "Hello"

	if got := ObfuscateString(s, "reverse").Obfuscated; got != "olleH" {
		t.Errorf("reverse = %q, want olleH", got)
	}

	rot := ObfuscateString(s, "rot13").Obfuscated
	if rot == s {
		t.Error("rot13 output should differ from input")
	}
	if back := ObfuscateString(rot, "rot13").Obfuscated; back != s {
		t.Errorf("rot13 applied twice = %q, want %q", back, s)
	}

	b64 := ObfuscateString(s, "base64")
	if !b64.Encoded {
		t.Error("base64 method should set Encoded=true")
	}
	if decoded, err := base64.StdEncoding.DecodeString(b64.Obfuscated); err != nil || string(decoded) != s {
		t.Errorf("base64 output %q does not decode back to %q", b64.Obfuscated, s)
	}

	hexResult := ObfuscateString(s, "hex")
	if !hexResult.Encoded {
		t.Error("hex method should set Encoded=true")
	}
	if decoded, err := hex.DecodeString(hexResult.Obfuscated); err != nil || string(decoded) != s {
		t.Errorf("hex output %q does not decode back to %q", hexResult.Obfuscated, s)
	}

	unicodeResult := ObfuscateString(s, "unicode").Obfuscated
	wantEscape := "\\u0048" // 'H' (0x48) as the obfuscator's \uXXXX escape
	if !strings.Contains(unicodeResult, wantEscape) {
		t.Errorf("unicode output missing expected escape %q, got: %s", wantEscape, unicodeResult)
	}

	decimalResult := ObfuscateString(s, "decimal").Obfuscated
	if decimalResult != "72,101,108,108,111" {
		t.Errorf("decimal = %q, want 72,101,108,108,111", decimalResult)
	}

	xorResult := ObfuscateString(s, "xor")
	if !xorResult.Encoded {
		t.Error("xor method should set Encoded=true")
	}
	if !strings.HasPrefix(xorResult.Obfuscated, "key=") {
		t.Errorf("xor output should start with key=, got: %s", xorResult.Obfuscated)
	}

	unknown := ObfuscateString(s, "not-a-real-method")
	if unknown.Obfuscated != s {
		t.Errorf("unknown method should pass the string through unchanged, got %q", unknown.Obfuscated)
	}
}

func TestObfuscateShellcodeMethods(t *testing.T) {
	shellcode := []byte{0x90, 0x90, 0xCC, 0x31, 0xC0}

	tests := []string{"xor", "base64", "uuid", "ipv4", "mac", "c-array", "unknown-method"}
	for _, method := range tests {
		result := ObfuscateShellcode(shellcode, method)
		if result.Obfuscated == "" {
			t.Errorf("method %q: Obfuscated should not be empty", method)
		}
		if result.Original != hex.EncodeToString(shellcode) {
			t.Errorf("method %q: Original = %q, want hex-encoded shellcode", method, result.Original)
		}
	}
}

func TestObfuscateShellcodeBase64RoundTrip(t *testing.T) {
	shellcode := []byte{0x01, 0x02, 0x03, 0x04}
	result := ObfuscateShellcode(shellcode, "base64")
	decoded, err := base64.StdEncoding.DecodeString(result.Obfuscated)
	if err != nil || string(decoded) != string(shellcode) {
		t.Errorf("base64 shellcode obfuscation did not round-trip: %q", result.Obfuscated)
	}
}

func TestFormatCArray(t *testing.T) {
	out := formatCArray([]byte{0xDE, 0xAD, 0xBE, 0xEF})
	if !strings.Contains(out, "0xde") || !strings.Contains(out, "0xef") {
		t.Errorf("formatCArray output missing expected bytes: %s", out)
	}
}

func TestFormatAsUUIDPadding(t *testing.T) {
	// 5 bytes, not a multiple of 16 - should still produce one UUID (padded).
	out := formatAsUUID([]byte{1, 2, 3, 4, 5})
	if !strings.Contains(out, "uuids[]") {
		t.Errorf("formatAsUUID output malformed: %s", out)
	}
}

func TestFormatAsIPv4Padding(t *testing.T) {
	out := formatAsIPv4([]byte{1, 2, 3, 4, 5})
	if !strings.Contains(out, "ips[]") {
		t.Errorf("formatAsIPv4 output malformed: %s", out)
	}
}

func TestFormatAsMACPadding(t *testing.T) {
	out := formatAsMAC([]byte{1, 2, 3, 4, 5, 6, 7})
	if !strings.Contains(out, "macs[]") {
		t.Errorf("formatAsMAC output malformed: %s", out)
	}
}

func TestDisplayResultShortAndLong(t *testing.T) {
	short := &ObfuscationResult{Original: "short", Obfuscated: "short-obf", Method: "test"}
	out := captureStdout(t, func() { DisplayResult(short) })
	if !strings.Contains(out, "short") {
		t.Errorf("DisplayResult output missing original text: %s", out)
	}

	long := &ObfuscationResult{
		Original:   strings.Repeat("a", 300),
		Obfuscated: strings.Repeat("b", 600),
		Method:     "test",
		Encoded:    true,
	}
	out = captureStdout(t, func() { DisplayResult(long) })
	if !strings.Contains(out, "...") {
		t.Errorf("DisplayResult should truncate long original/obfuscated text: %s", out)
	}
	if !strings.Contains(out, "encoded") {
		t.Errorf("DisplayResult should note the output is encoded: %s", out)
	}
}
