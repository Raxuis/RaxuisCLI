package ntlm

import (
	"os"
	"path/filepath"
	"testing"
)

func TestComputeNTHashKnownVector(t *testing.T) {
	// Well-known NTLM test vector: NT hash of "password".
	got := ComputeNTHash("password")
	want := "8846F7EAEE8FB117AD06BDD830B7586C"
	if got != want {
		t.Errorf("ComputeNTHash(password) = %q, want %q", got, want)
	}
}

func TestComputeNTHashEmpty(t *testing.T) {
	got := ComputeNTHash("")
	want := "31D6CFE0D16AE931B73C59D7E0C089C0" // NT hash of empty string
	if got != want {
		t.Errorf("ComputeNTHash(\"\") = %q, want %q", got, want)
	}
}

func TestComputeLMHashLongPassword(t *testing.T) {
	got := ComputeLMHash("this-password-is-way-too-long")
	want := "AAD3B435B51404EEAAD3B435B51404EE"
	if got != want {
		t.Errorf("ComputeLMHash(long) = %q, want %q", got, want)
	}
}

func TestComputeLMHashShortPassword(t *testing.T) {
	// Current implementation always returns the placeholder value, even for
	// short passwords (documented as simplified/not real DES-based LM hash).
	got := ComputeLMHash("short")
	if got == "" {
		t.Error("ComputeLMHash should never return an empty string")
	}
}

func TestComputeNTLMv2Deterministic(t *testing.T) {
	serverChallenge := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	clientChallenge := []byte{8, 7, 6, 5, 4, 3, 2, 1}

	a := ComputeNTLMv2("alice", "CORP", "password", serverChallenge, clientChallenge)
	b := ComputeNTLMv2("alice", "CORP", "password", serverChallenge, clientChallenge)

	if len(a) == 0 {
		t.Fatal("ComputeNTLMv2 returned empty response")
	}
	if string(a) != string(b) {
		t.Error("ComputeNTLMv2 should be deterministic for the same inputs")
	}

	c := ComputeNTLMv2("alice", "CORP", "different-password", serverChallenge, clientChallenge)
	if string(a) == string(c) {
		t.Error("ComputeNTLMv2 should differ for a different password")
	}
}

func TestCrackNTHashFound(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wordlist.txt")
	if err := os.WriteFile(path, []byte("wrong1\nwrong2\npassword\nwrong3\n"), 0644); err != nil {
		t.Fatalf("failed to write wordlist: %v", err)
	}

	result, err := CrackNTHash("8846F7EAEE8FB117AD06BDD830B7586C", path)
	if err != nil {
		t.Fatalf("CrackNTHash returned error: %v", err)
	}
	if !result.Found || result.Password != "password" {
		t.Errorf("CrackNTHash result = %+v, want Found=true Password=password", result)
	}
	if result.Attempts != 3 {
		t.Errorf("Attempts = %d, want 3 (stops at the match)", result.Attempts)
	}
}

func TestCrackNTHashNotFound(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wordlist.txt")
	if err := os.WriteFile(path, []byte("wrong1\nwrong2\n"), 0644); err != nil {
		t.Fatalf("failed to write wordlist: %v", err)
	}

	result, err := CrackNTHash("8846F7EAEE8FB117AD06BDD830B7586C", path)
	if err != nil {
		t.Fatalf("CrackNTHash returned error: %v", err)
	}
	if result.Found {
		t.Error("CrackNTHash should not find a match in a wordlist without the password")
	}
	if result.Attempts != 2 {
		t.Errorf("Attempts = %d, want 2", result.Attempts)
	}
}

func TestCrackNTHashMissingWordlist(t *testing.T) {
	if _, err := CrackNTHash("hash", "/nonexistent/wordlist.txt"); err == nil {
		t.Error("CrackNTHash with a missing wordlist should return an error")
	}
}

func TestCrackNTHashCaseInsensitive(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wordlist.txt")
	os.WriteFile(path, []byte("password\n"), 0644)

	// Provide the hash in lowercase to verify it's normalized before comparing.
	result, err := CrackNTHash("8846f7eaee8fb117ad06bdd830b7586c", path)
	if err != nil {
		t.Fatalf("CrackNTHash returned error: %v", err)
	}
	if !result.Found {
		t.Error("CrackNTHash should match regardless of hash case")
	}
}

func TestParseNTLMDump(t *testing.T) {
	h, err := ParseNTLMDump("alice:1001:AAD3B435B51404EEAAD3B435B51404EE:8846F7EAEE8FB117AD06BDD830B7586C:::")
	if err != nil {
		t.Fatalf("ParseNTLMDump returned error: %v", err)
	}
	if h.Username != "alice" || h.LMHash != "AAD3B435B51404EEAAD3B435B51404EE" || h.NTHash != "8846F7EAEE8FB117AD06BDD830B7586C" {
		t.Errorf("ParseNTLMDump = %+v, unexpected fields", h)
	}
	if h.Domain != "" {
		t.Errorf("Domain = %q, want empty (no backslash in username)", h.Domain)
	}
}

func TestParseNTLMDumpWithDomain(t *testing.T) {
	h, err := ParseNTLMDump(`CORP\alice:1001:AAD3B435B51404EEAAD3B435B51404EE:8846F7EAEE8FB117AD06BDD830B7586C:::`)
	if err != nil {
		t.Fatalf("ParseNTLMDump returned error: %v", err)
	}
	if h.Domain != "CORP" || h.Username != "alice" {
		t.Errorf("ParseNTLMDump domain/user = %q/%q, want CORP/alice", h.Domain, h.Username)
	}
}

func TestParseNTLMDumpInvalid(t *testing.T) {
	if _, err := ParseNTLMDump("not:enough:parts"); err == nil {
		t.Error("ParseNTLMDump with too few fields should return an error")
	}
}

func TestValidateHash(t *testing.T) {
	tests := []struct {
		hash string
		want bool
	}{
		{"8846F7EAEE8FB117AD06BDD830B7586C", true},
		{"not-hex-and-wrong-length", false},
		{"8846F7EAEE8FB117AD06BDD830B75", false}, // too short
		{"", false},
	}
	for _, tt := range tests {
		if got := ValidateHash(tt.hash); got != tt.want {
			t.Errorf("ValidateHash(%q) = %v, want %v", tt.hash, got, tt.want)
		}
	}
}

func TestIdentifyHashType(t *testing.T) {
	tests := []struct {
		hash string
		want string
	}{
		{"aad3b435b51404eeaad3b435b51404ee", "LM (empty/disabled)"},
		{"8846f7eaee8fb117ad06bdd830b7586c", "NTLM/MD5"},
		{"a" + repeatChar("b", 63), "SHA256/NTLMv2"},
		{"a" + repeatChar("b", 127), "SHA512"},
		{"alice:1001:AAD3B435B51404EEAAD3B435B51404EE:8846F7EAEE8FB117AD06BDD830B7586C:::", "NTLM Dump (user:uid:lm:nt)"},
		{"alice:8846f7eaee8fb117ad06bdd830b7586c", "user:hash"},
		{"totally unknown format", "Unknown"},
	}
	for _, tt := range tests {
		if got := IdentifyHashType(tt.hash); got != tt.want {
			t.Errorf("IdentifyHashType(%q) = %q, want %q", tt.hash, got, tt.want)
		}
	}
}

func repeatChar(c string, n int) string {
	result := ""
	for i := 0; i < n; i++ {
		result += c
	}
	return result
}

func TestFormatHashcat(t *testing.T) {
	h := &NTLMHash{NTHash: "8846F7EAEE8FB117AD06BDD830B7586C"}
	if got := FormatHashcat(h); got != h.NTHash {
		t.Errorf("FormatHashcat = %q, want %q", got, h.NTHash)
	}
}

func TestFormatJohn(t *testing.T) {
	h := &NTLMHash{Username: "alice", NTHash: "8846F7EAEE8FB117AD06BDD830B7586C"}
	got := FormatJohn(h)
	want := "alice:$NT$8846f7eaee8fb117ad06bdd830b7586c"
	if got != want {
		t.Errorf("FormatJohn = %q, want %q", got, want)
	}
}

func TestGeneratePTHCommand(t *testing.T) {
	tests := []struct {
		tool   string
		domain string
	}{
		{"impacket", "CORP"},
		{"impacket", ""},
		{"crackmapexec", "CORP"},
		{"cme", ""},
		{"evil-winrm", ""},
		{"wmiexec", "CORP"},
		{"wmiexec", ""},
		{"unknown-tool", ""},
	}
	for _, tt := range tests {
		cmd := GeneratePTHCommand("alice", tt.domain, "8846F7EAEE8FB117AD06BDD830B7586C", "10.0.0.1", tt.tool)
		if cmd == "" {
			t.Errorf("GeneratePTHCommand(tool=%s, domain=%s) returned empty string", tt.tool, tt.domain)
		}
	}
}

func TestDisplayFunctions(t *testing.T) {
	// Just exercise these for coverage/no-panic; output correctness isn't the point.
	h := &NTLMHash{Username: "alice", Domain: "CORP", LMHash: "AAD3B435B51404EEAAD3B435B51404EE", NTHash: "8846F7EAEE8FB117AD06BDD830B7586C", Password: "password"}
	DisplayHash(h)

	h2 := &NTLMHash{Username: "bob", LMHash: "SOMEOTHERHASH00000000000000000000"}
	DisplayHash(h2)

	DisplayCrackResult(&CrackResult{Hash: "x", Attempts: 5, Found: true, Password: "pw"})
	DisplayCrackResult(&CrackResult{Hash: "x", Attempts: 5, Found: false})

	DisplayPTHCommands("alice", "CORP", "8846F7EAEE8FB117AD06BDD830B7586C", "10.0.0.1")
}
