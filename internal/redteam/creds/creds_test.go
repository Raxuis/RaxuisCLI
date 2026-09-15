package creds

import (
	"testing"
)

func TestCredential(t *testing.T) {
	cred := Credential{
		Username: "admin",
		Password: "password123",
		Domain:   "DOMAIN",
		HashType: "NTLM",
	}
	if cred.Username != "admin" {
		t.Errorf("Credential.Username = %q, want admin", cred.Username)
	}
}

func TestConvertFormat(t *testing.T) {
	creds := []Credential{
		{Username: "admin", Hash: "5f4dcc3b5aa765d61d8327deb882cf99", HashType: "MD5"},
		{Username: "guest", Hash: "abc123def456", HashType: "SHA1"},
	}
	result := ConvertFormat(creds, "hashcat")
	if len(result) == 0 {
		t.Errorf("ConvertFormat() returned empty result")
	}
	if result[0] == "" {
		t.Errorf("ConvertFormat() first element is empty")
	}
}

func TestDecodeCredential(t *testing.T) {
	encoded := "YWRtaW46cGFzc3dvcmQxMjM="
	results := DecodeCredential(encoded)
	if len(results) == 0 {
		t.Errorf("DecodeCredential() returned empty results")
	}
	if results[0].Method != "Base64" || results[0].Value != "admin:password123" {
		t.Errorf("DecodeCredential() = %+v, want Base64 admin:password123", results)
	}
}

func TestGenerateCombo(t *testing.T) {
	users := []string{"admin", "guest"}
	passwords := []string{"pass123", "pwd456"}
	combos := GenerateCombo(users, passwords, "DOMAIN")
	if len(combos) != 4 {
		t.Errorf("GenerateCombo() returned %d combos, want 4", len(combos))
	}
}
