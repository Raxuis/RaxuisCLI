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

func TestParseHashFile(t *testing.T) {
	content := `
admin:500:aad3b435b51404eeaad3b435b51404ee:5f4dcc3b5aa765d61d8327deb882cf99:::
guest:501:aad3b435b51404eeaad3b435b51404ee:5f4dcc3b5aa765d61d8327deb882cf99:::
`
	results, err := ParseHashFile(content)
	if err != nil {
		t.Errorf("ParseHashFile() error = %v", err)
	}
	if len(results) < 2 {
		t.Errorf("ParseHashFile() returned %d results, want >= 2", len(results))
	}
}

func TestFormatHashcat(t *testing.T) {
	cred := Credential{
		Username: "admin",
		Hash:     "5f4dcc3b5aa765d61d8327deb882cf99",
		HashType: "MD5",
	}
	formatted := FormatHashcat(cred)
	if formatted == "" {
		t.Errorf("FormatHashcat() returned empty string")
	}
}

func TestFormatJohn(t *testing.T) {
	cred := Credential{
		Username: "admin",
		Hash:     "5f4dcc3b5aa765d61d8327deb882cf99",
		HashType: "MD5",
	}
	formatted := FormatJohn(cred)
	if formatted == "" {
		t.Errorf("FormatJohn() returned empty string")
	}
}
