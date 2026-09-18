package ldap

import (
	"testing"
)

func TestGetBaseDN(t *testing.T) {
	tests := []struct {
		name   string
		domain string
		want   string
	}{
		{"single", "example", "DC=example"},
		{"two-part", "example.com", "DC=example,DC=com"},
		{"three-part", "sub.example.com", "DC=sub,DC=example,DC=com"},
		{"empty", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetBaseDN(tt.domain); got != tt.want {
				t.Errorf("GetBaseDN(%q) = %q, want %q", tt.domain, got, tt.want)
			}
		})
	}
}

func TestFindKerberoastable(t *testing.T) {
	users := []User{
		{ServicePrincipal: []string{"HTTP/server"}, Enabled: true},
		{ServicePrincipal: []string{}, Enabled: true},
		{ServicePrincipal: []string{"LDAP/dc"}, Enabled: false},
		{ServicePrincipal: []string{"MSSQL/db"}, Enabled: true},
	}
	got := FindKerberoastable(users)
	if len(got) != 2 {
		t.Errorf("FindKerberoastable() returned %d users, want 2", len(got))
	}
}

func TestFindASREPRoastable(t *testing.T) {
	users := []User{
		{DontReqPreauth: true, Enabled: true},
		{DontReqPreauth: true, Enabled: false},
		{DontReqPreauth: false, Enabled: true},
	}
	got := FindASREPRoastable(users)
	if len(got) != 1 {
		t.Errorf("FindASREPRoastable() returned %d users, want 1", len(got))
	}
}

func TestParseBindResultCode(t *testing.T) {
	tests := []struct {
		name     string
		resp     []byte
		wantCode int
		wantOK   bool
	}{
		{"success", []byte{0x30, 0x0c, 0x02, 0x01, 0x01, 0x61, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00}, 0, true},
		{"invalid-creds", []byte{0x30, 0x0c, 0x02, 0x01, 0x01, 0x61, 0x07, 0x0a, 0x01, 0x31, 0x04, 0x00, 0x04, 0x00}, 49, true},
		{"multi-byte-msgid", []byte{0x30, 0x0e, 0x02, 0x03, 0x00, 0x00, 0x05, 0x61, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00}, 0, true},
		{"too-short", []byte{0x30, 0x02, 0x02, 0x01}, 0, false},
		{"not-sequence", []byte{0x02, 0x01, 0x01}, 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, ok := parseBindResultCode(tt.resp)
			if ok != tt.wantOK || (ok && code != tt.wantCode) {
				t.Errorf("parseBindResultCode(%s) = (%d, %v), want (%d, %v)", tt.name, code, ok, tt.wantCode, tt.wantOK)
			}
		})
	}
}
