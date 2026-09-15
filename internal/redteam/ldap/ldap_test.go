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
