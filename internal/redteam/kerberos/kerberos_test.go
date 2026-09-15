package kerberos

import (
	"testing"
	"time"
)

func TestFormatHashcat(t *testing.T) {
	tests := []struct {
		name   string
		ticket *KerberosTicket
		want   string
	}{
		{
			name: "tgs",
			ticket: &KerberosTicket{
				Type:     "TGS",
				EncType:  23,
				Username: "user",
				Domain:   "REALM",
				SPN:      "HTTP/server",
				Hash:     "abcd1234",
			},
			want: "$krb5tgs$23$*user$REALM$HTTP/server*$abcd1234",
		},
		{
			name: "asrep",
			ticket: &KerberosTicket{
				Type:     "AS-REP",
				EncType:  23,
				Username: "user",
				Domain:   "REALM",
				Hash:     "abcd1234",
			},
			want: "$krb5asrep$23$user@REALM:abcd1234",
		},
		{
			name: "unknown",
			ticket: &KerberosTicket{
				Type: "UNKNOWN",
				Hash: "abcd1234",
			},
			want: "abcd1234",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := FormatHashcat(tt.ticket); got != tt.want {
				t.Errorf("FormatHashcat() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFormatJohn(t *testing.T) {
	ticket := &KerberosTicket{
		Type:     "TGS",
		EncType:  23,
		Username: "user",
		Domain:   "REALM",
		SPN:      "HTTP/server",
		Hash:     "abcd1234",
	}
	got := FormatJohn(ticket)
	if got != "$krb5tgs$23$user$REALM$*HTTP/server*$abcd1234" {
		t.Errorf("FormatJohn() = %q", got)
	}
}

func TestParseHashcatOutput(t *testing.T) {
	tests := []struct {
		name    string
		line    string
		wantErr bool
		check   func(*KerberosTicket) bool
	}{
		{
			name:    "tgs hash",
			line:    "$krb5tgs$23$*user$REALM$SPN*$hash123",
			wantErr: false,
			check: func(t *KerberosTicket) bool {
				return t.Type == "TGS" && t.Username == "user" && t.Domain == "REALM" && t.SPN == "SPN"
			},
		},
		{
			name:    "asrep hash",
			line:    "$krb5asrep$23$user@REALM:hash123",
			wantErr: false,
			check: func(t *KerberosTicket) bool {
				return t.Type == "AS-REP" && t.Username == "user" && t.Domain == "REALM"
			},
		},
		{
			name:    "invalid",
			line:    "not-a-hash",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseHashcatOutput(tt.line)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseHashcatOutput() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && !tt.check(got) {
				t.Errorf("ParseHashcatOutput() check failed: %+v", got)
			}
		})
	}
}

func TestGenerateKerberoastCommand(t *testing.T) {
	got := GenerateKerberoastCommand("user@REALM")
	if got == "" {
		t.Errorf("GenerateKerberoastCommand() returned empty string")
	}
}

func TestGenerateASREPCommand(t *testing.T) {
	users := []string{"user1@REALM", "user2@REALM"}
	got := GenerateASREPCommand(users)
	if got == "" {
		t.Errorf("GenerateASREPCommand() returned empty string")
	}
}

func TestParseKirbiFile(t *testing.T) {
	data := []byte{0x76} // Magic byte
	got, err := ParseKirbiFile(data)
	if err != nil {
		t.Errorf("ParseKirbiFile() error = %v", err)
		return
	}
	if got == nil {
		t.Errorf("ParseKirbiFile() returned nil")
	}
}

func TestParseKirbiFileInvalid(t *testing.T) {
	data := []byte{0xFF} // Invalid magic
	_, err := ParseKirbiFile(data)
	if err == nil {
		t.Errorf("ParseKirbiFile() should error on invalid magic")
	}
}

func TestGenerateBloodHoundJSONTGS(t *testing.T) {
	tickets := []KerberosTicket{
		{Username: "user1", SPN: "HTTP/server1"},
		{Username: "user2", SPN: "LDAP/server2"},
	}
	got := GenerateBloodHoundJSONTGS(tickets)
	if got == "" {
		t.Errorf("GenerateBloodHoundJSONTGS() returned empty string")
	}
}
