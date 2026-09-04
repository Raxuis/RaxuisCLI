package payloads

import "testing"

func TestGetXSSPayloads(t *testing.T) {
	for level := 1; level <= 3; level++ {
		p := GetXSSPayloads(level)
		if len(p) == 0 {
			t.Errorf("GetXSSPayloads(%d) returned no payloads", level)
		}
	}
	if got := GetXSSPayloads(99); len(got) != len(XSSPayloads[2]) {
		t.Errorf("GetXSSPayloads(unknown level) should default to level 2, got %d payloads want %d", len(got), len(XSSPayloads[2]))
	}
}

func TestGetSQLiPayloads(t *testing.T) {
	for level := 1; level <= 3; level++ {
		p := GetSQLiPayloads(level)
		if len(p) == 0 {
			t.Errorf("GetSQLiPayloads(%d) returned no payloads", level)
		}
	}
	if got := GetSQLiPayloads(99); len(got) != len(SQLiPayloads[2]) {
		t.Errorf("GetSQLiPayloads(unknown level) should default to level 2")
	}
}

func TestMatchesSQLError(t *testing.T) {
	tests := []struct {
		body string
		want bool
	}{
		{"You have an error in your SQL syntax near", true},
		{"SQL syntax error in your MySQL query", true},
		{"everything is fine here", false},
		{"", false},
	}

	for _, tt := range tests {
		matched, _ := MatchesSQLError(tt.body)
		if matched != tt.want {
			t.Errorf("MatchesSQLError(%q) = %v, want %v", tt.body, matched, tt.want)
		}
	}
}

func TestGetLFIPayloads(t *testing.T) {
	for level := 1; level <= 3; level++ {
		p := GetLFIPayloads(level)
		if len(p) == 0 {
			t.Errorf("GetLFIPayloads(%d) returned no payloads", level)
		}
	}
	if got := GetLFIPayloads(0); len(got) != len(LFIPayloads[2]) {
		t.Errorf("GetLFIPayloads(unknown level) should default to level 2")
	}
}

func TestMatchesLFISuccess(t *testing.T) {
	tests := []struct {
		body string
		want bool
	}{
		{"root:x:0:0:root:/root:/bin/bash", true},
		{"[extensions]\r\n; for 16-bit app support", true},
		{"nothing interesting here", false},
	}

	for _, tt := range tests {
		matched, _ := MatchesLFISuccess(tt.body)
		if matched != tt.want {
			t.Errorf("MatchesLFISuccess(%q) = %v, want %v", tt.body, matched, tt.want)
		}
	}
}

func TestGetCmdInjPayloads(t *testing.T) {
	for level := 1; level <= 3; level++ {
		p := GetCmdInjPayloads(level)
		if len(p) == 0 {
			t.Errorf("GetCmdInjPayloads(%d) returned no payloads", level)
		}
	}
	if got := GetCmdInjPayloads(-1); len(got) != len(CmdInjPayloads[2]) {
		t.Errorf("GetCmdInjPayloads(unknown level) should default to level 2")
	}
}

func TestMatchesCmdOutput(t *testing.T) {
	tests := []struct {
		body string
		want bool
	}{
		{"uid=0(root) gid=0(root) groups=0(root)", true},
		{"total 42\ndrwxr-xr-x 2 root root", true},
		{"just a normal web page", false},
	}

	for _, tt := range tests {
		matched, _ := MatchesCmdOutput(tt.body)
		if matched != tt.want {
			t.Errorf("MatchesCmdOutput(%q) = %v, want %v", tt.body, matched, tt.want)
		}
	}
}

func TestGetNoSQLiPayloads(t *testing.T) {
	for level := 1; level <= 3; level++ {
		p := GetNoSQLiPayloads(level)
		if len(p) == 0 {
			t.Errorf("GetNoSQLiPayloads(%d) returned no payloads", level)
		}
	}
	if got := GetNoSQLiPayloads(100); len(got) != len(NoSQLiPayloads[2]) {
		t.Errorf("GetNoSQLiPayloads(unknown level) should default to level 2")
	}
}

func TestGetHostHeaderPayloads(t *testing.T) {
	p := GetHostHeaderPayloads()
	if len(p) != len(HostHeaderPayloads) {
		t.Errorf("GetHostHeaderPayloads() returned %d payloads, want %d", len(p), len(HostHeaderPayloads))
	}
}

func TestGetCORSTestOrigins(t *testing.T) {
	empty := GetCORSTestOrigins("")
	if len(empty) != len(CORSTestOrigins) {
		t.Errorf("GetCORSTestOrigins(\"\") returned %d origins, want %d", len(empty), len(CORSTestOrigins))
	}

	replaced := GetCORSTestOrigins("example.com")
	if len(replaced) != len(CORSTestOrigins) {
		t.Fatalf("GetCORSTestOrigins(example.com) returned %d origins, want %d", len(replaced), len(CORSTestOrigins))
	}

	found := false
	for _, origin := range replaced {
		if origin == "https://example.com.evil.com" {
			found = true
		}
		if containsSubstring(origin, "TARGETDOMAIN") {
			t.Errorf("origin %q still contains the TARGETDOMAIN placeholder", origin)
		}
	}
	if !found {
		t.Error("expected the subdomain-bypass origin to have TARGETDOMAIN replaced with example.com")
	}
}

func TestGetXXEPayloads(t *testing.T) {
	all := GetXXEPayloads("")
	if len(all) != len(XXEPayloads) {
		t.Errorf("GetXXEPayloads(\"\") returned %d payloads, want %d", len(all), len(XXEPayloads))
	}

	tests := []struct {
		payloadType string
		wantMin     int
	}{
		{"file", 1},
		{"oob", 1},
		{"error", 1},
	}

	for _, tt := range tests {
		got := GetXXEPayloads(tt.payloadType)
		if len(got) < tt.wantMin {
			t.Errorf("GetXXEPayloads(%q) returned %d payloads, want at least %d", tt.payloadType, len(got), tt.wantMin)
		}
	}

	if got := GetXXEPayloads("nonexistent-type"); len(got) != 0 {
		t.Errorf("GetXXEPayloads(unknown type) = %d payloads, want 0", len(got))
	}
}

func TestGetGraphQLQuery(t *testing.T) {
	got := GetGraphQLQuery("introspection_simple")
	if got == "" || got != GraphQLQueries["introspection_simple"] {
		t.Errorf("GetGraphQLQuery(introspection_simple) = %q, want the map value", got)
	}

	if got := GetGraphQLQuery("does-not-exist"); got != "" {
		t.Errorf("GetGraphQLQuery(unknown) = %q, want empty string", got)
	}
}

func TestGetOpenRedirectPayloads(t *testing.T) {
	p := GetOpenRedirectPayloads()
	if len(p) != len(OpenRedirectPayloads) {
		t.Errorf("GetOpenRedirectPayloads() returned %d payloads, want %d", len(p), len(OpenRedirectPayloads))
	}
}

func TestIsRedirectParam(t *testing.T) {
	tests := []struct {
		param string
		want  bool
	}{
		{"url", true},
		{"redirect_url", true},
		{"ReturnUrl", true}, // case-insensitive, contains "return"
		{"next", true},
		{"username", false},
		{"password", false},
		{"", false},
	}

	for _, tt := range tests {
		if got := IsRedirectParam(tt.param); got != tt.want {
			t.Errorf("IsRedirectParam(%q) = %v, want %v", tt.param, got, tt.want)
		}
	}
}
