package scan

import "testing"

func TestParseTargetsSingleAndList(t *testing.T) {
	got, err := ParseTargets("10.0.0.1, example.com ,10.0.0.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// duplicate 10.0.0.1 collapses to one entry.
	want := []string{"10.0.0.1", "example.com"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("got[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestParseTargetsCIDRStripsNetworkAndBroadcast(t *testing.T) {
	got, err := ParseTargets("192.168.1.0/29")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// /29 = 8 addresses, minus network (.0) and broadcast (.7) = 6 usable hosts.
	if len(got) != 6 {
		t.Fatalf("got %d hosts, want 6: %v", len(got), got)
	}
	if got[0] != "192.168.1.1" || got[len(got)-1] != "192.168.1.6" {
		t.Errorf("host range = %s..%s, want 192.168.1.1..192.168.1.6", got[0], got[len(got)-1])
	}
}

func TestParseTargetsSlash32IsSingleHost(t *testing.T) {
	got, err := ParseTargets("10.1.2.3/32")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 || got[0] != "10.1.2.3" {
		t.Errorf("got %v, want [10.1.2.3]", got)
	}
}

func TestParseTargetsRejectsInvalid(t *testing.T) {
	if _, err := ParseTargets("   "); err == nil {
		t.Error("expected error for empty target spec")
	}
	if _, err := ParseTargets("10.0.0.0/8"); err == nil {
		t.Error("expected error for oversized CIDR")
	}
	if _, err := ParseTargets("2001:db8::/64"); err == nil {
		t.Error("expected error for IPv6 CIDR expansion")
	}
}

func TestAnnotateTagsInterestingPorts(t *testing.T) {
	tests := []struct {
		port    int
		wantTag string
	}{
		{445, "ad"},
		{88, "ad"},
		{5985, "lateral"},
		{1433, "db"},
		{6379, "unauth"},
		{8080, "web"},
		{22, "recon"},
		{12345, ""},
	}
	for _, tt := range tests {
		tag, next := annotate("10.0.0.1", tt.port, "")
		if tag != tt.wantTag {
			t.Errorf("annotate(port %d) tag = %q, want %q", tt.port, tag, tt.wantTag)
		}
		if tt.wantTag != "" && next == "" {
			t.Errorf("annotate(port %d) returned empty next-step", tt.port)
		}
	}
}
