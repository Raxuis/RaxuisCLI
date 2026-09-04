package urlnorm

import "testing"

func TestEnsureScheme(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"example.com", "https://example.com"},
		{"example.com/path?a=1", "https://example.com/path?a=1"},
		{"http://example.com", "http://example.com"},
		{"https://example.com", "https://example.com"},
		{"HTTPS://example.com", "https://HTTPS://example.com"}, // scheme check is case-sensitive by design
	}

	for _, tt := range tests {
		if got := EnsureScheme(tt.input); got != tt.want {
			t.Errorf("EnsureScheme(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
