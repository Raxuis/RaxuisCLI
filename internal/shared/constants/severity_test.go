package constants

import "testing"

func TestParseSeverityIsCaseInsensitive(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  Severity
	}{
		{"critical", "critical", SeverityCritical},
		{"high", "HIGH", SeverityHigh},
		{"medium", "MeDiUm", SeverityMedium},
		{"low", "low", SeverityLow},
		{"info", "Info", SeverityInfo},
		{"none", "NONE", SeverityNone},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseSeverity(tt.input)
			if err != nil {
				t.Fatalf("ParseSeverity(%q) returned error: %v", tt.input, err)
			}
			if got != tt.want {
				t.Errorf("ParseSeverity(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestParseSeverityRejectsInvalidValues(t *testing.T) {
	if _, err := ParseSeverity("urgent"); err == nil {
		t.Fatal("ParseSeverity(urgent) returned nil error")
	}
}

func TestSeverityRankOrdersMostSevereFirst(t *testing.T) {
	tests := []struct {
		severity Severity
		want     int
	}{
		{SeverityNone, 0},
		{SeverityInfo, 1},
		{SeverityLow, 2},
		{SeverityMedium, 3},
		{SeverityHigh, 4},
		{SeverityCritical, 5},
	}

	for _, tt := range tests {
		if got := tt.severity.Rank(); got != tt.want {
			t.Errorf("%q.Rank() = %d, want %d", tt.severity, got, tt.want)
		}
	}
}

func TestMeetsThreshold(t *testing.T) {
	tests := []struct {
		name      string
		severity  Severity
		threshold Severity
		want      bool
	}{
		{"none threshold never matches", SeverityCritical, SeverityNone, false},
		{"below threshold", SeverityLow, SeverityHigh, false},
		{"equal threshold", SeverityHigh, SeverityHigh, true},
		{"above threshold", SeverityCritical, SeverityHigh, true},
		{"info threshold", SeverityInfo, SeverityInfo, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := MeetsThreshold(tt.severity, tt.threshold); got != tt.want {
				t.Errorf("MeetsThreshold(%q, %q) = %t, want %t", tt.severity, tt.threshold, got, tt.want)
			}
		})
	}
}
