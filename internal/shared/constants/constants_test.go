package constants

import "testing"

func TestSeverityColor(t *testing.T) {
	tests := []struct {
		severity Severity
		want     string
	}{
		{SeverityCritical, "\033[1;35m"},
		{SeverityHigh, "\033[1;31m"},
		{SeverityMedium, "\033[1;33m"},
		{SeverityLow, "\033[1;36m"},
		{SeverityInfo, "\033[1;34m"},
		{Severity("unknown"), "\033[0m"},
	}

	for _, tt := range tests {
		if got := tt.severity.Color(); got != tt.want {
			t.Errorf("%v.Color() = %q, want %q", tt.severity, got, tt.want)
		}
	}
}

func TestSeverityString(t *testing.T) {
	if got := SeverityCritical.String(); got != "CRITICAL" {
		t.Errorf("SeverityCritical.String() = %q, want %q", got, "CRITICAL")
	}
}

func TestVulnTypeString(t *testing.T) {
	if got := VulnXSS.String(); got != "XSS" {
		t.Errorf("VulnXSS.String() = %q, want %q", got, "XSS")
	}
}

func TestVulnTypeDescription(t *testing.T) {
	allTypes := []VulnType{
		VulnXSS, VulnSQLi, VulnLFI, VulnRFI, VulnSSRF, VulnCmdInj,
		VulnHeaders, VulnOpen, VulnCORS, VulnNoSQLi, VulnXXE,
		VulnGraphQL, VulnHostHeader, VulnRace,
	}

	for _, vt := range allTypes {
		desc := vt.Description()
		if desc == "" || desc == "Unknown vulnerability type" {
			t.Errorf("%v.Description() = %q, want a real description", vt, desc)
		}
	}

	if got := VulnType("bogus").Description(); got != "Unknown vulnerability type" {
		t.Errorf("unknown VulnType.Description() = %q, want %q", got, "Unknown vulnerability type")
	}
}
