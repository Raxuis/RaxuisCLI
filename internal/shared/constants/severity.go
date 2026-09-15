package constants

import (
	"errors"
	"fmt"
	"strings"
)

// Severity represents the severity level of a vulnerability finding
type Severity string

const (
	SeverityNone     Severity = "NONE"
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

// ErrInvalidSeverity indicates that a severity value is not one of the
// supported severity levels.
var ErrInvalidSeverity = errors.New("invalid severity")

// ParseSeverity parses a severity name without regard to case. Surrounding
// whitespace is ignored so values supplied by command-line flags are handled
// consistently.
func ParseSeverity(value string) (Severity, error) {
	switch Severity(strings.ToUpper(strings.TrimSpace(value))) {
	case SeverityNone:
		return SeverityNone, nil
	case SeverityCritical:
		return SeverityCritical, nil
	case SeverityHigh:
		return SeverityHigh, nil
	case SeverityMedium:
		return SeverityMedium, nil
	case SeverityLow:
		return SeverityLow, nil
	case SeverityInfo:
		return SeverityInfo, nil
	default:
		return SeverityNone, fmt.Errorf("%w: %q", ErrInvalidSeverity, value)
	}
}

// Rank returns the relative severity, with larger values representing more
// severe findings. Unknown values rank below the supported levels.
func (s Severity) Rank() int {
	switch s {
	case SeverityNone:
		return 0
	case SeverityInfo:
		return 1
	case SeverityLow:
		return 2
	case SeverityMedium:
		return 3
	case SeverityHigh:
		return 4
	case SeverityCritical:
		return 5
	default:
		return -1
	}
}

// MeetsThreshold reports whether severity reaches or exceeds threshold. The
// special none threshold disables policy failures and therefore never matches.
func MeetsThreshold(severity, threshold Severity) bool {
	if threshold == SeverityNone {
		return false
	}
	return severity.Rank() >= threshold.Rank() && severity.Rank() >= 0 && threshold.Rank() >= 0
}

// MeetsThreshold is also available as a method for callers that already hold
// a finding severity.
func (s Severity) MeetsThreshold(threshold Severity) bool {
	return MeetsThreshold(s, threshold)
}

// Color returns ANSI color code for the severity level
func (s Severity) Color() string {
	switch s {
	case SeverityCritical:
		return "\033[1;35m" // Bold Magenta
	case SeverityHigh:
		return "\033[1;31m" // Bold Red
	case SeverityMedium:
		return "\033[1;33m" // Bold Yellow
	case SeverityLow:
		return "\033[1;36m" // Bold Cyan
	case SeverityInfo:
		return "\033[1;34m" // Bold Blue
	default:
		return "\033[0m" // Reset
	}
}

// String returns the string representation of the severity
func (s Severity) String() string {
	return string(s)
}
