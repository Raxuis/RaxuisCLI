package constants

// Severity represents the severity level of a vulnerability finding
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

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
