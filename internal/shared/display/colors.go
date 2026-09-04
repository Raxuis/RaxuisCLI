package display

// ANSI color codes
const (
	Reset     = "\033[0m"
	Bold      = "\033[1m"
	Dim       = "\033[2m"
	Italic    = "\033[3m"
	Underline = "\033[4m"

	// Regular colors
	Black   = "\033[30m"
	Red     = "\033[31m"
	Green   = "\033[32m"
	Yellow  = "\033[33m"
	Blue    = "\033[34m"
	Magenta = "\033[35m"
	Cyan    = "\033[36m"
	White   = "\033[37m"

	// Bold colors
	BoldBlack   = "\033[1;30m"
	BoldRed     = "\033[1;31m"
	BoldGreen   = "\033[1;32m"
	BoldYellow  = "\033[1;33m"
	BoldBlue    = "\033[1;34m"
	BoldMagenta = "\033[1;35m"
	BoldCyan    = "\033[1;36m"
	BoldWhite   = "\033[1;37m"

	// Background colors
	BgBlack   = "\033[40m"
	BgRed     = "\033[41m"
	BgGreen   = "\033[42m"
	BgYellow  = "\033[43m"
	BgBlue    = "\033[44m"
	BgMagenta = "\033[45m"
	BgCyan    = "\033[46m"
	BgWhite   = "\033[47m"
)

// ColorFunc returns a function that wraps text in the given color
func ColorFunc(color string) func(string) string {
	return func(text string) string {
		return color + text + Reset
	}
}

// Colorize wraps text with a color code
func Colorize(text, color string) string {
	return color + text + Reset
}

// Helper functions for common colors
func RedText(text string) string {
	return BoldRed + text + Reset
}

func GreenText(text string) string {
	return BoldGreen + text + Reset
}

func YellowText(text string) string {
	return BoldYellow + text + Reset
}

func BlueText(text string) string {
	return BoldBlue + text + Reset
}

func MagentaText(text string) string {
	return BoldMagenta + text + Reset
}

func CyanText(text string) string {
	return BoldCyan + text + Reset
}

func WhiteText(text string) string {
	return BoldWhite + text + Reset
}

func DimText(text string) string {
	return Dim + text + Reset
}

// SeverityColor returns the appropriate color for a severity level
func SeverityColor(severity string) string {
	switch severity {
	case "CRITICAL":
		return BoldMagenta
	case "HIGH":
		return BoldRed
	case "MEDIUM":
		return BoldYellow
	case "LOW":
		return BoldCyan
	case "INFO":
		return BoldBlue
	default:
		return Reset
	}
}

// ColorSeverity colors a severity string
func ColorSeverity(severity string) string {
	return SeverityColor(severity) + severity + Reset
}

// SuccessIcon returns a colored success icon
func SuccessIcon() string {
	return GreenText("[+]")
}

// ErrorIcon returns a colored error icon
func ErrorIcon() string {
	return RedText("[-]")
}

// InfoIcon returns a colored info icon
func InfoIcon() string {
	return BlueText("[*]")
}

// WarningIcon returns a colored warning icon
func WarningIcon() string {
	return YellowText("[!]")
}
