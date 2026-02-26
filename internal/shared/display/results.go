package display

import (
	"fmt"
	"strings"

	"raxuiscli/internal/shared/constants"
	"raxuiscli/internal/shared/models"
)

// DisplayVulnResults displays vulnerability results in a formatted way
func DisplayVulnResults(results []models.VulnResult) {
	if len(results) == 0 {
		fmt.Println("\n" + GreenText("[NO VULNERABILITIES FOUND]"))
		return
	}

	PrintHeader("VULNERABILITY SCAN RESULTS")

	// Group by severity
	bySeverity := map[constants.Severity][]models.VulnResult{
		constants.SeverityCritical: {},
		constants.SeverityHigh:     {},
		constants.SeverityMedium:   {},
		constants.SeverityLow:      {},
		constants.SeverityInfo:     {},
	}

	for _, r := range results {
		bySeverity[r.Severity] = append(bySeverity[r.Severity], r)
	}

	// Summary
	fmt.Printf("\n%sSummary:%s\n", BoldWhite, Reset)
	fmt.Printf("  %sCritical:%s %d\n", BoldMagenta, Reset, len(bySeverity[constants.SeverityCritical]))
	fmt.Printf("  %sHigh:%s     %d\n", BoldRed, Reset, len(bySeverity[constants.SeverityHigh]))
	fmt.Printf("  %sMedium:%s   %d\n", BoldYellow, Reset, len(bySeverity[constants.SeverityMedium]))
	fmt.Printf("  %sLow:%s      %d\n", BoldCyan, Reset, len(bySeverity[constants.SeverityLow]))
	fmt.Printf("  %sInfo:%s     %d\n", BoldBlue, Reset, len(bySeverity[constants.SeverityInfo]))

	// Display by severity
	severityOrder := []constants.Severity{
		constants.SeverityCritical,
		constants.SeverityHigh,
		constants.SeverityMedium,
		constants.SeverityLow,
		constants.SeverityInfo,
	}

	for _, severity := range severityOrder {
		vulns := bySeverity[severity]
		if len(vulns) == 0 {
			continue
		}

		color := SeverityColor(string(severity))
		fmt.Printf("\n%s[%s]%s\n", color, severity, Reset)
		fmt.Println(strings.Repeat("-", 40))

		for i, v := range vulns {
			fmt.Printf("\n%s%d. %s%s\n", BoldWhite, i+1, v.Type, Reset)
			fmt.Printf("   %sURL:%s %s\n", Dim, Reset, Truncate(v.URL, 70))
			if v.Parameter != "" {
				fmt.Printf("   %sParameter:%s %s\n", Dim, Reset, v.Parameter)
			}
			if v.Payload != "" {
				fmt.Printf("   %sPayload:%s %s\n", Dim, Reset, Truncate(v.Payload, 50))
			}
			fmt.Printf("   %sEvidence:%s %s\n", Dim, Reset, Truncate(v.Evidence, 60))
			fmt.Printf("   %sDescription:%s %s\n", Dim, Reset, v.Description)
			fmt.Printf("   %sRemediation:%s %s\n", Dim, Reset, v.Remediation)
		}
	}

	fmt.Println()
}

// DisplaySimpleResults displays results in a simple format
func DisplaySimpleResults(results []models.VulnResult) {
	for _, r := range results {
		color := SeverityColor(string(r.Severity))
		fmt.Printf("%s[%s]%s %s - %s\n", color, r.Severity, Reset, r.Type, r.URL)
	}
}

// DisplayPayloads displays a list of payloads
func DisplayPayloads(vulnType string, level int, payloads []string) {
	fmt.Printf("\n%s[%s Payloads - Level %d]%s\n", BoldWhite, vulnType, level, Reset)
	fmt.Println(strings.Repeat("-", 40))
	fmt.Printf("Total payloads: %d\n\n", len(payloads))

	for i, p := range payloads {
		fmt.Printf("%s%3d.%s %s\n", BoldCyan, i+1, Reset, p)
	}
	fmt.Println()
}

// Truncate truncates a string to maxLen characters
func Truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// DisplayProgress displays a simple progress indicator
func DisplayProgress(current, total int, prefix string) {
	percent := float64(current) / float64(total) * 100
	barWidth := 30
	filled := int(float64(barWidth) * float64(current) / float64(total))

	bar := strings.Repeat("█", filled) + strings.Repeat("░", barWidth-filled)
	fmt.Printf("\r%s [%s] %.1f%% (%d/%d)", prefix, bar, percent, current, total)

	if current == total {
		fmt.Println()
	}
}

// ClearLine clears the current line
func ClearLine() {
	fmt.Print("\r" + strings.Repeat(" ", 80) + "\r")
}
