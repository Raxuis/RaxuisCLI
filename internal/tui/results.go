package tui

import (
	"fmt"
	"strings"

	"github.com/Raxuis/RaxuisCLI/internal/shared/constants"
	"github.com/Raxuis/RaxuisCLI/internal/shared/models"
	"github.com/Raxuis/RaxuisCLI/internal/shared/render"
	"github.com/Raxuis/RaxuisCLI/internal/shared/report"
)

var severityOrder = []constants.Severity{
	constants.SeverityCritical,
	constants.SeverityHigh,
	constants.SeverityMedium,
	constants.SeverityLow,
	constants.SeverityInfo,
}

var severityColors = map[constants.Severity]string{
	constants.SeverityCritical: "#e879f9",
	constants.SeverityHigh:     "#fb7185",
	constants.SeverityMedium:   "#fbbf24",
	constants.SeverityLow:      "#38bdf8",
	constants.SeverityInfo:     "#a3a3a3",
}

type severityCount struct {
	Severity constants.Severity
	Count    int
}

func countBySeverity(findings []models.VulnResult) []severityCount {
	totals := make(map[constants.Severity]int)
	for _, finding := range findings {
		totals[finding.Severity]++
	}
	counts := make([]severityCount, 0, len(severityOrder))
	for _, severity := range severityOrder {
		counts = append(counts, severityCount{Severity: severity, Count: totals[severity]})
	}
	return counts
}

// The zero value (SeverityNone) means "show everything".
func visibleFindings(findings []models.VulnResult, filter constants.Severity) []models.VulnResult {
	if filter == constants.SeverityNone || filter == "" {
		return findings
	}
	out := make([]models.VulnResult, 0, len(findings))
	for _, finding := range findings {
		if finding.Severity == filter {
			out = append(out, finding)
		}
	}
	return out
}

func renderReport(styles Styles, value report.Report, filter constants.Severity, savedPath string, narrow bool) string {
	var b strings.Builder
	b.WriteString(styles.Title.Render(fmt.Sprintf(uiText.ResultsTitleFmt, value.Audit.Target)))
	b.WriteString("\n\n")

	b.WriteString(styles.Muted.Render(uiText.ResultsSummary))
	for _, count := range countBySeverity(value.Findings) {
		b.WriteString(badge(styles.Color, severityColors[count.Severity], fmt.Sprintf("%s %d", severityLabel(count.Severity), count.Count)))
		b.WriteString(" ")
	}
	b.WriteString("\n\n")

	filtered := visibleFindings(value.Findings, filter)
	if filter != constants.SeverityNone && filter != "" {
		b.WriteString(styles.Muted.Render(fmt.Sprintf(uiText.ResultsFilterFmt, severityLabel(filter))))
		b.WriteString("\n")
	}
	if len(filtered) == 0 {
		b.WriteString(styles.Muted.Render(uiText.ResultsNoFindings))
	}
	for _, finding := range filtered {
		b.WriteString(badge(styles.Color, severityColors[finding.Severity], severityLabel(finding.Severity)))
		b.WriteString(" ")
		b.WriteString(styles.App.Render(finding.Title))
		b.WriteString("\n")
		if !narrow && finding.Remediation != "" {
			b.WriteString(styles.Muted.Render("    " + finding.Remediation))
			b.WriteString("\n")
		}
	}

	b.WriteString("\n")
	if savedPath != "" {
		b.WriteString(styles.Accent.Render(fmt.Sprintf(uiText.ResultsSavedFmt, savedPath)))
		b.WriteString("\n")
	}
	b.WriteString(styles.Muted.Render(uiText.ResultsHint))
	return b.String()
}

func renderComparison(styles Styles, comparison report.Comparison, narrow bool) string {
	var b strings.Builder
	b.WriteString(styles.Title.Render(uiText.ComparisonHeading))
	b.WriteString("\n\n")

	summary := []struct {
		label string
		count int
	}{
		{uiText.CmpAdded, len(comparison.Findings.Added)},
		{uiText.CmpResolved, len(comparison.Findings.Resolved)},
		{uiText.CmpChanged, len(comparison.Findings.Changed)},
		{uiText.CmpUnchanged, len(comparison.Findings.Unchanged)},
	}
	for _, row := range summary {
		b.WriteString(styles.Muted.Render(fmt.Sprintf("%-12s", row.label+":")))
		b.WriteString(" ")
		b.WriteString(styles.App.Render(fmt.Sprintf("%d", row.count)))
		b.WriteString("\n")
	}

	b.WriteString("\n")
	if comparison.HasRegressionAt(constants.SeverityLow) {
		b.WriteString(styles.Accent.Render(uiText.CmpRegressions))
	} else {
		b.WriteString(styles.Muted.Render(uiText.CmpNoRegressions))
	}
	if !narrow {
		b.WriteString("\n")
		for _, added := range comparison.Findings.Added {
			b.WriteString(badge(styles.Color, severityColors[added.Severity], uiText.CmpNewBadge))
			b.WriteString(" ")
			b.WriteString(styles.App.Render(added.Title))
			b.WriteString("\n")
		}
	}
	b.WriteString("\n")
	b.WriteString(styles.Muted.Render(uiText.InfoHint))
	return b.String()
}

func renderBrowse(styles Styles, items []paletteItem, cursor int, narrow bool) string {
	var b strings.Builder
	b.WriteString(styles.Title.Render(fmt.Sprintf(uiText.BrowseTitleFmt, len(items))))
	b.WriteString("\n\n")
	for i, item := range items {
		marker := "  "
		style := styles.Item
		if i == cursor {
			marker = "▸ "
			style = styles.SelectedItem
		}
		badges := maturityBadge(styles, item.maturity) + " " + safetyBadge(styles, item.safety)
		line := marker + item.title
		if narrow {
			b.WriteString(style.Render(line))
			b.WriteString(" ")
			b.WriteString(badges)
		} else {
			b.WriteString(style.Render(fmt.Sprintf("%-34s", line)))
			b.WriteString(" ")
			b.WriteString(badges)
			b.WriteString("  ")
			b.WriteString(styles.Muted.Render(item.summary))
		}
		b.WriteString("\n")
	}
	b.WriteString("\n")
	b.WriteString(styles.Muted.Render(uiText.BrowseHint))
	return b.String()
}

func saveReport(path string, value report.Report, output string, force bool) (string, error) {
	renderer, err := render.RendererFor(output)
	if err != nil {
		return "", err
	}
	if err := report.WriteFile(path, value, renderer, force); err != nil {
		return "", err
	}
	return path, nil
}

func severityLabel(severity constants.Severity) string {
	if severity == "" {
		return "none"
	}
	return strings.ToLower(string(severity))
}
