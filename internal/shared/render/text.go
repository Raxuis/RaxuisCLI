package render

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"time"

	"raxuiscli/internal/shared/report"
)

type textRenderer struct{}

// ComparisonRenderer is an optional renderer capability for the versioned
// report comparison envelope. Renderer remains unchanged so existing
// report.WriteFile callers stay source compatible.
type ComparisonRenderer interface {
	RenderComparison(io.Writer, report.Comparison) error
}

// NewTextRenderer returns a renderer for a portable, human-readable report.
func NewTextRenderer() Renderer {
	return textRenderer{}
}

func (textRenderer) Render(writer io.Writer, value report.Report) error {
	var output bytes.Buffer
	fmt.Fprintln(&output, "RaxuisCLI Audit Report")
	fmt.Fprintln(&output, "======================")
	fmt.Fprintf(&output, "Audit ID: %s\n", value.Audit.ID)
	fmt.Fprintf(&output, "Kind: %s\n", value.Audit.Kind)
	fmt.Fprintf(&output, "Target: %s\n", value.Audit.Target)
	fmt.Fprintf(&output, "Status: %s\n", value.Audit.Status)
	fmt.Fprintf(&output, "Started: %s\n", value.Audit.StartedAt.UTC().Format(time.RFC3339))
	fmt.Fprintf(&output, "Duration: %s\n", value.Audit.Duration)
	fmt.Fprintf(&output, "Tool: %s %s (%s; %s; %s)\n", value.Tool.Name, value.Tool.Version, value.Tool.Commit, value.Tool.GoVersion, value.Tool.Platform)

	fmt.Fprintf(&output, "\nFindings (%d)\n", len(value.Findings))
	fmt.Fprintln(&output, "------------")
	if len(value.Findings) == 0 {
		fmt.Fprintln(&output, "None")
	}
	for _, finding := range value.Findings {
		fmt.Fprintf(&output, "[%s] %s\n", finding.Severity, finding.Title)
		fmt.Fprintf(&output, "  Rule: %s\n", finding.RuleID)
		fmt.Fprintf(&output, "  Status: %s\n", finding.Status)
		fmt.Fprintf(&output, "  Resource: %s\n", finding.Resource)
		if finding.Parameter != "" {
			fmt.Fprintf(&output, "  Parameter: %s\n", finding.Parameter)
		}
		if finding.Evidence != "" {
			fmt.Fprintf(&output, "  Evidence: %s\n", finding.Evidence)
		}
		if finding.Remediation != "" {
			fmt.Fprintf(&output, "  Remediation: %s\n", finding.Remediation)
		}
	}

	fmt.Fprintf(&output, "\nObservations (%d)\n", len(value.Observations))
	fmt.Fprintln(&output, "----------------")
	if len(value.Observations) == 0 {
		fmt.Fprintln(&output, "None")
	}
	for _, observation := range value.Observations {
		fmt.Fprintf(&output, "%s: %s\n", observation.Key, observation.Value)
	}

	fmt.Fprintf(&output, "\nErrors (%d)\n", len(value.Errors))
	fmt.Fprintln(&output, "----------")
	if len(value.Errors) == 0 {
		fmt.Fprintln(&output, "None")
	}
	for _, reportError := range value.Errors {
		fmt.Fprintf(&output, "%s: %s\n", reportError.Code, reportError.Message)
	}

	return writeAll(writer, output.Bytes())
}

func (textRenderer) RenderComparison(writer io.Writer, value report.Comparison) error {
	var output bytes.Buffer
	fmt.Fprintln(&output, "RaxuisCLI Audit Comparison")
	fmt.Fprintln(&output, "==========================")
	fmt.Fprintf(&output, "Before: %s (%s)\n", value.Before.Audit.ID, value.Before.Audit.Target)
	fmt.Fprintf(&output, "After: %s (%s)\n", value.After.Audit.ID, value.After.Audit.Target)
	fmt.Fprintf(&output, "Kind: %s\n", value.After.Audit.Kind)

	view := newComparisonView(value)

	fmt.Fprintf(&output, "\nRegressions (%d)\n", len(value.Findings.Added)+len(view.Worsened))
	fmt.Fprintln(&output, "---------------")
	if len(value.Findings.Added) == 0 && len(view.Worsened) == 0 {
		fmt.Fprintln(&output, "None")
	}
	for _, finding := range value.Findings.Added {
		fmt.Fprintf(&output, "ADDED [%s] %s\n  Rule: %s\n  Resource: %s\n", finding.Severity, finding.Title, finding.RuleID, finding.Resource)
	}
	for _, change := range view.Worsened {
		fmt.Fprintf(&output, "WORSENED [%s -> %s] %s\n  Rule: %s\n  Resource: %s\n", change.Before.Severity, change.After.Severity, change.After.Title, change.After.RuleID, change.After.Resource)
		writeChangeSummary(&output, change)
	}

	fmt.Fprintf(&output, "\nResolutions (%d)\n", len(value.Findings.Resolved)+len(view.Improved))
	fmt.Fprintln(&output, "---------------")
	if len(value.Findings.Resolved) == 0 && len(view.Improved) == 0 {
		fmt.Fprintln(&output, "None")
	}
	for _, finding := range value.Findings.Resolved {
		fmt.Fprintf(&output, "RESOLVED [%s] %s\n  Rule: %s\n  Resource: %s\n", finding.Severity, finding.Title, finding.RuleID, finding.Resource)
	}
	for _, change := range view.Improved {
		fmt.Fprintf(&output, "IMPROVED [%s -> %s] %s\n  Rule: %s\n  Resource: %s\n", change.Before.Severity, change.After.Severity, change.After.Title, change.After.RuleID, change.After.Resource)
		writeChangeSummary(&output, change)
	}

	fmt.Fprintf(&output, "\nOther finding changes (%d)\n", len(view.Other))
	fmt.Fprintln(&output, "-------------------------")
	if len(view.Other) == 0 {
		fmt.Fprintln(&output, "None")
	}
	for _, change := range view.Other {
		fmt.Fprintf(&output, "CHANGED [%s] %s\n  Rule: %s\n", change.After.Severity, change.After.Title, change.After.RuleID)
		writeChangeSummary(&output, change)
	}

	fmt.Fprintf(&output, "\nObservations: %d added, %d removed, %d changed\n", len(value.Observations.Added), len(value.Observations.Removed), len(value.Observations.Changed))
	return writeAll(writer, output.Bytes())
}

type comparisonView struct {
	Comparison report.Comparison
	Worsened   []report.FindingChange
	Improved   []report.FindingChange
	Other      []report.FindingChange
}

func newComparisonView(value report.Comparison) comparisonView {
	result := comparisonView{Comparison: value, Worsened: make([]report.FindingChange, 0), Improved: make([]report.FindingChange, 0), Other: make([]report.FindingChange, 0)}
	for _, change := range value.Findings.Changed {
		switch {
		case change.SeverityWorsened:
			result.Worsened = append(result.Worsened, change)
		case change.SeverityImproved:
			result.Improved = append(result.Improved, change)
		default:
			result.Other = append(result.Other, change)
		}
	}
	return result
}

func writeChangeSummary(output *bytes.Buffer, change report.FindingChange) {
	if summary := changeSummary(change); summary != "" {
		fmt.Fprintf(output, "  Changes: %s\n", summary)
	}
}

func changeSummary(change report.FindingChange) string {
	labels := make([]string, 0, 7)
	if change.EvidenceChanged {
		labels = append(labels, "Evidence changed")
	}
	if change.Before.Title != change.After.Title {
		labels = append(labels, "Title changed")
	}
	if change.Before.Type != change.After.Type {
		labels = append(labels, "Type changed")
	}
	if change.Before.Status != change.After.Status {
		labels = append(labels, "Status changed")
	}
	if change.Before.Parameter != change.After.Parameter {
		labels = append(labels, "Parameter changed")
	}
	if change.Before.Payload != change.After.Payload {
		labels = append(labels, "Payload changed")
	}
	if change.Before.Description != change.After.Description {
		labels = append(labels, "Description changed")
	}
	if change.Before.Remediation != change.After.Remediation {
		labels = append(labels, "Remediation changed")
	}
	return strings.Join(labels, "; ")
}
