package render

import (
	"bytes"
	"fmt"
	"io"
	"time"

	"raxuiscli/internal/shared/report"
)

type textRenderer struct{}

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
