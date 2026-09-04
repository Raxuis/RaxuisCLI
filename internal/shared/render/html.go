package render

import (
	"bytes"
	_ "embed"
	"fmt"
	"html/template"
	"io"
	"strings"

	"raxuiscli/internal/shared/constants"
	"raxuiscli/internal/shared/report"
)

//go:embed templates/report.html
var reportHTMLTemplate string

//go:embed templates/report.css
var reportCSS string

type htmlRenderer struct {
	template *template.Template
}

type htmlReport struct {
	Report report.Report
	Counts []severityCount
}

type severityCount struct {
	Name  string
	Class string
	Count int
}

// NewHTMLRenderer returns a renderer for a self-contained audit report.
func NewHTMLRenderer() Renderer {
	return htmlRenderer{template: newHTMLTemplate()}
}

func (renderer htmlRenderer) Render(writer io.Writer, value report.Report) error {
	var output bytes.Buffer
	if err := renderer.template.Execute(&output, htmlReport{Report: value, Counts: severityCounts(value)}); err != nil {
		return fmt.Errorf("execute HTML report template: %w", err)
	}
	return writeAll(writer, output.Bytes())
}

func newHTMLTemplate() *template.Template {
	const cssPlaceholder = "{{ .EmbeddedCSS }}"
	source := strings.Replace(reportHTMLTemplate, cssPlaceholder, reportCSS, 1)
	return template.Must(template.New("report.html").Funcs(template.FuncMap{
		"severityClass": severityClass,
	}).Parse(source))
}

func severityCounts(value report.Report) []severityCount {
	severities := []constants.Severity{
		constants.SeverityCritical,
		constants.SeverityHigh,
		constants.SeverityMedium,
		constants.SeverityLow,
		constants.SeverityInfo,
	}
	counts := make([]severityCount, len(severities))
	for index, severity := range severities {
		counts[index] = severityCount{Name: severity.String(), Class: severityClass(severity), Count: 0}
	}
	for _, finding := range value.Findings {
		for index := range counts {
			if finding.Severity.String() == counts[index].Name {
				counts[index].Count++
				break
			}
		}
	}
	return counts
}

func severityClass(severity constants.Severity) string {
	return strings.ToLower(severity.String())
}
