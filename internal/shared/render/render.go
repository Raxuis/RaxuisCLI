// Package render formats versioned reports for people and programs.
package render

import (
	"fmt"
	"io"
	"strings"

	"github.com/Raxuis/RaxuisCLI/internal/shared/report"
)

// Renderer writes a report to an output stream.
type Renderer interface {
	Render(io.Writer, report.Report) error
}

// Format identifies a supported report representation.
type Format string

const (
	// FormatText is a human-readable terminal-friendly report.
	FormatText Format = "text"
	// FormatJSON is the schema-v1 machine-readable report envelope.
	FormatJSON Format = "json"
	// FormatHTML is the self-contained human-readable HTML report.
	FormatHTML Format = "html"
)

// RendererFor returns the renderer for format. Format matching is
// case-insensitive to keep command integration straightforward.
func RendererFor(format string) (Renderer, error) {
	switch Format(strings.ToLower(strings.TrimSpace(format))) {
	case FormatText:
		return NewTextRenderer(), nil
	case FormatJSON:
		return NewJSONRenderer(), nil
	case FormatHTML:
		return NewHTMLRenderer(), nil
	default:
		return nil, fmt.Errorf("unsupported report format %q", format)
	}
}

// Render selects a renderer and writes value to writer.
func Render(writer io.Writer, format string, value report.Report) error {
	renderer, err := RendererFor(format)
	if err != nil {
		return err
	}
	return renderer.Render(writer, value)
}

func writeAll(writer io.Writer, content []byte) error {
	for len(content) > 0 {
		written, err := writer.Write(content)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		content = content[written:]
	}
	return nil
}
