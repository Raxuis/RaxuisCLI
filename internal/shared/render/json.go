package render

import (
	"encoding/json"
	"fmt"
	"io"

	"raxuiscli/internal/shared/report"
)

type jsonRenderer struct{}

// NewJSONRenderer returns a renderer for the stable report envelope. It emits
// no presentation text, allowing the result to be consumed directly by tools.
func NewJSONRenderer() Renderer {
	return jsonRenderer{}
}

func (jsonRenderer) Render(writer io.Writer, value report.Report) error {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal report JSON: %w", err)
	}
	return writeAll(writer, append(encoded, '\n'))
}

func (jsonRenderer) RenderComparison(writer io.Writer, value report.Comparison) error {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal comparison JSON: %w", err)
	}
	return writeAll(writer, append(encoded, '\n'))
}
