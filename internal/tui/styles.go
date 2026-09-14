package tui

import (
	"os"
	"strings"

	"charm.land/lipgloss/v2"
)

// Palette holds the approved dark command-palette colors. The values mirror the
// HTML report theme so the terminal interface and the saved reports read as one
// product.
type Palette struct {
	Background string
	Surface    string
	Line       string
	Text       string
	Muted      string
	Accent     string // muted mint
	SelectedBg string // soft selected-row background, no side border
}

// DarkPalette is the approved dark, restrained direction.
var DarkPalette = Palette{
	Background: "#0b1220",
	Surface:    "#121c2d",
	Line:       "#26354c",
	Text:       "#e5edf5",
	Muted:      "#9aabc0",
	Accent:     "#72e3c1",
	SelectedBg: "#16263c",
}

// Styles are the reusable lip gloss styles for the interface. When color is
// disabled every style degrades to plain text so redirected output, dumb
// terminals, and NO_COLOR stay clean and deterministic.
type Styles struct {
	App          lipgloss.Style
	Title        lipgloss.Style
	Muted        lipgloss.Style
	Accent       lipgloss.Style
	Item         lipgloss.Style
	SelectedItem lipgloss.Style
	Footer       lipgloss.Style
}

// newStyles builds the interface styles from the approved dark palette. When
// enabled is false the styles carry no color or emphasis attributes so their
// Render output is the raw text.
func newStyles(enabled bool) Styles {
	p := DarkPalette
	base := lipgloss.NewStyle()
	if !enabled {
		item := base.PaddingLeft(2)
		return Styles{
			App:          base,
			Title:        base,
			Muted:        base,
			Accent:       base,
			Item:         item,
			SelectedItem: item,
			Footer:       base,
		}
	}

	accent := lipgloss.Color(p.Accent)
	return Styles{
		App:          base.Foreground(lipgloss.Color(p.Text)),
		Title:        base.Foreground(accent).Bold(true),
		Muted:        base.Foreground(lipgloss.Color(p.Muted)),
		Accent:       base.Foreground(accent),
		Item:         base.Foreground(lipgloss.Color(p.Text)).PaddingLeft(2),
		SelectedItem: base.Foreground(accent).Background(lipgloss.Color(p.SelectedBg)).Bold(true).PaddingLeft(2),
		Footer:       base.Foreground(lipgloss.Color(p.Muted)),
	}
}

// ColorEnabled reports whether colorized output should be produced. It honors
// the --no-color flag, the NO_COLOR convention, dumb terminals, and output that
// is not attached to a terminal. lookupEnv and isTTY are injected so the
// decision is testable without touching the process environment.
func ColorEnabled(noColorFlag bool, lookupEnv func(string) (string, bool), isTTY bool) bool {
	if noColorFlag {
		return false
	}
	if _, ok := lookupEnv("NO_COLOR"); ok {
		return false
	}
	if term, ok := lookupEnv("TERM"); ok && strings.EqualFold(strings.TrimSpace(term), "dumb") {
		return false
	}
	return isTTY
}

// isTerminal reports whether f refers to a character device (a real terminal)
// rather than a pipe or regular file.
func isTerminal(f *os.File) bool {
	if f == nil {
		return false
	}
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}
