package tui

import (
	"os"
	"strings"

	"charm.land/lipgloss/v2"
)

// Palette mirrors the HTML report theme so the terminal interface and the saved
// reports read as one product.
type Palette struct {
	Background string
	Surface    string
	Line       string
	Text       string
	Muted      string
	Accent     string // muted mint
	SelectedBg string // soft selected-row background, no side border
}

var DarkPalette = Palette{
	Background: "#0b1220",
	Surface:    "#121c2d",
	Line:       "#26354c",
	Text:       "#e5edf5",
	Muted:      "#9aabc0",
	Accent:     "#72e3c1",
	SelectedBg: "#16263c",
}

type Styles struct {
	Color        bool // consulted by badge helpers so their inline colors honor the same decision
	App          lipgloss.Style
	Title        lipgloss.Style
	Muted        lipgloss.Style
	Accent       lipgloss.Style
	Item         lipgloss.Style
	SelectedItem lipgloss.Style
	Footer       lipgloss.Style
}

// When enabled is false every style is plain text, so redirected output, dumb
// terminals, and NO_COLOR stay clean.
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
		Color:        true,
		App:          base.Foreground(lipgloss.Color(p.Text)),
		Title:        base.Foreground(accent).Bold(true),
		Muted:        base.Foreground(lipgloss.Color(p.Muted)),
		Accent:       base.Foreground(accent),
		Item:         base.Foreground(lipgloss.Color(p.Text)).PaddingLeft(2),
		SelectedItem: base.Foreground(accent).Background(lipgloss.Color(p.SelectedBg)).Bold(true).PaddingLeft(2),
		Footer:       base.Foreground(lipgloss.Color(p.Muted)),
	}
}

// ColorEnabled honors --no-color, NO_COLOR, dumb terminals, and non-terminal
// output. lookupEnv and isTTY are injected so the decision is testable.
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
