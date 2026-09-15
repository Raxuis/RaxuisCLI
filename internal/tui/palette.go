package tui

import (
	"strings"

	"charm.land/lipgloss/v2"

	"raxuiscli/internal/shared/catalog"
)

// actionID identifies a top-level action offered on the home palette.
type actionID int

const (
	actionAudit actionID = iota
	actionDemo
	actionCompare
	actionBrowse
	actionAbout
)

type paletteItem struct {
	id       actionID
	title    string
	summary  string
	path     string // catalog command path, empty for interface-only actions
	maturity catalog.Maturity
	safety   catalog.SafetyLevel
}

// Maturity and safety come from the catalog so the interface and the docs never disagree.
func initialActions() []paletteItem {
	specs := []struct {
		id      actionID
		title   string
		summary string
		path    string
	}{
		{actionAudit, uiText.ActionAuditTitle, uiText.ActionAuditSummary, "raxuiscli audit web"},
		{actionDemo, uiText.ActionDemoTitle, uiText.ActionDemoSummary, "raxuiscli demo web"},
		{actionCompare, uiText.ActionCompareTitle, uiText.ActionCompareSummary, "raxuiscli compare"},
		{actionBrowse, uiText.ActionBrowseTitle, uiText.ActionBrowseSummary, ""},
		{actionAbout, uiText.ActionAboutTitle, uiText.ActionAboutSummary, ""},
	}
	items := make([]paletteItem, 0, len(specs))
	for _, spec := range specs {
		item := paletteItem{
			id:       spec.id,
			title:    spec.title,
			summary:  spec.summary,
			path:     spec.path,
			maturity: catalog.MaturityStable,
			safety:   catalog.SafetySafe,
		}
		if spec.path != "" {
			if entry, ok := catalog.Lookup(spec.path); ok {
				item.maturity = entry.Maturity
				item.safety = entry.Safety
			}
		}
		items = append(items, item)
	}
	return items
}

func browseItems() []paletteItem {
	entries := catalog.All()
	items := make([]paletteItem, 0, len(entries))
	for _, entry := range entries {
		items = append(items, paletteItem{
			id:       actionBrowse,
			title:    entry.Path,
			summary:  entry.Summary,
			path:     entry.Path,
			maturity: entry.Maturity,
			safety:   entry.Safety,
		})
	}
	return items
}

func filterItems(items []paletteItem, query string) []paletteItem {
	query = strings.TrimSpace(query)
	if query == "" {
		return items
	}
	out := make([]paletteItem, 0, len(items))
	for _, item := range items {
		if fuzzyMatch(query, item.title) || fuzzyMatch(query, item.summary) {
			out = append(out, item)
		}
	}
	return out
}

// Subsequence match, case-insensitive: "pwa" matches "Passive Web Audit".
func fuzzyMatch(query, target string) bool {
	q := []rune(strings.ToLower(query))
	if len(q) == 0 {
		return true
	}
	i := 0
	for _, r := range strings.ToLower(target) {
		if r == q[i] {
			i++
			if i == len(q) {
				return true
			}
		}
	}
	return false
}

func maturityBadge(styles Styles, maturity catalog.Maturity) string {
	label := string(maturity)
	switch maturity {
	case catalog.MaturityStable:
		label = uiText.MaturityStable
	case catalog.MaturityExperimental:
		label = uiText.MaturityExperimental
	case catalog.MaturityInformational:
		label = uiText.MaturityInformational
	}
	return badge(styles.Color, maturityColor(maturity), label)
}

func safetyBadge(styles Styles, safety catalog.SafetyLevel) string {
	return badge(styles.Color, safetyColor(safety), string(safety))
}

func maturityColor(maturity catalog.Maturity) string {
	switch maturity {
	case catalog.MaturityStable:
		return DarkPalette.Accent
	case catalog.MaturityExperimental:
		return badgeAmber
	case catalog.MaturityInformational:
		return badgeBlue
	}
	return DarkPalette.Muted
}

func safetyColor(safety catalog.SafetyLevel) string {
	switch safety {
	case catalog.SafetySafe, catalog.SafetyPassive:
		return DarkPalette.Accent
	case catalog.SafetyActive:
		return badgeAmber
	case catalog.SafetyDangerous:
		return badgePink
	}
	return DarkPalette.Muted
}

const (
	badgeAmber = "#fbbf24"
	badgeBlue  = "#38bdf8"
	badgePink  = "#fb7185"
)

func badge(colorEnabled bool, hexColor, label string) string {
	text := "[" + label + "]"
	if !colorEnabled {
		return text
	}
	return lipgloss.NewStyle().Foreground(lipgloss.Color(hexColor)).Render(text)
}
