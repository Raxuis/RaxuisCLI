package tui

import (
	"fmt"
	"strings"
)

type reviewData struct {
	Scope    string
	Duration string
	Output   string
	Safety   string
	Command  string // pre-masked by its form
}

func renderReview(styles Styles, data reviewData) string {
	rows := [][2]string{
		{uiText.ReviewScope, data.Scope},
		{uiText.ReviewDuration, data.Duration},
		{uiText.ReviewOutput, data.Output},
		{uiText.ReviewSafety, data.Safety},
	}
	var b strings.Builder
	b.WriteString(styles.Title.Render(uiText.ReviewHeading))
	b.WriteString("\n\n")
	for _, row := range rows {
		b.WriteString(styles.Muted.Render(fmt.Sprintf("%-18s", row[0]+":")))
		b.WriteString(" ")
		b.WriteString(styles.App.Render(row[1]))
		b.WriteString("\n")
	}
	b.WriteString("\n")
	b.WriteString(styles.Muted.Render(uiText.ReviewCommandHeading))
	b.WriteString("\n")
	b.WriteString(styles.Accent.Render("  " + data.Command))
	return b.String()
}
