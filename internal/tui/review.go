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
		{"Scope", data.Scope},
		{"Expected duration", data.Duration},
		{"Output", data.Output},
		{"Safety level", data.Safety},
	}
	var b strings.Builder
	b.WriteString(styles.Title.Render("Review"))
	b.WriteString("\n\n")
	for _, row := range rows {
		b.WriteString(styles.Muted.Render(fmt.Sprintf("%-18s", row[0]+":")))
		b.WriteString(" ")
		b.WriteString(styles.App.Render(row[1]))
		b.WriteString("\n")
	}
	b.WriteString("\n")
	b.WriteString(styles.Muted.Render("Equivalent command"))
	b.WriteString("\n")
	b.WriteString(styles.Accent.Render("  " + data.Command))
	return b.String()
}
