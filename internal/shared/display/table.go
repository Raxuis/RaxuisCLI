package display

import (
	"fmt"
	"strings"
)

// PrintTable prints a simple table with headers and rows
func PrintTable(headers []string, rows [][]string) {
	if len(headers) == 0 {
		return
	}

	// Calculate column widths
	widths := make([]int, len(headers))
	for i, h := range headers {
		widths[i] = len(h)
	}

	for _, row := range rows {
		for i, cell := range row {
			if i < len(widths) && len(cell) > widths[i] {
				widths[i] = len(cell)
			}
		}
	}

	// Print header
	printRow(headers, widths, true)
	printSeparator(widths)

	// Print rows
	for _, row := range rows {
		printRow(row, widths, false)
	}
}

func printRow(cells []string, widths []int, isHeader bool) {
	parts := make([]string, len(cells))
	for i, cell := range cells {
		width := 10
		if i < len(widths) {
			width = widths[i]
		}
		if isHeader {
			parts[i] = fmt.Sprintf(BoldWhite+"%-*s"+Reset, width, cell)
		} else {
			parts[i] = fmt.Sprintf("%-*s", width, cell)
		}
	}
	fmt.Println("  " + strings.Join(parts, "  "))
}

func printSeparator(widths []int) {
	parts := make([]string, len(widths))
	for i, w := range widths {
		parts[i] = strings.Repeat("-", w)
	}
	fmt.Println("  " + strings.Join(parts, "  "))
}

// PrintKeyValue prints a key-value pair with consistent formatting
func PrintKeyValue(key, value string) {
	fmt.Printf("  %s%-15s%s %s\n", BoldCyan, key+":", Reset, value)
}

// PrintKeyValueIndent prints a key-value pair with custom indentation
func PrintKeyValueIndent(key, value string, indent int) {
	indentStr := strings.Repeat(" ", indent)
	fmt.Printf("%s%s%-15s%s %s\n", indentStr, BoldCyan, key+":", Reset, value)
}

// PrintSection prints a section header
func PrintSection(title string) {
	fmt.Printf("\n%s[%s]%s\n", BoldWhite, title, Reset)
	fmt.Println(strings.Repeat("-", len(title)+2))
}

// PrintHeader prints a main header
func PrintHeader(title string) {
	width := 80
	fmt.Println()
	fmt.Println(strings.Repeat("=", width))
	padding := (width - len(title)) / 2
	fmt.Printf("%s%s%s%s\n", strings.Repeat(" ", padding), BoldWhite, title, Reset)
	fmt.Println(strings.Repeat("=", width))
}

// PrintSubHeader prints a sub-header
func PrintSubHeader(title string) {
	fmt.Printf("\n%s%s%s\n", BoldYellow, title, Reset)
	fmt.Println(strings.Repeat("-", len(title)))
}

// PrintBullet prints a bulleted item
func PrintBullet(text string) {
	fmt.Printf("  • %s\n", text)
}

// PrintNumbered prints a numbered item
func PrintNumbered(num int, text string) {
	fmt.Printf("  %d. %s\n", num, text)
}

// PrintBox prints text in a box
func PrintBox(lines []string, width int) {
	if width <= 0 {
		width = 60
	}

	border := "+" + strings.Repeat("-", width-2) + "+"
	fmt.Println(border)

	for _, line := range lines {
		padding := width - 4 - len(line)
		if padding < 0 {
			padding = 0
			line = line[:width-7] + "..."
		}
		fmt.Printf("| %s%s |\n", line, strings.Repeat(" ", padding))
	}

	fmt.Println(border)
}
