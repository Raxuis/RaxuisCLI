// Package tui implements the guided terminal interface for RaxuisCLI. It is a
// small, explicit Bubble Tea state machine kept isolated from the audit and
// report packages so those never depend on terminal UI libraries.
package tui

import (
	"os"

	tea "charm.land/bubbletea/v2"
)

func ConfigFromEnv(noColor bool) Config {
	return Config{
		Color: ColorEnabled(noColor, os.LookupEnv, isTerminal(os.Stdout)),
	}
}

func Run(cfg Config) error {
	_, err := tea.NewProgram(New(cfg)).Run()
	return err
}
