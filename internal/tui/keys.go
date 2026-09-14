package tui

import (
	"charm.land/bubbles/v2/key"
	tea "charm.land/bubbletea/v2"
)

// Wrapped here so view files need not import the key package.
func matchesBinding(msg tea.KeyPressMsg, binding key.Binding) bool {
	return key.Matches(msg, binding)
}

type keyMap struct {
	Up      key.Binding
	Down    key.Binding
	Confirm key.Binding
	Back    key.Binding
	Search  key.Binding
	Quit    key.Binding
}

func defaultKeyMap() keyMap {
	return keyMap{
		Up: key.NewBinding(
			key.WithKeys("up", "k"),
			key.WithHelp("↑/k", "move up"),
		),
		Down: key.NewBinding(
			key.WithKeys("down", "j"),
			key.WithHelp("↓/j", "move down"),
		),
		Confirm: key.NewBinding(
			key.WithKeys("enter"),
			key.WithHelp("enter", "confirm"),
		),
		Back: key.NewBinding(
			key.WithKeys("esc"),
			key.WithHelp("esc", "back"),
		),
		Search: key.NewBinding(
			key.WithKeys("ctrl+k", "/"),
			key.WithHelp("ctrl+k", "search"),
		),
		Quit: key.NewBinding(
			key.WithKeys("ctrl+c", "q"),
			key.WithHelp("q", "quit"),
		),
	}
}
