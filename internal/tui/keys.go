package tui

import "charm.land/bubbles/v2/key"

// keyMap collects the keyboard bindings for the interface. Navigation works
// without a mouse; every action reachable from the UI has a binding here.
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
