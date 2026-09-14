package tui

import (
	"fmt"
	"strings"

	"charm.land/bubbles/v2/key"
	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
)

// state enumerates the screens of the guided interface. The interface is a
// small, explicit state machine so update logic can be tested without a real
// terminal.
type state int

const (
	stateLoading state = iota
	stateHome
	stateSearch
	stateForm
	stateReview
	stateRunning
	stateResults
	stateError
	stateAbout
)

// narrowWidth is the terminal width below which the interface collapses to a
// single-column layout.
const narrowWidth = 72

// uiText centralizes every user-facing string. Keeping them in one place lets a
// future release localize the interface without touching update logic.
var uiText = struct {
	AppTitle     string
	Loading      string
	HomeHint     string
	SearchPrompt string
	SearchEmpty  string
	FormHint     string
	ReviewHint   string
	Running      string
	ResultsHint  string
	ErrorHeading string
	AboutHeading string
	AboutBody    string
	CreditText   string
	CreditURL    string
}{
	AppTitle:     "RaxuisCLI — Guided Interface",
	Loading:      "Loading…",
	HomeHint:     "↑/↓ move · enter select · ctrl+k search · q quit",
	SearchPrompt: "Search actions",
	SearchEmpty:  "No matching actions.",
	FormHint:     "enter continue · esc back",
	ReviewHint:   "enter run · esc back",
	Running:      "Running…",
	ResultsHint:  "esc home · q quit",
	ErrorHeading: "Something went wrong",
	AboutHeading: "About",
	AboutBody:    "RaxuisCLI is a passive security auditing toolkit.",
	CreditText:   "Created by Raxuis · github.com/raxuis",
	CreditURL:    "https://github.com/raxuis",
}

// actionID identifies a top-level action offered on the home palette.
type actionID int

const (
	actionAudit actionID = iota
	actionDemo
	actionCompare
	actionBrowse
	actionAbout
)

// action is a selectable entry in the command palette.
type action struct {
	id    actionID
	title string
	desc  string
}

func defaultActions() []action {
	return []action{
		{actionAudit, "Passive Web Audit", "Inspect HTTP headers and TLS for one target."},
		{actionDemo, "Local Demo", "Audit a safe in-process fixture on loopback."},
		{actionCompare, "Compare Reports", "Diff two saved audit snapshots."},
		{actionBrowse, "Browse Commands", "List every command and its maturity."},
		{actionAbout, "Help / About", "Learn what this interface can do."},
	}
}

// Config carries the settings the interface needs from the root command.
type Config struct {
	// Color enables colorized, styled output. Callers compute it with
	// ColorEnabled so the flag, environment, and terminal are all respected.
	Color bool
}

// readyMsg signals that startup work is finished and the home screen can show.
type readyMsg struct{}

// auditDoneMsg and auditFailedMsg model the completion of a run. The shell wires
// only the state transitions; the real audit service is connected in a later
// task.
type (
	auditDoneMsg   struct{ summary string }
	auditFailedMsg struct{ err error }
)

// Model is the Bubble Tea model for the guided interface.
type Model struct {
	state    state
	keys     keyMap
	styles   Styles
	actions  []action
	cursor   int
	search   textinput.Model
	width    int
	summary  string
	err      error
	quitting bool
}

// New builds the interface model from cfg.
func New(cfg Config) Model {
	search := textinput.New()
	search.Placeholder = uiText.SearchPrompt

	return Model{
		state:   stateLoading,
		keys:    defaultKeyMap(),
		styles:  newStyles(cfg.Color),
		actions: defaultActions(),
		search:  search,
	}
}

// Init implements tea.Model.
func (m Model) Init() tea.Cmd {
	return func() tea.Msg { return readyMsg{} }
}

// narrow reports whether the interface should use a single-column layout.
func (m Model) narrow() bool {
	return m.width > 0 && m.width < narrowWidth
}

// visibleActions returns the actions matching the current search query.
func (m Model) visibleActions() []action {
	q := strings.TrimSpace(strings.ToLower(m.search.Value()))
	if q == "" {
		return m.actions
	}
	var out []action
	for _, a := range m.actions {
		if strings.Contains(strings.ToLower(a.title), q) {
			out = append(out, a)
		}
	}
	return out
}

// Update implements tea.Model.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		return m, nil
	case readyMsg:
		if m.state == stateLoading {
			m.state = stateHome
		}
		return m, nil
	case auditDoneMsg:
		if m.state == stateRunning {
			m.state = stateResults
			m.summary = msg.summary
		}
		return m, nil
	case auditFailedMsg:
		if m.state == stateRunning {
			m.state = stateError
			m.err = msg.err
		}
		return m, nil
	case tea.KeyPressMsg:
		return m.handleKey(msg)
	}
	return m, nil
}

func (m Model) handleKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	// Ctrl+C always quits, even while typing.
	if msg.String() == "ctrl+c" {
		m.quitting = true
		return m, tea.Quit
	}

	switch m.state {
	case stateSearch:
		return m.updateSearch(msg)
	case stateHome:
		return m.updateHome(msg)
	case stateForm:
		switch {
		case key.Matches(msg, m.keys.Back):
			m.state = stateHome
		case key.Matches(msg, m.keys.Confirm):
			m.state = stateReview
		}
		return m, nil
	case stateReview:
		return m.updateReview(msg)
	case stateResults, stateError, stateAbout:
		return m.updateInfo(msg)
	case stateRunning:
		// Runs are non-interactive; only Ctrl+C (handled above) interrupts.
		return m, nil
	}
	return m, nil
}

func (m Model) updateHome(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch {
	case key.Matches(msg, m.keys.Quit):
		m.quitting = true
		return m, tea.Quit
	case key.Matches(msg, m.keys.Search):
		m.state = stateSearch
		m.cursor = 0
		return m, m.search.Focus()
	case key.Matches(msg, m.keys.Up):
		if m.cursor > 0 {
			m.cursor--
		}
		return m, nil
	case key.Matches(msg, m.keys.Down):
		if m.cursor < len(m.visibleActions())-1 {
			m.cursor++
		}
		return m, nil
	case key.Matches(msg, m.keys.Confirm):
		return m.selectAction(), nil
	}
	return m, nil
}

func (m Model) updateSearch(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch {
	case key.Matches(msg, m.keys.Back):
		m.search.SetValue("")
		m.search.Blur()
		m.cursor = 0
		m.state = stateHome
		return m, nil
	case key.Matches(msg, m.keys.Confirm):
		m.search.Blur()
		m.state = stateHome
		return m.selectAction(), nil
	}

	var cmd tea.Cmd
	m.search, cmd = m.search.Update(msg)
	if m.cursor >= len(m.visibleActions()) {
		m.cursor = 0
	}
	return m, cmd
}

// selectAction opens the screen for the highlighted action.
func (m Model) selectAction() Model {
	visible := m.visibleActions()
	if len(visible) == 0 {
		return m
	}
	if m.cursor >= len(visible) {
		m.cursor = len(visible) - 1
	}
	if visible[m.cursor].id == actionAbout {
		m.state = stateAbout
		return m
	}
	m.state = stateForm
	return m
}

func (m Model) updateReview(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch {
	case key.Matches(msg, m.keys.Back):
		m.state = stateForm
		return m, nil
	case key.Matches(msg, m.keys.Confirm):
		m.state = stateRunning
		return m, func() tea.Msg { return auditDoneMsg{summary: "0 findings"} }
	}
	return m, nil
}

func (m Model) updateInfo(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch {
	case key.Matches(msg, m.keys.Quit):
		m.quitting = true
		return m, tea.Quit
	case key.Matches(msg, m.keys.Back):
		m.state = stateHome
		m.err = nil
		m.summary = ""
		return m, nil
	}
	return m, nil
}

// View implements tea.Model.
func (m Model) View() tea.View {
	if m.quitting {
		return tea.NewView("")
	}
	return tea.NewView(m.render())
}

func (m Model) render() string {
	var b strings.Builder
	b.WriteString(m.styles.Title.Render(uiText.AppTitle))
	b.WriteString("\n\n")
	b.WriteString(m.body())
	b.WriteString("\n\n")
	b.WriteString(m.styles.Footer.Render(uiText.CreditText))
	return b.String()
}

func (m Model) body() string {
	switch m.state {
	case stateLoading:
		return m.styles.Muted.Render(uiText.Loading)
	case stateHome, stateSearch:
		return m.homeBody()
	case stateForm:
		return m.styles.App.Render("Enter target and options.") + "\n\n" + m.styles.Muted.Render(uiText.FormHint)
	case stateReview:
		return m.styles.App.Render("Review the equivalent command.") + "\n\n" + m.styles.Muted.Render(uiText.ReviewHint)
	case stateRunning:
		return m.styles.Muted.Render(uiText.Running)
	case stateResults:
		summary := m.summary
		if summary == "" {
			summary = "Done."
		}
		return m.styles.App.Render(summary) + "\n\n" + m.styles.Muted.Render(uiText.ResultsHint)
	case stateError:
		msg := "unknown error"
		if m.err != nil {
			msg = m.err.Error()
		}
		return m.styles.Title.Render(uiText.ErrorHeading) + "\n" + m.styles.App.Render(msg) + "\n\n" + m.styles.Muted.Render(uiText.ResultsHint)
	case stateAbout:
		return m.aboutBody()
	}
	return ""
}

func (m Model) homeBody() string {
	var b strings.Builder
	if m.state == stateSearch {
		b.WriteString(m.search.View())
		b.WriteString("\n\n")
	}

	visible := m.visibleActions()
	if len(visible) == 0 {
		b.WriteString(m.styles.Muted.Render(uiText.SearchEmpty))
		return b.String()
	}

	for i, a := range visible {
		style := m.styles.Item
		marker := "  "
		if i == m.cursor {
			style = m.styles.SelectedItem
			marker = "▸ "
		}
		line := marker + a.title
		if !m.narrow() {
			line = fmt.Sprintf("%s — %s", line, a.desc)
		}
		b.WriteString(style.Render(line))
		b.WriteString("\n")
	}
	b.WriteString("\n")
	b.WriteString(m.styles.Muted.Render(uiText.HomeHint))
	return b.String()
}

func (m Model) aboutBody() string {
	var b strings.Builder
	b.WriteString(m.styles.Title.Render(uiText.AboutHeading))
	b.WriteString("\n")
	b.WriteString(m.styles.App.Render(uiText.AboutBody))
	b.WriteString("\n\n")
	b.WriteString(m.styles.Accent.Render(uiText.CreditText))
	b.WriteString("\n")
	b.WriteString(m.styles.Muted.Render(uiText.CreditURL))
	b.WriteString("\n\n")
	b.WriteString(m.styles.Muted.Render(uiText.ResultsHint))
	return b.String()
}
