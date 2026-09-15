package tui

import (
	"context"
	"errors"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"

	webaudit "github.com/Raxuis/RaxuisCLI/internal/audit/web"
	"github.com/Raxuis/RaxuisCLI/internal/shared/report"
)

func newTestModel() Model { return New(Config{Color: false}) }

func step(t *testing.T, m Model, msg tea.Msg) Model {
	t.Helper()
	next, _ := m.Update(msg)
	got, ok := next.(Model)
	if !ok {
		t.Fatalf("Update returned %T, want tui.Model", next)
	}
	return got
}

func enter() tea.KeyPressMsg { return tea.KeyPressMsg{Code: tea.KeyEnter} }
func esc() tea.KeyPressMsg   { return tea.KeyPressMsg{Code: tea.KeyEsc} }
func up() tea.KeyPressMsg    { return tea.KeyPressMsg{Code: tea.KeyUp} }
func down() tea.KeyPressMsg  { return tea.KeyPressMsg{Code: tea.KeyDown} }
func ctrlK() tea.KeyPressMsg { return tea.KeyPressMsg{Code: 'k', Mod: tea.ModCtrl} }
func runeKey(r rune) tea.KeyPressMsg {
	return tea.KeyPressMsg{Code: r, Text: string(r)}
}

func TestStartsInLoadingThenHome(t *testing.T) {
	m := newTestModel()
	if m.state != stateLoading {
		t.Fatalf("initial state = %v, want loading", m.state)
	}
	m = step(t, m, readyMsg{})
	if m.state != stateHome {
		t.Fatalf("after ready state = %v, want home", m.state)
	}
}

func TestHomeCursorNavigationIsBounded(t *testing.T) {
	m := step(t, newTestModel(), readyMsg{})
	m = step(t, m, up()) // already at top
	if m.cursor != 0 {
		t.Fatalf("cursor after up at top = %d, want 0", m.cursor)
	}
	for i := 0; i < len(m.items)+3; i++ {
		m = step(t, m, down())
	}
	if want := len(m.items) - 1; m.cursor != want {
		t.Fatalf("cursor after many downs = %d, want %d", m.cursor, want)
	}
}

func TestHomeSelectOpensAuditForm(t *testing.T) {
	m := step(t, newTestModel(), readyMsg{})
	m = step(t, m, enter()) // first action is the audit
	if m.state != stateForm || m.selected != actionAudit {
		t.Fatalf("state = %v selected = %v, want form/audit", m.state, m.selected)
	}
}

func TestSearchFiltersToCompare(t *testing.T) {
	m := step(t, newTestModel(), readyMsg{})
	m = step(t, m, ctrlK())
	if m.state != stateSearch {
		t.Fatalf("state = %v, want search", m.state)
	}
	for _, r := range "compare" {
		m = step(t, m, runeKey(r))
	}
	visible := m.visibleItems()
	if len(visible) != 1 || visible[0].id != actionCompare {
		t.Fatalf("visible = %+v, want only Compare Reports", visible)
	}
	m = step(t, m, enter())
	if m.state != stateForm || m.selected != actionCompare {
		t.Fatalf("state = %v selected = %v, want form/compare", m.state, m.selected)
	}
}

func TestSearchEscapeReturnsHomeAndClears(t *testing.T) {
	m := step(t, newTestModel(), readyMsg{})
	m = step(t, m, ctrlK())
	for _, r := range "compare" {
		m = step(t, m, runeKey(r))
	}
	m = step(t, m, esc())
	if m.state != stateHome {
		t.Fatalf("state = %v, want home", m.state)
	}
	if m.search.Value() != "" {
		t.Fatalf("search value = %q, want empty", m.search.Value())
	}
	if len(m.visibleItems()) != len(m.items) {
		t.Fatalf("filter not cleared: %d visible", len(m.visibleItems()))
	}
}

func TestAuditFormToReviewToRunToResults(t *testing.T) {
	fake := report.Report{Audit: report.AuditInfo{Target: "https://example.com"}}
	m := step(t, newTestModel(), readyMsg{})
	m.svc = services{audit: func(context.Context, string, webaudit.Options) (report.Report, error) {
		return fake, nil
	}}
	m = step(t, m, enter()) // -> audit form
	m.form.inputs[0].SetValue("https://example.com")
	m = step(t, m, enter()) // -> review
	if m.state != stateReview {
		t.Fatalf("state = %v, want review", m.state)
	}

	next, cmd := m.Update(enter()) // -> running, emits run command
	m = next.(Model)
	if m.state != stateRunning {
		t.Fatalf("state = %v, want running", m.state)
	}
	if cmd == nil {
		t.Fatal("expected a run command")
	}
	m = step(t, m, cmd())
	if m.state != stateResults || m.kind != kindReport {
		t.Fatalf("state = %v kind = %v, want results/report", m.state, m.kind)
	}
}

func TestAuditFormRejectsInvalidURL(t *testing.T) {
	m := step(t, newTestModel(), readyMsg{})
	m = step(t, m, enter()) // audit form
	m.form.inputs[0].SetValue("not a url")
	m = step(t, m, enter())
	if m.state != stateForm {
		t.Fatalf("state = %v, want form (invalid URL should not advance)", m.state)
	}
	if m.form.errText == "" {
		t.Fatal("expected an inline validation error")
	}
}

func TestReviewBackToForm(t *testing.T) {
	m := step(t, newTestModel(), readyMsg{})
	m = step(t, m, enter()) // form
	m.form.inputs[0].SetValue("https://example.com")
	m = step(t, m, enter()) // review
	m = step(t, m, esc())
	if m.state != stateForm {
		t.Fatalf("state = %v, want form", m.state)
	}
}

func TestRunningCancellation(t *testing.T) {
	cancelled := false
	m := newTestModel()
	m.state = stateRunning
	m.cancel = func() { cancelled = true }
	m = step(t, m, esc())
	if !cancelled {
		t.Fatal("esc during running did not cancel the context")
	}
	if m.state != stateReview || !m.cancelled {
		t.Fatalf("state = %v cancelled = %v, want review/true", m.state, m.cancelled)
	}
}

func TestRunningFailureGoesToError(t *testing.T) {
	m := newTestModel()
	m.state = stateRunning
	m = step(t, m, auditFailedMsg{err: errors.New("dial failed")})
	if m.state != stateError || m.err == nil {
		t.Fatalf("state = %v err = %v, want error state with error", m.state, m.err)
	}
}

func TestResultsAndErrorReturnHome(t *testing.T) {
	for _, s := range []state{stateResults, stateError} {
		m := newTestModel()
		m.state = s
		m.err = errors.New("x")
		m = step(t, m, esc())
		if m.state != stateHome {
			t.Fatalf("from %v, state = %v, want home", s, m.state)
		}
		if m.err != nil {
			t.Fatalf("error not cleared returning home")
		}
	}
}

func TestBrowseCommandsListing(t *testing.T) {
	m := step(t, newTestModel(), readyMsg{})
	for i := 0; i < 3; i++ { // navigate to Browse Commands (4th action)
		m = step(t, m, down())
	}
	m = step(t, m, enter())
	if m.state != stateBrowse {
		t.Fatalf("state = %v, want browse", m.state)
	}
	if len(m.browse) == 0 {
		t.Fatal("browse listing is empty")
	}
	m = step(t, m, down())
	if m.browseCursor != 1 {
		t.Fatalf("browse cursor = %d, want 1", m.browseCursor)
	}
	m = step(t, m, esc())
	if m.state != stateHome {
		t.Fatalf("state = %v, want home", m.state)
	}
}

func TestAboutStateFromHelpAction(t *testing.T) {
	m := step(t, newTestModel(), readyMsg{})
	for i := 0; i < len(m.items)-1; i++ {
		m = step(t, m, down())
	}
	m = step(t, m, enter())
	if m.state != stateAbout {
		t.Fatalf("state = %v, want about", m.state)
	}
	body := m.aboutBody()
	if !strings.Contains(body, "Created by Raxuis") || !strings.Contains(body, "github.com/raxuis") {
		t.Fatalf("about body missing credit: %q", body)
	}
	m = step(t, m, esc())
	if m.state != stateHome {
		t.Fatalf("state = %v, want home", m.state)
	}
}

func TestQuitFromHome(t *testing.T) {
	m := step(t, newTestModel(), readyMsg{})
	next, cmd := m.Update(runeKey('q'))
	m = next.(Model)
	if !m.quitting || cmd == nil {
		t.Fatalf("q did not quit: quitting=%v", m.quitting)
	}
}

func TestCtrlCQuitsWhileTyping(t *testing.T) {
	m := step(t, newTestModel(), readyMsg{})
	m = step(t, m, ctrlK()) // search state, input focused
	next, cmd := m.Update(tea.KeyPressMsg{Code: 'c', Mod: tea.ModCtrl})
	m = next.(Model)
	if !m.quitting || cmd == nil {
		t.Fatalf("ctrl+c during search did not quit: quitting=%v", m.quitting)
	}
}

func TestNarrowLayoutDropsDescriptions(t *testing.T) {
	m := step(t, newTestModel(), readyMsg{})

	wide := step(t, m, tea.WindowSizeMsg{Width: 120, Height: 40})
	if !strings.Contains(wide.homeBody(), "—") {
		t.Fatal("wide layout should include action descriptions")
	}

	narrow := step(t, m, tea.WindowSizeMsg{Width: 40, Height: 20})
	if !narrow.narrow() {
		t.Fatal("expected narrow() to be true at width 40")
	}
	if strings.Contains(narrow.homeBody(), "—") {
		t.Fatal("narrow layout should drop descriptions")
	}
}

func TestFooterCreditAlwaysRendered(t *testing.T) {
	m := step(t, newTestModel(), readyMsg{})
	view := m.render()
	if !strings.Contains(view, "Created by Raxuis · github.com/raxuis") {
		t.Fatalf("footer missing credit: %q", view)
	}
}

func TestNoColorRendersPlainText(t *testing.T) {
	m := step(t, New(Config{Color: false}), readyMsg{})
	if strings.Contains(m.render(), "\x1b") {
		t.Fatal("no-color render should contain no ANSI escape sequences")
	}
}

func TestColorRendersAnsi(t *testing.T) {
	m := step(t, New(Config{Color: true}), readyMsg{})
	if !strings.Contains(m.render(), "\x1b") {
		t.Fatal("color render should contain ANSI escape sequences")
	}
}

func TestColorEnabled(t *testing.T) {
	env := func(pairs map[string]string) func(string) (string, bool) {
		return func(k string) (string, bool) {
			v, ok := pairs[k]
			return v, ok
		}
	}
	tests := []struct {
		name    string
		noColor bool
		env     map[string]string
		isTTY   bool
		want    bool
	}{
		{"tty no flags", false, nil, true, true},
		{"not a tty", false, nil, false, false},
		{"no-color flag", true, nil, true, false},
		{"NO_COLOR set empty", false, map[string]string{"NO_COLOR": ""}, true, false},
		{"TERM dumb", false, map[string]string{"TERM": "dumb"}, true, false},
		{"TERM xterm", false, map[string]string{"TERM": "xterm-256color"}, true, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ColorEnabled(tc.noColor, env(tc.env), tc.isTTY)
			if got != tc.want {
				t.Fatalf("ColorEnabled = %v, want %v", got, tc.want)
			}
		})
	}
}
