package tui

import (
	"context"
	"fmt"
	"runtime"
	"strings"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"

	webaudit "github.com/Raxuis/RaxuisCLI/internal/audit/web"
	localdemo "github.com/Raxuis/RaxuisCLI/internal/demo"
	"github.com/Raxuis/RaxuisCLI/internal/shared/constants"
	"github.com/Raxuis/RaxuisCLI/internal/shared/report"
)

// An explicit state machine so update logic is testable without a real terminal.
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
	stateBrowse
)

type resultKind int

const (
	kindReport resultKind = iota
	kindComparison
)

const narrowWidth = 72

type Config struct {
	Color    bool   // compute with ColorEnabled to honor the flag, env, and terminal
	Force    bool   // allow a saved report to overwrite an existing file
	SavePath string // save destination; empty uses a format-appropriate default name
}

// Injectable so update logic and runs can be tested without a network.
type services struct {
	audit   func(context.Context, string, webaudit.Options) (report.Report, error)
	demo    func(context.Context) (report.Report, error)
	compare func(before, after string) (report.Comparison, error)
}

func defaultServices() services {
	return services{
		audit: webaudit.Audit,
		demo:  localdemo.Web,
		compare: func(before, after string) (report.Comparison, error) {
			beforeReport, err := report.ReadFile(before)
			if err != nil {
				return report.Comparison{}, err
			}
			afterReport, err := report.ReadFile(after)
			if err != nil {
				return report.Comparison{}, err
			}
			return report.Compare(beforeReport, afterReport, false)
		},
	}
}

// Run-completion messages. A run started while a context is live; the model
// ignores a completion whose state is no longer running (for example after the
// operator canceled).
type (
	auditDoneMsg struct {
		report report.Report
		output string
	}
	compareDoneMsg struct{ comparison report.Comparison }
	auditFailedMsg struct{ err error }
	readyMsg       struct{}
)

type Model struct {
	state  state
	keys   keyMap
	styles Styles
	config Config
	width  int

	items    []paletteItem
	cursor   int
	search   textinput.Model
	selected actionID

	form        auditForm
	compareForm compareForm

	report     report.Report
	comparison report.Comparison
	kind       resultKind
	output     string
	filter     constants.Severity
	savedPath  string

	browse       []paletteItem
	browseCursor int

	svc       services
	cancel    context.CancelFunc
	canceled bool
	err       error
	quitting  bool
}

func New(cfg Config) Model {
	search := textinput.New()
	search.Placeholder = uiText.SearchPrompt

	return Model{
		state:  stateLoading,
		keys:   defaultKeyMap(),
		styles: newStyles(cfg.Color),
		config: cfg,
		items:  initialActions(),
		search: search,
		filter: constants.SeverityNone,
		svc:    defaultServices(),
	}
}

func (m Model) Init() tea.Cmd {
	return func() tea.Msg { return readyMsg{} }
}

func (m Model) narrow() bool {
	return m.width > 0 && m.width < narrowWidth
}

func (m Model) visibleItems() []paletteItem {
	return filterItems(m.items, m.search.Value())
}

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
			m.clearCancel()
			m.report = msg.report
			m.kind = kindReport
			m.output = msg.output
			m.filter = constants.SeverityNone
			m.savedPath = ""
			m.state = stateResults
		}
		return m, nil
	case compareDoneMsg:
		if m.state == stateRunning {
			m.clearCancel()
			m.comparison = msg.comparison
			m.kind = kindComparison
			m.state = stateResults
		}
		return m, nil
	case auditFailedMsg:
		if m.state == stateRunning {
			m.clearCancel()
			m.err = msg.err
			m.state = stateError
		}
		return m, nil
	case tea.KeyPressMsg:
		return m.handleKey(msg)
	}
	return m, nil
}

func (m *Model) clearCancel() {
	if m.cancel != nil {
		m.cancel()
		m.cancel = nil
	}
}

func (m Model) handleKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	// Ctrl+C always quits, even while typing.
	if msg.String() == "ctrl+c" {
		m.clearCancel()
		m.quitting = true
		return m, tea.Quit
	}

	switch m.state {
	case stateSearch:
		return m.updateSearch(msg)
	case stateHome:
		return m.updateHome(msg)
	case stateForm:
		return m.updateForm(msg)
	case stateReview:
		return m.updateReview(msg)
	case stateRunning:
		if matchesBinding(msg, m.keys.Back) {
			m.clearCancel()
			m.canceled = true
			m.state = stateReview
		}
		return m, nil
	case stateResults:
		return m.updateResults(msg)
	case stateBrowse:
		return m.updateBrowse(msg)
	case stateError, stateAbout:
		return m.updateInfo(msg)
	}
	return m, nil
}

func (m Model) updateHome(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch {
	case matchesBinding(msg, m.keys.Quit):
		m.quitting = true
		return m, tea.Quit
	case matchesBinding(msg, m.keys.Search):
		m.state = stateSearch
		m.cursor = 0
		return m, m.search.Focus()
	case matchesBinding(msg, m.keys.Up):
		if m.cursor > 0 {
			m.cursor--
		}
		return m, nil
	case matchesBinding(msg, m.keys.Down):
		if m.cursor < len(m.visibleItems())-1 {
			m.cursor++
		}
		return m, nil
	case matchesBinding(msg, m.keys.Confirm):
		return m.selectItem(), nil
	}
	return m, nil
}

func (m Model) updateSearch(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch {
	case matchesBinding(msg, m.keys.Back):
		m.search.SetValue("")
		m.search.Blur()
		m.cursor = 0
		m.state = stateHome
		return m, nil
	case matchesBinding(msg, m.keys.Confirm):
		if len(m.visibleItems()) == 0 {
			return m, nil
		}
		m.search.Blur()
		m.state = stateHome
		return m.selectItem(), nil
	}

	var cmd tea.Cmd
	m.search, cmd = m.search.Update(msg)
	if m.cursor >= len(m.visibleItems()) {
		m.cursor = 0
	}
	return m, cmd
}

func (m Model) selectItem() Model {
	visible := m.visibleItems()
	if len(visible) == 0 {
		return m
	}
	if m.cursor >= len(visible) {
		m.cursor = len(visible) - 1
	}
	m.selected = visible[m.cursor].id
	switch m.selected {
	case actionAudit:
		m.form = newAuditForm()
		m.state = stateForm
	case actionCompare:
		m.compareForm = newCompareForm()
		m.state = stateForm
	case actionDemo:
		m.state = stateReview
	case actionBrowse:
		m.browse = browseItems()
		m.browseCursor = 0
		m.state = stateBrowse
	case actionAbout:
		m.state = stateAbout
	}
	return m
}

func (m Model) updateForm(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch {
	case matchesBinding(msg, m.keys.Back):
		m.state = stateHome
		return m, nil
	case matchesBinding(msg, m.keys.Confirm):
		if m.selected == actionCompare {
			if err := m.compareForm.validate(); err != nil {
				m.compareForm.errText = err.Error()
				return m, nil
			}
		} else if err := m.form.validate(); err != nil {
			m.form.errText = err.Error()
			return m, nil
		}
		m.state = stateReview
		return m, nil
	}

	var cmd tea.Cmd
	if m.selected == actionCompare {
		m.compareForm, cmd = m.compareForm.update(msg, m.keys)
	} else {
		m.form, cmd = m.form.update(msg, m.keys)
	}
	return m, cmd
}

func (m Model) updateReview(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch {
	case matchesBinding(msg, m.keys.Back):
		if m.selected == actionDemo {
			m.state = stateHome
		} else {
			m.state = stateForm
		}
		return m, nil
	case matchesBinding(msg, m.keys.Confirm):
		ctx, cancel := context.WithCancel(context.Background())
		m.cancel = cancel
		m.canceled = false
		m.state = stateRunning
		return m, m.runCmd(ctx)
	}
	return m, nil
}

func (m Model) updateResults(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch {
	case matchesBinding(msg, m.keys.Quit):
		m.quitting = true
		return m, tea.Quit
	case matchesBinding(msg, m.keys.Back):
		m.state = stateHome
		m.err = nil
		m.savedPath = ""
		m.filter = constants.SeverityNone
		return m, nil
	}
	if m.kind != kindReport {
		return m, nil
	}
	switch msg.String() {
	case "1", "2", "3", "4", "5":
		m.filter = severityOrder[int(msg.String()[0]-'1')]
	case "a":
		m.filter = constants.SeverityNone
	case "s":
		return m.saveCurrentReport(), nil
	}
	return m, nil
}

func (m Model) saveCurrentReport() Model {
	output := m.output
	if output == "" {
		output = "text"
	}
	path := m.config.SavePath
	if path == "" {
		path = "raxuis-report." + extensionFor(output)
	}
	saved, err := saveReport(path, m.report, output, m.config.Force)
	if err != nil {
		m.err = err
		m.state = stateError
		return m
	}
	m.savedPath = saved
	return m
}

func (m Model) updateBrowse(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch {
	case matchesBinding(msg, m.keys.Quit):
		m.quitting = true
		return m, tea.Quit
	case matchesBinding(msg, m.keys.Back):
		m.state = stateHome
		return m, nil
	case matchesBinding(msg, m.keys.Up):
		if m.browseCursor > 0 {
			m.browseCursor--
		}
	case matchesBinding(msg, m.keys.Down):
		if m.browseCursor < len(m.browse)-1 {
			m.browseCursor++
		}
	}
	return m, nil
}

func (m Model) updateInfo(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch {
	case matchesBinding(msg, m.keys.Quit):
		m.quitting = true
		return m, tea.Quit
	case matchesBinding(msg, m.keys.Back):
		m.state = stateHome
		m.err = nil
		return m, nil
	}
	return m, nil
}

// The context is stored on the model so a running action can be canceled.
func (m Model) runCmd(ctx context.Context) tea.Cmd {
	svc := m.svc
	switch m.selected {
	case actionDemo:
		return func() tea.Msg {
			value, err := svc.demo(ctx)
			if err != nil {
				return auditFailedMsg{err: err}
			}
			value.Tool = toolInfo()
			return auditDoneMsg{report: value, output: "text"}
		}
	case actionCompare:
		before, after := m.compareForm.before(), m.compareForm.after()
		return func() tea.Msg {
			comparison, err := svc.compare(before, after)
			if err != nil {
				return auditFailedMsg{err: err}
			}
			return compareDoneMsg{comparison: comparison}
		}
	default:
		target := m.form.target()
		output := m.form.output()
		options := webaudit.Options{Cookie: m.form.cookie()}
		return func() tea.Msg {
			value, err := svc.audit(ctx, target, options)
			if err != nil {
				return auditFailedMsg{err: err}
			}
			value.Tool = toolInfo()
			return auditDoneMsg{report: value, output: output}
		}
	}
}

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
		if m.selected == actionCompare {
			return m.compareForm.view(m.styles) + "\n\n" + m.styles.Muted.Render(uiText.FormHint)
		}
		return m.form.view(m.styles) + "\n\n" + m.styles.Muted.Render(uiText.FormHint)
	case stateReview:
		return renderReview(m.styles, m.reviewData()) + "\n\n" + m.styles.Muted.Render(uiText.ReviewHint)
	case stateRunning:
		if m.canceled {
			return m.styles.Muted.Render(uiText.Cancelled)
		}
		return m.styles.Muted.Render(uiText.Running)
	case stateResults:
		if m.kind == kindComparison {
			return renderComparison(m.styles, m.comparison, m.narrow())
		}
		return renderReport(m.styles, m.report, m.filter, m.savedPath, m.narrow())
	case stateBrowse:
		return renderBrowse(m.styles, m.browse, m.browseCursor, m.narrow())
	case stateError:
		message := uiText.ErrorUnknown
		if m.err != nil {
			message = m.err.Error()
		}
		return m.styles.Title.Render(uiText.ErrorHeading) + "\n" +
			m.styles.App.Render(message) + "\n\n" +
			m.styles.Muted.Render(uiText.InfoHint)
	case stateAbout:
		return m.aboutBody()
	}
	return ""
}

func (m Model) reviewData() reviewData {
	switch m.selected {
	case actionDemo:
		return reviewData{
			Scope:    uiText.DemoScope,
			Duration: uiText.DemoDuration,
			Output:   uiText.OutputStdoutText,
			Safety:   uiText.SafetySafe,
			Command:  "raxuiscli demo web",
		}
	case actionCompare:
		return reviewData{
			Scope:    m.compareForm.before() + uiText.CompareScopeSep + m.compareForm.after(),
			Duration: uiText.CompareDuration,
			Output:   uiText.OutputStdoutText,
			Safety:   uiText.SafetySafe,
			Command:  m.compareForm.equivalentCommand(),
		}
	default:
		return reviewData{
			Scope:    m.form.target(),
			Duration: uiText.AuditDuration,
			Output:   fmt.Sprintf(uiText.OutputStdoutFmt, m.form.output()),
			Safety:   uiText.SafetyPassive,
			Command:  m.form.equivalentCommand(),
		}
	}
}

func (m Model) homeBody() string {
	var b strings.Builder
	if m.state == stateSearch {
		b.WriteString(m.search.View())
		b.WriteString("\n\n")
	}

	visible := m.visibleItems()
	if len(visible) == 0 {
		b.WriteString(m.styles.Muted.Render(uiText.SearchEmpty))
		return b.String()
	}

	for i, item := range visible {
		style := m.styles.Item
		marker := "  "
		if i == m.cursor {
			style = m.styles.SelectedItem
			marker = "▸ "
		}
		line := marker + item.title
		if !m.narrow() {
			line = fmt.Sprintf("%s — %s", line, item.summary)
		}
		b.WriteString(style.Render(line))
		b.WriteString(" ")
		b.WriteString(maturityBadge(m.styles, item.maturity))
		b.WriteString(" ")
		b.WriteString(safetyBadge(m.styles, item.safety))
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
	b.WriteString(m.styles.Muted.Render(uiText.InfoHint))
	return b.String()
}

func extensionFor(output string) string {
	switch output {
	case "json":
		return "json"
	case "html":
		return "html"
	default:
		return "txt"
	}
}

// Minimal deterministic provenance so a saved report stays a valid schema-v1 document.
func toolInfo() report.ToolInfo {
	return report.ToolInfo{
		Name:      "raxuiscli",
		Version:   "dev",
		Commit:    "unknown",
		GoVersion: runtime.Version(),
		Platform:  runtime.GOOS + "/" + runtime.GOARCH,
	}
}
