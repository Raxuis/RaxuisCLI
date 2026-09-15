package tui

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
)

// Mirror the root command's accepted values so the interface can only produce
// commands the CLI would also accept.
var (
	outputFormats = []string{"text", "json", "html"}
	thresholds    = []string{"none", "info", "low", "medium", "high", "critical"}
)

type auditForm struct {
	inputs      []textinput.Model // 0: url, 1: cookie
	outputIndex int
	failOnIndex int
	focus       int // 0: url, 1: cookie, 2: output, 3: fail-on
	errText     string
}

const auditFieldCount = 4

func newAuditForm() auditForm {
	target := textinput.New()
	target.Placeholder = uiText.PlaceholderURL
	cookie := textinput.New()
	cookie.Placeholder = uiText.PlaceholderCookie
	form := auditForm{inputs: []textinput.Model{target, cookie}}
	form.inputs[0].Focus()
	return form
}

func (f auditForm) target() string { return strings.TrimSpace(f.inputs[0].Value()) }
func (f auditForm) cookie() string { return strings.TrimSpace(f.inputs[1].Value()) }
func (f auditForm) output() string { return outputFormats[f.outputIndex] }
func (f auditForm) failOn() string { return thresholds[f.failOnIndex] }

func (f auditForm) validate() error {
	raw := f.target()
	if raw == "" {
		return errors.New(uiText.ErrEnterURL)
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%s: %w", uiText.ErrInvalidURL, err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return errors.New(uiText.ErrURLScheme)
	}
	if parsed.Host == "" {
		return errors.New(uiText.ErrURLHost)
	}
	return nil
}

// Secret values are masked so the preview is safe to display and screenshot.
func (f auditForm) equivalentCommand() string {
	parts := []string{"raxuiscli", "audit", "web", quoteArg(f.target())}
	parts = append(parts, "--output", f.output())
	if f.failOn() != "none" {
		parts = append(parts, "--fail-on", f.failOn())
	}
	if f.cookie() != "" {
		parts = append(parts, "--cookie", "'***'")
	}
	return strings.Join(parts, " ")
}

// Back and Confirm are handled by the caller.
func (f auditForm) update(msg tea.KeyPressMsg, keys keyMap) (auditForm, tea.Cmd) {
	switch {
	case msg.String() == "tab", matchesBinding(msg, keys.Down):
		return f.moveFocus(1), nil
	case msg.String() == "shift+tab", matchesBinding(msg, keys.Up):
		return f.moveFocus(-1), nil
	}

	switch f.focus {
	case 2:
		if d := selectorDelta(msg); d != 0 {
			f.outputIndex = cycleIndex(f.outputIndex, len(outputFormats), d)
		}
		return f, nil
	case 3:
		if d := selectorDelta(msg); d != 0 {
			f.failOnIndex = cycleIndex(f.failOnIndex, len(thresholds), d)
		}
		return f, nil
	default:
		var cmd tea.Cmd
		f.inputs[f.focus], cmd = f.inputs[f.focus].Update(msg)
		return f, cmd
	}
}

func (f auditForm) moveFocus(delta int) auditForm {
	f.focus = cycleIndex(f.focus, auditFieldCount, delta)
	for i := range f.inputs {
		if i == f.focus {
			f.inputs[i].Focus()
		} else {
			f.inputs[i].Blur()
		}
	}
	return f
}

func (f auditForm) view(styles Styles) string {
	var b strings.Builder
	labels := []string{uiText.FieldTargetURL, uiText.FieldCookie}
	for i, input := range f.inputs {
		b.WriteString(fieldLine(styles, labels[i], input.View(), f.focus == i))
		b.WriteString("\n")
	}
	b.WriteString(fieldLine(styles, uiText.FieldOutput, f.output(), f.focus == 2))
	b.WriteString("\n")
	b.WriteString(fieldLine(styles, uiText.FieldFailOn, f.failOn(), f.focus == 3))
	if f.errText != "" {
		b.WriteString("\n")
		b.WriteString(styles.Accent.Render("! " + f.errText))
	}
	return b.String()
}

type compareForm struct {
	inputs  []textinput.Model // 0: before, 1: after
	focus   int
	errText string
}

func newCompareForm() compareForm {
	before := textinput.New()
	before.Placeholder = uiText.PlaceholderBefore
	after := textinput.New()
	after.Placeholder = uiText.PlaceholderAfter
	form := compareForm{inputs: []textinput.Model{before, after}}
	form.inputs[0].Focus()
	return form
}

func (f compareForm) before() string { return strings.TrimSpace(f.inputs[0].Value()) }
func (f compareForm) after() string  { return strings.TrimSpace(f.inputs[1].Value()) }

func (f compareForm) validate() error {
	if f.before() == "" || f.after() == "" {
		return errors.New(uiText.ErrBothPaths)
	}
	return nil
}

func (f compareForm) equivalentCommand() string {
	return strings.Join([]string{"raxuiscli", "compare", quoteArg(f.before()), quoteArg(f.after())}, " ")
}

func (f compareForm) update(msg tea.KeyPressMsg, keys keyMap) (compareForm, tea.Cmd) {
	switch {
	case msg.String() == "tab", matchesBinding(msg, keys.Down):
		f.focus = cycleIndex(f.focus, len(f.inputs), 1)
		f = f.refocus()
		return f, nil
	case msg.String() == "shift+tab", matchesBinding(msg, keys.Up):
		f.focus = cycleIndex(f.focus, len(f.inputs), -1)
		f = f.refocus()
		return f, nil
	}
	var cmd tea.Cmd
	f.inputs[f.focus], cmd = f.inputs[f.focus].Update(msg)
	return f, cmd
}

func (f compareForm) refocus() compareForm {
	for i := range f.inputs {
		if i == f.focus {
			f.inputs[i].Focus()
		} else {
			f.inputs[i].Blur()
		}
	}
	return f
}

func (f compareForm) view(styles Styles) string {
	var b strings.Builder
	labels := []string{uiText.FieldBefore, uiText.FieldAfter}
	for i, input := range f.inputs {
		b.WriteString(fieldLine(styles, labels[i], input.View(), f.focus == i))
		b.WriteString("\n")
	}
	if f.errText != "" {
		b.WriteString(styles.Accent.Render("! " + f.errText))
	}
	return b.String()
}

func fieldLine(styles Styles, label, value string, focused bool) string {
	marker := "  "
	style := styles.Item
	if focused {
		marker = "▸ "
		style = styles.SelectedItem
	}
	return style.Render(fmt.Sprintf("%s%-18s %s", marker, label+":", value))
}

func selectorDelta(msg tea.KeyPressMsg) int {
	switch msg.String() {
	case "left", "h":
		return -1
	case "right", "l", "space", " ":
		return 1
	default:
		return 0
	}
}

func cycleIndex(current, length, delta int) int {
	if length == 0 {
		return 0
	}
	return ((current+delta)%length + length) % length
}

func quoteArg(value string) string {
	if value == "" {
		return "''"
	}
	if strings.ContainsAny(value, " \t'\"") {
		return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
	}
	return value
}
