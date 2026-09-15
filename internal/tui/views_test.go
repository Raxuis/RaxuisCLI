package tui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"

	"raxuiscli/internal/shared/catalog"
	"raxuiscli/internal/shared/constants"
	"raxuiscli/internal/shared/models"
	"raxuiscli/internal/shared/report"
)

func TestFuzzyMatch(t *testing.T) {
	cases := []struct {
		query, target string
		want          bool
	}{
		{"pwa", "Passive Web Audit", true},
		{"demo", "Local Demo", true},
		{"cmp", "Compare Reports", true},
		{"", "anything", true},
		{"zzz", "Local Demo", false},
	}
	for _, tc := range cases {
		if got := fuzzyMatch(tc.query, tc.target); got != tc.want {
			t.Errorf("fuzzyMatch(%q, %q) = %v, want %v", tc.query, tc.target, got, tc.want)
		}
	}
}

func TestFilterItemsFuzzy(t *testing.T) {
	items := initialActions()
	got := filterItems(items, "pwa")
	if len(got) != 1 || got[0].id != actionAudit {
		t.Fatalf("filterItems(pwa) = %+v, want only audit", got)
	}
	if len(filterItems(items, "")) != len(items) {
		t.Fatal("empty query should return all items")
	}
}

func TestInitialActionsUseCatalogMetadata(t *testing.T) {
	items := initialActions()
	if len(items) != 5 {
		t.Fatalf("initial actions = %d, want 5", len(items))
	}
	for _, item := range items {
		if item.path == "" {
			continue
		}
		entry, ok := catalog.Lookup(item.path)
		if !ok {
			t.Fatalf("catalog missing %q", item.path)
		}
		if item.maturity != entry.Maturity || item.safety != entry.Safety {
			t.Fatalf("%q badges out of sync with catalog", item.path)
		}
	}
}

func TestBadges(t *testing.T) {
	plain := NewStylesForTest(false)
	if got := maturityBadge(plain, catalog.MaturityExperimental); got != "[exp]" {
		t.Errorf("maturity badge = %q, want [exp]", got)
	}
	if got := safetyBadge(plain, catalog.SafetyDangerous); got != "[dangerous]" {
		t.Errorf("safety badge = %q, want [dangerous]", got)
	}
	colored := NewStylesForTest(true)
	if !strings.Contains(maturityBadge(colored, catalog.MaturityStable), "\x1b") {
		t.Error("colored maturity badge should carry ANSI")
	}
}

// NewStylesForTest exposes the internal style constructor to tests.
func NewStylesForTest(color bool) Styles { return newStyles(color) }

func auditFormWith(url, cookie string) auditForm {
	f := newAuditForm()
	f.inputs[0].SetValue(url)
	f.inputs[1].SetValue(cookie)
	return f
}

func TestAuditFormValidate(t *testing.T) {
	cases := []struct {
		url     string
		wantErr bool
	}{
		{"https://example.com", false},
		{"http://example.com/path", false},
		{"", true},
		{"ftp://example.com", true},
		{"https://", true},
		{"not a url", true},
	}
	for _, tc := range cases {
		err := auditFormWith(tc.url, "").validate()
		if (err != nil) != tc.wantErr {
			t.Errorf("validate(%q) err = %v, wantErr = %v", tc.url, err, tc.wantErr)
		}
	}
}

func TestEquivalentCommandMasksCookie(t *testing.T) {
	f := auditFormWith("https://example.com", "session=SECRET123")
	cmd := f.equivalentCommand()
	if strings.Contains(cmd, "SECRET123") {
		t.Fatalf("equivalent command leaked the cookie: %q", cmd)
	}
	if !strings.Contains(cmd, "--cookie '***'") {
		t.Fatalf("equivalent command should mask the cookie: %q", cmd)
	}
	if !strings.Contains(cmd, "raxuiscli audit web https://example.com") {
		t.Fatalf("equivalent command missing target: %q", cmd)
	}
}

func TestCompareEquivalentCommand(t *testing.T) {
	f := newCompareForm()
	f.inputs[0].SetValue("before.json")
	f.inputs[1].SetValue("after.json")
	if got := f.equivalentCommand(); got != "raxuiscli compare before.json after.json" {
		t.Fatalf("compare command = %q", got)
	}
	if f.validate() != nil {
		t.Fatal("both paths set should validate")
	}
	if newCompareForm().validate() == nil {
		t.Fatal("empty paths should not validate")
	}
}

func sampleFindings() []models.VulnResult {
	return []models.VulnResult{
		{Title: "Critical thing", Severity: constants.SeverityCritical, Remediation: "fix now"},
		{Title: "High thing", Severity: constants.SeverityHigh, Remediation: "fix soon"},
		{Title: "Low thing", Severity: constants.SeverityLow},
	}
}

func TestVisibleFindingsFilter(t *testing.T) {
	findings := sampleFindings()
	if got := visibleFindings(findings, constants.SeverityNone); len(got) != 3 {
		t.Fatalf("none filter = %d findings, want 3", len(got))
	}
	got := visibleFindings(findings, constants.SeverityHigh)
	if len(got) != 1 || got[0].Severity != constants.SeverityHigh {
		t.Fatalf("high filter = %+v, want one high finding", got)
	}
}

func TestCountBySeverity(t *testing.T) {
	counts := countBySeverity(sampleFindings())
	byLevel := map[constants.Severity]int{}
	for _, c := range counts {
		byLevel[c.Severity] = c.Count
	}
	if byLevel[constants.SeverityCritical] != 1 || byLevel[constants.SeverityHigh] != 1 || byLevel[constants.SeverityMedium] != 0 {
		t.Fatalf("unexpected counts: %+v", byLevel)
	}
}

func sampleReport() report.Report {
	return report.Report{
		SchemaVersion: report.SchemaVersion,
		Tool:          toolInfo(),
		Audit:         report.AuditInfo{Kind: "web", Target: "https://example.com", Status: "ok"},
		Findings:      sampleFindings(),
	}
}

func TestSaveReportWritesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.json")
	saved, err := saveReport(path, sampleReport(), "json", false)
	if err != nil {
		t.Fatalf("saveReport: %v", err)
	}
	if saved != path {
		t.Fatalf("saved path = %q, want %q", saved, path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading saved report: %v", err)
	}
	if !strings.Contains(string(data), "schema_version") {
		t.Fatalf("saved JSON report missing schema envelope: %q", string(data))
	}
}

func TestResultsSaveKeyRecordsPath(t *testing.T) {
	dir := t.TempDir()
	m := newTestModel()
	m.state = stateResults
	m.kind = kindReport
	m.report = sampleReport()
	m.output = "json"
	m.config.SavePath = filepath.Join(dir, "out.json")
	m = step(t, m, runeKey('s'))
	if m.state == stateError {
		t.Fatalf("save failed: %v", m.err)
	}
	if m.savedPath == "" {
		t.Fatal("savedPath not recorded")
	}
	if _, err := os.Stat(m.savedPath); err != nil {
		t.Fatalf("saved report file missing: %v", err)
	}
}

func TestResultsSeverityFilterKeys(t *testing.T) {
	m := newTestModel()
	m.state = stateResults
	m.kind = kindReport
	m.report = sampleReport()
	m = step(t, m, runeKey('2')) // high
	if m.filter != constants.SeverityHigh {
		t.Fatalf("filter = %v, want high", m.filter)
	}
	m = step(t, m, runeKey('a')) // clear
	if m.filter != constants.SeverityNone {
		t.Fatalf("filter = %v, want none", m.filter)
	}
}

func TestRenderReviewShowsScopeAndMaskedCommand(t *testing.T) {
	styles := NewStylesForTest(false)
	data := reviewData{
		Scope:    "https://example.com",
		Duration: "up to 10s",
		Output:   "stdout (text)",
		Safety:   "passive",
		Command:  "raxuiscli audit web https://example.com --output text --cookie '***'",
	}
	out := renderReview(styles, data)
	for _, want := range []string{"https://example.com", "up to 10s", "passive", "'***'"} {
		if !strings.Contains(out, want) {
			t.Fatalf("review missing %q: %q", want, out)
		}
	}
}

func TestRenderReportNarrowDropsRemediation(t *testing.T) {
	styles := NewStylesForTest(false)
	value := sampleReport()
	wide := renderReport(styles, value, constants.SeverityNone, "", false)
	if !strings.Contains(wide, "fix now") {
		t.Fatal("wide report should include remediation")
	}
	narrow := renderReport(styles, value, constants.SeverityNone, "", true)
	if strings.Contains(narrow, "fix now") {
		t.Fatal("narrow report should drop remediation detail")
	}
}

func TestSelectorIgnoresNonNavKeys(t *testing.T) {
	f := newAuditForm()
	f.focus = 2 // output selector
	f, _ = f.update(tea.KeyPressMsg{Code: 'x', Text: "x"}, defaultKeyMap())
	if f.outputIndex != 0 {
		t.Fatalf("a letter changed the selector: outputIndex = %d", f.outputIndex)
	}
	f, _ = f.update(tea.KeyPressMsg{Code: tea.KeyRight}, defaultKeyMap())
	if f.outputIndex != 1 {
		t.Fatalf("right did not advance the selector: outputIndex = %d", f.outputIndex)
	}
}

func TestSearchConfirmWithoutMatchesStays(t *testing.T) {
	m := step(t, newTestModel(), readyMsg{})
	m = step(t, m, ctrlK())
	for _, r := range "zzzz" {
		m = step(t, m, runeKey(r))
	}
	if len(m.visibleItems()) != 0 {
		t.Fatal("expected no matches for gibberish query")
	}
	m = step(t, m, enter())
	if m.state != stateSearch {
		t.Fatalf("state = %v, want search (confirm with no match must not leave home filtered-empty)", m.state)
	}
}

func TestRenderBrowseShowsBadges(t *testing.T) {
	styles := NewStylesForTest(false)
	out := renderBrowse(styles, browseItems(), 0, false)
	if !strings.Contains(out, "raxuiscli audit web") {
		t.Fatal("browse should list catalog commands")
	}
	if !strings.Contains(out, "[stable]") {
		t.Fatal("browse should render maturity badges")
	}
}
