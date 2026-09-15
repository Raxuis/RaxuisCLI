package tui

// Centralized user-facing strings (Fmt suffix = fmt.Sprintf format). CLI tokens stay inline.
var uiText = struct {
	AppTitle   string
	Loading    string
	CreditText string
	CreditURL  string

	HomeHint     string
	SearchPrompt string
	SearchEmpty  string

	ActionAuditTitle     string
	ActionAuditSummary   string
	ActionDemoTitle      string
	ActionDemoSummary    string
	ActionCompareTitle   string
	ActionCompareSummary string
	ActionBrowseTitle    string
	ActionBrowseSummary  string
	ActionAboutTitle     string
	ActionAboutSummary   string

	MaturityStable        string
	MaturityExperimental  string
	MaturityInformational string

	FormHint          string
	FieldTargetURL    string
	FieldCookie       string
	FieldOutput       string
	FieldFailOn       string
	FieldBefore       string
	FieldAfter        string
	PlaceholderURL    string
	PlaceholderCookie string
	PlaceholderBefore string
	PlaceholderAfter  string

	ErrEnterURL   string
	ErrInvalidURL string
	ErrURLScheme  string
	ErrURLHost    string
	ErrBothPaths  string

	ReviewHint           string
	ReviewHeading        string
	ReviewScope          string
	ReviewDuration       string
	ReviewOutput         string
	ReviewSafety         string
	ReviewCommandHeading string
	DemoScope            string
	DemoDuration         string
	AuditDuration        string
	CompareDuration      string
	CompareScopeSep      string
	OutputStdoutText     string
	OutputStdoutFmt      string
	SafetySafe           string
	SafetyPassive        string

	Running   string
	Canceled string

	ResultsTitleFmt   string
	ResultsSummary    string
	ResultsFilterFmt  string
	ResultsNoFindings string
	ResultsSavedFmt   string
	ResultsHint       string

	ComparisonHeading string
	CmpAdded          string
	CmpResolved       string
	CmpChanged        string
	CmpUnchanged      string
	CmpRegressions    string
	CmpNoRegressions  string
	CmpNewBadge       string

	BrowseTitleFmt string
	BrowseHint     string

	ErrorHeading string
	ErrorUnknown string
	AboutHeading string
	AboutBody    string
	InfoHint     string
}{
	AppTitle:   "RaxuisCLI — Guided Interface",
	Loading:    "Loading…",
	CreditText: "Created by Raxuis · github.com/raxuis",
	CreditURL:  "https://github.com/raxuis",

	HomeHint:     "↑/↓ move · enter select · ctrl+k search · q quit",
	SearchPrompt: "Search actions",
	SearchEmpty:  "No matching actions.",

	ActionAuditTitle:     "Passive Web Audit",
	ActionAuditSummary:   "Inspect HTTP headers and TLS for one target.",
	ActionDemoTitle:      "Local Demo",
	ActionDemoSummary:    "Audit a safe in-process fixture on loopback.",
	ActionCompareTitle:   "Compare Reports",
	ActionCompareSummary: "Diff two saved audit snapshots.",
	ActionBrowseTitle:    "Browse Commands",
	ActionBrowseSummary:  "List every command with its maturity and safety.",
	ActionAboutTitle:     "Help / About",
	ActionAboutSummary:   "Learn what this interface can do.",

	MaturityStable:        "stable",
	MaturityExperimental:  "exp",
	MaturityInformational: "info",

	FormHint:          "tab move · ←/→ change · enter continue · esc back",
	FieldTargetURL:    "Target URL",
	FieldCookie:       "Cookie (optional)",
	FieldOutput:       "Output",
	FieldFailOn:       "Fail on",
	FieldBefore:       "Before report",
	FieldAfter:        "After report",
	PlaceholderURL:    "https://example.com",
	PlaceholderCookie: "session=…",
	PlaceholderBefore: "before.json",
	PlaceholderAfter:  "after.json",

	ErrEnterURL:   "enter a target URL",
	ErrInvalidURL: "invalid URL",
	ErrURLScheme:  "URL must start with http:// or https://",
	ErrURLHost:    "URL must include a host",
	ErrBothPaths:  "enter both report paths",

	ReviewHint:           "enter run · esc back",
	ReviewHeading:        "Review",
	ReviewScope:          "Scope",
	ReviewDuration:       "Expected duration",
	ReviewOutput:         "Output",
	ReviewSafety:         "Safety level",
	ReviewCommandHeading: "Equivalent command",
	DemoScope:            "https://127.0.0.1/demo (loopback fixture)",
	DemoDuration:         "up to 5s",
	AuditDuration:        "up to 10s",
	CompareDuration:      "instant",
	CompareScopeSep:      " → ",
	OutputStdoutText:     "stdout (text)",
	OutputStdoutFmt:      "stdout (%s)",
	SafetySafe:           "safe",
	SafetyPassive:        "passive",

	Running:   "Running…  esc cancels",
	Canceled: "Run canceled.",

	ResultsTitleFmt:   "Results — %s",
	ResultsSummary:    "Summary  ",
	ResultsFilterFmt:  "Filter: %s (press a to clear)",
	ResultsNoFindings: "No findings to show.",
	ResultsSavedFmt:   "Saved report: %s",
	ResultsHint:       "1-5 filter · a all · s save · esc home · q quit",

	ComparisonHeading: "Comparison",
	CmpAdded:          "Added",
	CmpResolved:       "Resolved",
	CmpChanged:        "Changed",
	CmpUnchanged:      "Unchanged",
	CmpRegressions:    "Regressions detected.",
	CmpNoRegressions:  "No regressions at or above low severity.",
	CmpNewBadge:       "new",

	BrowseTitleFmt: "Commands (%d)",
	BrowseHint:     "↑/↓ move · esc home · q quit",

	ErrorHeading: "Something went wrong",
	ErrorUnknown: "unknown error",
	AboutHeading: "About",
	AboutBody:    "RaxuisCLI is a passive security auditing toolkit.",
	InfoHint:     "esc home · q quit",
}
