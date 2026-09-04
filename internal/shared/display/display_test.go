package display

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"

	"raxuiscli/internal/shared/constants"
	"raxuiscli/internal/shared/models"
)

// captureStdout runs fn with os.Stdout redirected and returns everything it printed.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}
	os.Stdout = w

	fn()

	w.Close()
	os.Stdout = orig

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatalf("failed to read captured output: %v", err)
	}
	return buf.String()
}

func TestPrintTable(t *testing.T) {
	out := captureStdout(t, func() {
		PrintTable([]string{"Name", "Age"}, [][]string{
			{"Alice", "30"},
			{"Bob", "25"},
		})
	})

	for _, want := range []string{"Name", "Age", "Alice", "30", "Bob", "25"} {
		if !strings.Contains(out, want) {
			t.Errorf("PrintTable output missing %q; got:\n%s", want, out)
		}
	}
}

func TestPrintTableEmptyHeaders(t *testing.T) {
	out := captureStdout(t, func() {
		PrintTable(nil, [][]string{{"a"}})
	})
	if out != "" {
		t.Errorf("PrintTable with no headers should print nothing, got %q", out)
	}
}

func TestPrintKeyValue(t *testing.T) {
	out := captureStdout(t, func() {
		PrintKeyValue("Status", "OK")
	})
	if !strings.Contains(out, "Status") || !strings.Contains(out, "OK") {
		t.Errorf("PrintKeyValue output missing key/value; got %q", out)
	}
}

func TestPrintKeyValueIndent(t *testing.T) {
	out := captureStdout(t, func() {
		PrintKeyValueIndent("Status", "OK", 4)
	})
	if !strings.HasPrefix(out, "    ") {
		t.Errorf("PrintKeyValueIndent should start with 4 spaces of indent, got %q", out)
	}
}

func TestPrintSection(t *testing.T) {
	out := captureStdout(t, func() {
		PrintSection("Results")
	})
	if !strings.Contains(out, "[Results]") {
		t.Errorf("PrintSection output missing title; got %q", out)
	}
}

func TestPrintHeader(t *testing.T) {
	out := captureStdout(t, func() {
		PrintHeader("SCAN")
	})
	if !strings.Contains(out, "SCAN") || !strings.Contains(out, "====") {
		t.Errorf("PrintHeader output missing title/border; got %q", out)
	}
}

func TestPrintSubHeader(t *testing.T) {
	out := captureStdout(t, func() {
		PrintSubHeader("Details")
	})
	if !strings.Contains(out, "Details") {
		t.Errorf("PrintSubHeader output missing title; got %q", out)
	}
}

func TestPrintBulletAndNumbered(t *testing.T) {
	out := captureStdout(t, func() {
		PrintBullet("item one")
		PrintNumbered(2, "item two")
	})
	if !strings.Contains(out, "•") || !strings.Contains(out, "item one") {
		t.Errorf("PrintBullet output wrong; got %q", out)
	}
	if !strings.Contains(out, "2.") || !strings.Contains(out, "item two") {
		t.Errorf("PrintNumbered output wrong; got %q", out)
	}
}

func TestPrintBox(t *testing.T) {
	out := captureStdout(t, func() {
		PrintBox([]string{"short line"}, 20)
	})
	if !strings.Contains(out, "short line") || !strings.Contains(out, "+") {
		t.Errorf("PrintBox output wrong; got %q", out)
	}
}

func TestPrintBoxDefaultWidth(t *testing.T) {
	out := captureStdout(t, func() {
		PrintBox([]string{"x"}, 0)
	})
	if !strings.Contains(out, "x") {
		t.Errorf("PrintBox with width<=0 should still print, got %q", out)
	}
}

func TestPrintBoxTruncatesLongLines(t *testing.T) {
	longLine := strings.Repeat("a", 100)
	out := captureStdout(t, func() {
		PrintBox([]string{longLine}, 20)
	})
	if !strings.Contains(out, "...") {
		t.Errorf("PrintBox should truncate a line longer than the box width, got %q", out)
	}
}

func TestTruncate(t *testing.T) {
	tests := []struct {
		input  string
		maxLen int
		want   string
	}{
		{"short", 10, "short"},
		{"this is a long string", 10, "this is..."},
		{"", 5, ""},
	}

	for _, tt := range tests {
		if got := Truncate(tt.input, tt.maxLen); got != tt.want {
			t.Errorf("Truncate(%q, %d) = %q, want %q", tt.input, tt.maxLen, got, tt.want)
		}
	}
}

func TestDisplayVulnResultsEmpty(t *testing.T) {
	out := captureStdout(t, func() {
		DisplayVulnResults(nil)
	})
	if !strings.Contains(out, "NO VULNERABILITIES FOUND") {
		t.Errorf("DisplayVulnResults(nil) should report no vulnerabilities, got %q", out)
	}
}

func TestDisplayVulnResultsGroupsBySeverity(t *testing.T) {
	results := []models.VulnResult{
		{Type: constants.VulnXSS, Severity: constants.SeverityHigh, URL: "http://example.com?q=1", Parameter: "q", Payload: "<script>", Evidence: "reflected", Description: "d", Remediation: "r"},
		{Type: constants.VulnSQLi, Severity: constants.SeverityCritical, URL: "http://example.com?id=1", Evidence: "error", Description: "d", Remediation: "r"},
	}

	out := captureStdout(t, func() {
		DisplayVulnResults(results)
	})

	for _, want := range []string{"VULNERABILITY SCAN RESULTS", "CRITICAL", "HIGH", "XSS", "SQLi", "example.com"} {
		if !strings.Contains(out, want) {
			t.Errorf("DisplayVulnResults output missing %q; got:\n%s", want, out)
		}
	}
}

func TestDisplaySimpleResults(t *testing.T) {
	results := []models.VulnResult{
		{Type: constants.VulnLFI, Severity: constants.SeverityMedium, URL: "http://example.com?f=1"},
	}
	out := captureStdout(t, func() {
		DisplaySimpleResults(results)
	})
	if !strings.Contains(out, "LFI") || !strings.Contains(out, "example.com") {
		t.Errorf("DisplaySimpleResults output wrong; got %q", out)
	}
}

func TestDisplayPayloads(t *testing.T) {
	out := captureStdout(t, func() {
		DisplayPayloads("XSS", 1, []string{"<script>alert(1)</script>", "<img onerror=alert(1)>"})
	})
	if !strings.Contains(out, "Total payloads: 2") || !strings.Contains(out, "<script>") {
		t.Errorf("DisplayPayloads output wrong; got %q", out)
	}
}

func TestDisplayProgress(t *testing.T) {
	out := captureStdout(t, func() {
		DisplayProgress(5, 10, "Scanning")
	})
	if !strings.Contains(out, "Scanning") || !strings.Contains(out, "50.0%") {
		t.Errorf("DisplayProgress output wrong; got %q", out)
	}
}

func TestDisplayProgressComplete(t *testing.T) {
	out := captureStdout(t, func() {
		DisplayProgress(10, 10, "Done")
	})
	if !strings.Contains(out, "100.0%") {
		t.Errorf("DisplayProgress at completion should show 100%%; got %q", out)
	}
	if !strings.HasSuffix(out, "\n") {
		t.Error("DisplayProgress should print a trailing newline once current == total")
	}
}

func TestClearLine(t *testing.T) {
	out := captureStdout(t, func() {
		ClearLine()
	})
	if !strings.HasPrefix(out, "\r") {
		t.Errorf("ClearLine output should start with a carriage return, got %q", out)
	}
}
