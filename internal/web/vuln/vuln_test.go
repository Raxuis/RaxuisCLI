package vuln

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
)

func captureVulnStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}
	os.Stdout = w
	stdoutW = w
	fn()
	w.Close()
	os.Stdout = orig
	stdoutW = orig

	var buf bytes.Buffer
	io.Copy(&buf, r)
	return buf.String()
}

func TestTruncate(t *testing.T) {
	tests := []struct {
		in     string
		maxLen int
		want   string
	}{
		{"short", 10, "short"},
		{"this is a longer string", 10, "this is..."},
	}
	for _, tt := range tests {
		if got := truncate(tt.in, tt.maxLen); got != tt.want {
			t.Errorf("truncate(%q, %d) = %q, want %q", tt.in, tt.maxLen, got, tt.want)
		}
	}
}

func TestGetPayloads(t *testing.T) {
	tests := []VulnType{VulnXSS, VulnSQLi, VulnLFI, VulnCmdInj, VulnOpen, VulnNoSQLi, VulnXXE}
	for _, vt := range tests {
		if got := GetPayloads(vt, 2); len(got) == 0 {
			t.Errorf("GetPayloads(%s, 2) returned no payloads", vt)
		}
	}
	if got := GetPayloads(VulnCORS, 1); got != nil {
		t.Errorf("GetPayloads(unsupported type) = %v, want nil", got)
	}
}

func TestDisplayResultsEmpty(t *testing.T) {
	out := captureVulnStdout(t, func() { DisplayResults(nil) })
	if !strings.Contains(out, "NO VULNERABILITIES FOUND") {
		t.Errorf("DisplayResults(nil) output = %q, want it to report no vulnerabilities", out)
	}
}

func TestDisplayResultsGrouping(t *testing.T) {
	results := []VulnResult{
		{Type: VulnXSS, Severity: SeverityHigh, URL: "http://example.com?q=1", Parameter: "q", Payload: "<script>", Evidence: "reflected", Description: "d", Remediation: "r"},
		{Type: VulnSQLi, Severity: SeverityCritical, URL: "http://example.com?id=1", Evidence: "error", Description: "d", Remediation: "r"},
	}
	out := captureVulnStdout(t, func() { DisplayResults(results) })
	for _, want := range []string{"VULNERABILITY SCAN RESULTS", "Critical: 1", "High:     1", "XSS", "SQLi"} {
		if !strings.Contains(out, want) {
			t.Errorf("DisplayResults output missing %q; got:\n%s", want, out)
		}
	}
}

func TestQuickScanUsesRegistry(t *testing.T) {
	// Confirms the quickScanTests registry actually drives QuickScan: a
	// server that reflects payloads back should produce at least one XSS
	// finding (from the TestXSS entry) among the header-scan results too.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Echo back the decoded query value (not RawQuery, which is still
		// percent-encoded and would never contain the literal payload).
		w.Write([]byte("echo: " + r.URL.Query().Get("q")))
	}))
	defer srv.Close()

	opts := ScanOptions{URL: srv.URL + "?q=1", Threads: 4, Timeout: 5, PayloadLevel: 1}
	resultChan := make(chan VulnResult, 500)
	doneChan := make(chan bool)

	go QuickScan(opts, resultChan, doneChan)

	var results []VulnResult
loop:
	for {
		select {
		case r := <-resultChan:
			results = append(results, r)
		case <-doneChan:
			for {
				select {
				case r := <-resultChan:
					results = append(results, r)
				default:
					break loop
				}
			}
		}
	}

	seenTypes := map[VulnType]bool{}
	for _, r := range results {
		seenTypes[r.Type] = true
	}
	// At minimum the header scan (always run) and XSS (reflects the query
	// param verbatim) should have produced findings.
	if !seenTypes[VulnHeaders] {
		t.Error("QuickScan should report missing security headers for a bare httptest server")
	}
	if !seenTypes[VulnXSS] {
		t.Errorf("QuickScan should have found the reflected XSS via the registry; saw types: %v", seenTypes)
	}
}

func TestCreateClientDoRequestBuildTestURLDelegate(t *testing.T) {
	// These are thin delegations to internal/shared/httpclient; a light
	// smoke test is enough to confirm the wiring, not re-test httpclient
	// itself.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	client := createClient(ScanOptions{Timeout: 5})
	resp, body, err := doRequest(client, srv.URL, ScanOptions{})
	if err != nil {
		t.Fatalf("doRequest returned error: %v", err)
	}
	resp.Body.Close()
	if body != "ok" {
		t.Errorf("doRequest body = %q, want %q", body, "ok")
	}

	parsed, _ := url.Parse("http://example.com?a=1")
	origQuery := parsed.RawQuery
	built := buildTestURL(parsed, "b", "2")
	if parsed.RawQuery != origQuery {
		t.Error("buildTestURL must not mutate the original *url.URL (this caused a real data race previously)")
	}
	if !strings.Contains(built, "b=2") {
		t.Errorf("buildTestURL result %q missing injected param", built)
	}
}
