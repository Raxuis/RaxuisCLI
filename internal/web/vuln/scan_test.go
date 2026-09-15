package vuln_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Raxuis/RaxuisCLI/internal/web/vuln"
)

func drainVulnResults(resultChan <-chan vuln.VulnResult) []vuln.VulnResult {
	var results []vuln.VulnResult
	for r := range resultChan {
		results = append(results, r)
	}
	return results
}

func runAndDrain(t *testing.T, run func(chan<- vuln.VulnResult)) []vuln.VulnResult {
	t.Helper()
	resultChan := make(chan vuln.VulnResult, 1000)
	done := make(chan struct{})
	go func() {
		run(resultChan)
		close(resultChan)
		close(done)
	}()
	results := drainVulnResults(resultChan)
	<-done
	return results
}

func TestXSSReflected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "search results for: %s", r.URL.Query().Get("q"))
	}))
	defer srv.Close()

	opts := vuln.ScanOptions{URL: srv.URL + "?q=1", Threads: 8, Timeout: 5, PayloadLevel: 1}
	results := runAndDrain(t, func(ch chan<- vuln.VulnResult) { vuln.TestXSS(opts, ch) })

	found := false
	for _, r := range results {
		if r.Type == vuln.VulnXSS {
			found = true
		}
	}
	if !found {
		t.Errorf("expected an XSS finding for a server reflecting the query param verbatim, got %+v", results)
	}
}

func TestXSSNotVulnerable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("nothing reflected here"))
	}))
	defer srv.Close()

	opts := vuln.ScanOptions{URL: srv.URL + "?q=1", Threads: 8, Timeout: 5, PayloadLevel: 1}
	results := runAndDrain(t, func(ch chan<- vuln.VulnResult) { vuln.TestXSS(opts, ch) })
	if len(results) != 0 {
		t.Errorf("expected no XSS findings for a non-reflecting server, got %+v", results)
	}
}

func TestXSSInvalidURL(t *testing.T) {
	opts := vuln.ScanOptions{URL: "://bad", Threads: 4, Timeout: 5}
	results := runAndDrain(t, func(ch chan<- vuln.VulnResult) { vuln.TestXSS(opts, ch) })
	if len(results) != 0 {
		t.Errorf("TestXSS with an invalid URL should produce no results, got %+v", results)
	}
}

func TestSQLiErrorBased(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		if id == "1" {
			w.Write([]byte("normal page"))
			return
		}
		w.Write([]byte("You have an error in your SQL syntax near '" + id + "'"))
	}))
	defer srv.Close()

	opts := vuln.ScanOptions{URL: srv.URL + "?id=1", Threads: 8, Timeout: 5, PayloadLevel: 1}
	results := runAndDrain(t, func(ch chan<- vuln.VulnResult) { vuln.TestSQLi(opts, ch) })

	found := false
	for _, r := range results {
		if r.Type == vuln.VulnSQLi && r.Severity == vuln.SeverityCritical {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a critical SQLi finding from the SQL error message, got %+v", results)
	}
}

func TestSQLiBooleanBased(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		if id == "1" {
			w.Write([]byte("one row"))
			return
		}
		if len(id) > 5 && id[:5] == "1 OR " || (len(id) >= 4 && (id[:4] == "' OR" || id[:4] == "\" OR")) {
			// Simulate a boolean-based response with a large body size difference.
			w.Write([]byte(makeLongBody()))
			return
		}
		w.Write([]byte("one row"))
	}))
	defer srv.Close()

	opts := vuln.ScanOptions{URL: srv.URL + "?id=1", Threads: 8, Timeout: 5, PayloadLevel: 2}
	results := runAndDrain(t, func(ch chan<- vuln.VulnResult) { vuln.TestSQLi(opts, ch) })

	found := false
	for _, r := range results {
		if r.Type == vuln.VulnSQLi {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a boolean-based SQLi finding from the content-length difference, got %+v", results)
	}
}

func makeLongBody() string {
	b := make([]byte, 500)
	for i := range b {
		b[i] = 'x'
	}
	return string(b)
}

func TestLFISuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		file := r.URL.Query().Get("file")
		if file == "about" {
			w.Write([]byte("about page"))
			return
		}
		w.Write([]byte("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"))
	}))
	defer srv.Close()

	opts := vuln.ScanOptions{URL: srv.URL + "?file=about", Threads: 8, Timeout: 5, PayloadLevel: 1}
	results := runAndDrain(t, func(ch chan<- vuln.VulnResult) { vuln.TestLFI(opts, ch) })

	found := false
	for _, r := range results {
		if r.Type == vuln.VulnLFI {
			found = true
		}
	}
	if !found {
		t.Errorf("expected an LFI finding when /etc/passwd content is echoed back, got %+v", results)
	}
}

func TestCommandInjectionOutputDetected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("uid=0(root) gid=0(root) groups=0(root)"))
	}))
	defer srv.Close()

	opts := vuln.ScanOptions{URL: srv.URL + "?cmd=1", Threads: 8, Timeout: 5, PayloadLevel: 1}
	results := runAndDrain(t, func(ch chan<- vuln.VulnResult) { vuln.TestCommandInjection(opts, ch) })

	found := false
	for _, r := range results {
		if r.Type == vuln.VulnCmdInj {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a command injection finding when id-command output is echoed, got %+v", results)
	}
}

func TestOpenRedirectDetected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next := r.URL.Query().Get("next")
		if next != "" {
			http.Redirect(w, r, next, http.StatusFound)
			return
		}
		w.Write([]byte("home"))
	}))
	defer srv.Close()

	opts := vuln.ScanOptions{URL: srv.URL + "?next=home", Threads: 4, Timeout: 5}
	resultChan := make(chan vuln.VulnResult, 100)
	vuln.TestOpenRedirect(opts, resultChan)
	close(resultChan)
	results := drainVulnResults(resultChan)

	found := false
	for _, r := range results {
		if r.Type == vuln.VulnOpen && r.Severity == vuln.SeverityHigh {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a high-severity open redirect finding for the known redirect param %q, got %+v", "next", results)
	}
}

func TestOpenRedirectInvalidURL(t *testing.T) {
	opts := vuln.ScanOptions{URL: "://bad"}
	resultChan := make(chan vuln.VulnResult, 10)
	vuln.TestOpenRedirect(opts, resultChan)
	close(resultChan)
	if len(drainVulnResults(resultChan)) != 0 {
		t.Error("TestOpenRedirect with an invalid URL should produce no results")
	}
}

func TestNoSQLiURLParam(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for k := range r.URL.Query() {
			if k != "id" {
				w.Write([]byte("MongoError: unknown operator"))
				return
			}
		}
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	opts := vuln.NoSQLiOptions{ScanOptions: vuln.ScanOptions{URL: srv.URL + "?id=1", Timeout: 5, PayloadLevel: 1}}
	results := runAndDrain(t, func(ch chan<- vuln.VulnResult) { vuln.TestNoSQLi(opts, ch) })

	found := false
	for _, r := range results {
		if r.Type == vuln.VulnNoSQLi {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a NoSQLi finding from the MongoError response, got %+v", results)
	}
}

func TestNoSQLiJSONBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"welcome back admin"}`))
	}))
	defer srv.Close()

	opts := vuln.NoSQLiOptions{
		ScanOptions: vuln.ScanOptions{URL: srv.URL, Timeout: 5, PayloadLevel: 1},
		Data:        `{"user":"admin","pass":"x"}`,
		IsJSON:      true,
	}
	results := runAndDrain(t, func(ch chan<- vuln.VulnResult) { vuln.TestNoSQLi(opts, ch) })

	found := false
	for _, r := range results {
		if r.Type == vuln.VulnNoSQLi && r.Parameter == "JSON body" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a NoSQLi JSON-body finding (auth bypass indicator), got %+v", results)
	}
}
