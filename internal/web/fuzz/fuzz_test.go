package fuzz

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func captureFuzzStdout(t *testing.T, fn func()) string {
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
	io.Copy(&buf, r)
	return buf.String()
}

func TestLoadWordlist(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "words.txt")
	content := "admin\n# comment\n\nlogin\n  \nbackup\n"
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write wordlist: %v", err)
	}

	words, err := LoadWordlist(path)
	if err != nil {
		t.Fatalf("LoadWordlist returned error: %v", err)
	}
	want := []string{"admin", "login", "backup"}
	if len(words) != len(want) {
		t.Fatalf("LoadWordlist = %v, want %v", words, want)
	}
	for i := range want {
		if words[i] != want[i] {
			t.Errorf("words[%d] = %q, want %q", i, words[i], want[i])
		}
	}
}

func TestLoadWordlistMissingFile(t *testing.T) {
	if _, err := LoadWordlist("/nonexistent/wordlist.txt"); err == nil {
		t.Error("LoadWordlist on a missing file should return an error")
	}
}

func TestCommonDirectoriesAndParams(t *testing.T) {
	if len(CommonDirectories()) == 0 {
		t.Error("CommonDirectories() should not be empty")
	}
	if len(CommonParams()) == 0 {
		t.Error("CommonParams() should not be empty")
	}
}

func drainFuzzResults(resultChan <-chan FuzzResult, doneChan <-chan bool) []FuzzResult {
	var results []FuzzResult
	for {
		select {
		case r := <-resultChan:
			results = append(results, r)
		case <-doneChan:
			// Drain anything left in the buffer.
			for {
				select {
				case r := <-resultChan:
					results = append(results, r)
				default:
					return results
				}
			}
		}
	}
}

func TestFuzzDirectoryFindsExisting(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("admin panel"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	opts := FuzzOptions{URL: srv.URL, Words: []string{"admin", "login", "missing"}, Threads: 4, Timeout: 5}
	resultChan := make(chan FuzzResult, 100)
	doneChan := make(chan bool)

	go FuzzDirectory(opts, resultChan, doneChan)
	results := drainFuzzResults(resultChan, doneChan)

	found := false
	for _, r := range results {
		if r.Input == "admin" && r.StatusCode == 200 {
			found = true
		}
		if r.StatusCode == 404 {
			t.Errorf("404 result for %q should have been filtered out by default", r.Input)
		}
	}
	if !found {
		t.Errorf("expected to find /admin (200), results: %+v", results)
	}
}

func TestFuzzDirectoryWithExtensions(t *testing.T) {
	var mu sync.Mutex
	var gotPaths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotPaths = append(gotPaths, r.URL.Path)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	opts := FuzzOptions{URL: srv.URL, Words: []string{"index"}, Extensions: []string{"php", "html"}, Threads: 4, Timeout: 5}
	resultChan := make(chan FuzzResult, 100)
	doneChan := make(chan bool)

	go FuzzDirectory(opts, resultChan, doneChan)
	drainFuzzResults(resultChan, doneChan)

	wantSuffixes := []string{"/index", "/index.php", "/index.html"}
	for _, want := range wantSuffixes {
		found := false
		for _, p := range gotPaths {
			if p == want {
				found = true
			}
		}
		if !found {
			t.Errorf("expected a request to %q, got paths: %v", want, gotPaths)
		}
	}
}

func TestFuzzParameterRaceAndCorrectness(t *testing.T) {
	// Regression test for the data race fixed in FuzzParameter: it used to
	// mutate the shared *url.URL from concurrent goroutines instead of
	// copying it first. Run with -race to verify. Also asserts each request
	// actually carries the parameter under test.
	var mu sync.Mutex
	seenParams := map[string]bool{}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		for k := range r.URL.Query() {
			if k != "existing" {
				seenParams[k] = true
			}
		}
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	opts := FuzzOptions{
		URL:     srv.URL + "?existing=1",
		Words:   []string{"a", "b", "c", "d", "e", "f", "g", "h"},
		Threads: 8,
		Timeout: 5,
	}
	resultChan := make(chan FuzzResult, 1000)
	doneChan := make(chan bool)

	go FuzzParameter(opts, resultChan, doneChan)
	drainFuzzResults(resultChan, doneChan)

	for _, want := range opts.Words {
		if !seenParams[want] {
			t.Errorf("expected a request carrying parameter %q, got seen params: %v", want, seenParams)
		}
	}
}

func TestFuzzParameterInvalidURL(t *testing.T) {
	opts := FuzzOptions{URL: "://not-a-valid-url", Words: []string{"a"}, Threads: 1, Timeout: 1}
	resultChan := make(chan FuzzResult, 10)
	doneChan := make(chan bool)

	go FuzzParameter(opts, resultChan, doneChan)
	results := drainFuzzResults(resultChan, doneChan)

	if len(results) != 1 || results[0].Error == nil {
		t.Errorf("FuzzParameter with an invalid URL should emit a single error result, got %+v", results)
	}
}

func TestFuzzVirtualHostDetectsDifference(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host == "vhost.local" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("special vhost content"))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("default"))
	}))
	defer srv.Close()

	opts := FuzzOptions{URL: srv.URL, Words: []string{"vhost.local", "other.local"}, Threads: 4, Timeout: 5}
	resultChan := make(chan FuzzResult, 100)
	doneChan := make(chan bool)

	go FuzzVirtualHost(opts, resultChan, doneChan)
	results := drainFuzzResults(resultChan, doneChan)

	found := false
	for _, r := range results {
		if r.Input == "vhost.local" {
			found = true
		}
		if r.Input == "other.local" {
			t.Errorf("other.local should match the baseline and not be reported, got %+v", r)
		}
	}
	if !found {
		t.Errorf("expected vhost.local to differ from baseline, results: %+v", results)
	}
}

func TestShouldIncludeResultFilters(t *testing.T) {
	tests := []struct {
		name   string
		result FuzzResult
		opts   FuzzOptions
		want   bool
	}{
		{"error excluded", FuzzResult{Error: assertErr}, FuzzOptions{}, false},
		{"default excludes 4xx", FuzzResult{StatusCode: 404}, FuzzOptions{}, false},
		{"default includes 2xx", FuzzResult{StatusCode: 200}, FuzzOptions{}, true},
		{"match status whitelist hit", FuzzResult{StatusCode: 403}, FuzzOptions{MatchStatus: []int{403}}, true},
		{"match status whitelist miss", FuzzResult{StatusCode: 200}, FuzzOptions{MatchStatus: []int{403}}, false},
		{"filter status blacklist", FuzzResult{StatusCode: 200}, FuzzOptions{FilterStatus: []int{200}}, false},
		{"filter size", FuzzResult{StatusCode: 200, ContentLength: 100}, FuzzOptions{FilterSize: []int{100}}, false},
		{"filter words", FuzzResult{StatusCode: 200, WordCount: 5}, FuzzOptions{FilterWords: []int{5}}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shouldIncludeResult(tt.result, tt.opts); got != tt.want {
				t.Errorf("shouldIncludeResult() = %v, want %v", got, tt.want)
			}
		})
	}
}

var assertErr = errNotFound{}

type errNotFound struct{}

func (errNotFound) Error() string { return "not found" }

func TestDoFuzzRequestBasics(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("one two three\nsecond line"))
	}))
	defer srv.Close()

	client := createHTTPClient(FuzzOptions{Timeout: 5})
	result := doFuzzRequest(client, srv.URL, FuzzOptions{})

	if result.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", result.StatusCode)
	}
	if result.WordCount != 5 {
		t.Errorf("WordCount = %d, want 5", result.WordCount)
	}
	if result.LineCount != 2 {
		t.Errorf("LineCount = %d, want 2", result.LineCount)
	}
}

func TestDoFuzzRequestRedirect(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/target", http.StatusFound)
	}))
	defer srv.Close()

	client := createHTTPClient(FuzzOptions{Timeout: 5, FollowRedir: false})
	result := doFuzzRequest(client, srv.URL, FuzzOptions{})

	if result.Redirect == "" {
		t.Error("expected Redirect to be populated for a 302 response")
	}
}

func TestDoFuzzRequestPOSTWithData(t *testing.T) {
	var gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 1024)
		n, _ := r.Body.Read(buf)
		gotBody = string(buf[:n])
	}))
	defer srv.Close()

	client := createHTTPClient(FuzzOptions{Timeout: 5})
	doFuzzRequest(client, srv.URL, FuzzOptions{Method: "POST", Data: "a=1&b=2"})

	if gotBody != "a=1&b=2" {
		t.Errorf("request body = %q, want a=1&b=2", gotBody)
	}
}

func TestDoFuzzRequestInvalidURL(t *testing.T) {
	client := createHTTPClient(FuzzOptions{Timeout: 5})
	result := doFuzzRequest(client, "://bad-url", FuzzOptions{})
	if result.Error == nil {
		t.Error("doFuzzRequest with an invalid URL should set Error")
	}
}

func TestDisplayResults(t *testing.T) {
	results := &FuzzResults{
		Type:    FuzzDir,
		BaseURL: "http://example.com",
		Total:   2,
		Found:   1,
		Results: []FuzzResult{
			{Input: "admin", StatusCode: 200, ContentLength: 100, WordCount: 10},
			{Input: "backup", StatusCode: 301, ContentLength: 0, WordCount: 0, Redirect: "http://example.com/backup/"},
		},
	}

	out := captureFuzzStdout(t, func() {
		DisplayResults(results)
	})

	for _, want := range []string{"FUZZING RESULTS", "example.com", "admin", "backup", "301"} {
		if !strings.Contains(out, want) {
			t.Errorf("DisplayResults output missing %q; got:\n%s", want, out)
		}
	}
}

func TestDisplayResultsEmpty(t *testing.T) {
	results := &FuzzResults{Type: FuzzDir, BaseURL: "http://example.com"}
	out := captureFuzzStdout(t, func() {
		DisplayResults(results)
	})
	if !strings.Contains(out, "No results found") {
		t.Errorf("DisplayResults with no results should say so; got:\n%s", out)
	}
}

func TestDisplayProgress(t *testing.T) {
	out := captureFuzzStdout(t, func() {
		DisplayProgress(5, 10, 2, 3.5)
	})
	if !strings.Contains(out, "50.0%") || !strings.Contains(out, "Found: 2") {
		t.Errorf("DisplayProgress output wrong; got %q", out)
	}
}
