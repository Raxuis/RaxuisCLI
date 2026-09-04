package vuln_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"raxuiscli/internal/web/vuln"
)

func TestXXEFileDisclosure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if len(body) > 0 {
			w.Write([]byte("root:x:0:0:root:/root:/bin/bash"))
			return
		}
		w.Write([]byte("empty"))
	}))
	defer srv.Close()

	opts := vuln.XXEOptions{ScanOptions: vuln.ScanOptions{URL: srv.URL, Timeout: 5}, PayloadType: "file"}
	results := runAndDrain(t, func(ch chan<- vuln.VulnResult) { vuln.TestXXE(opts, ch) })

	found := false
	for _, r := range results {
		if r.Type == vuln.VulnXXE && r.Severity == vuln.SeverityCritical {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a critical XXE finding for leaked /etc/passwd content, got %+v", results)
	}
}

func TestXXEErrorIndicator(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("XML parser error: DOCTYPE not allowed"))
	}))
	defer srv.Close()

	opts := vuln.XXEOptions{ScanOptions: vuln.ScanOptions{URL: srv.URL, Timeout: 5}, PayloadType: "error"}
	results := runAndDrain(t, func(ch chan<- vuln.VulnResult) { vuln.TestXXE(opts, ch) })

	found := false
	for _, r := range results {
		if r.Type == vuln.VulnXXE && r.Severity == vuln.SeverityMedium {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a medium XXE finding for the DOCTYPE parser error, got %+v", results)
	}
}

func TestXXEOOBSkippedWithoutCallback(t *testing.T) {
	requestCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	opts := vuln.XXEOptions{ScanOptions: vuln.ScanOptions{URL: srv.URL, Timeout: 5}, PayloadType: "oob"}
	runAndDrain(t, func(ch chan<- vuln.VulnResult) { vuln.TestXXE(opts, ch) })

	if requestCount != 0 {
		t.Errorf("OOB payloads should be skipped entirely without an OOBCallback, but the server received %d requests", requestCount)
	}
}

func TestXXEOOBWithCallback(t *testing.T) {
	var gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		gotBody = string(body)
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	opts := vuln.XXEOptions{ScanOptions: vuln.ScanOptions{URL: srv.URL, Timeout: 5}, PayloadType: "oob", OOBCallback: "attacker.example"}
	runAndDrain(t, func(ch chan<- vuln.VulnResult) { vuln.TestXXE(opts, ch) })

	if gotBody == "" {
		t.Fatal("expected at least one OOB request to reach the server")
	}
	if !contains(gotBody, "attacker.example") {
		t.Errorf("OOB payload should have CALLBACK replaced with the configured callback, got body: %s", gotBody)
	}
}

func contains(s, substr string) bool {
	return len(substr) == 0 || (len(s) >= len(substr) && indexOf(s, substr) >= 0)
}

func indexOf(s, substr string) int {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

func TestCORSWildcardWithCredentials(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	opts := vuln.CORSOptions{ScanOptions: vuln.ScanOptions{URL: srv.URL, Timeout: 5}, TestOrigin: "https://evil.com"}
	results := runAndDrain(t, func(ch chan<- vuln.VulnResult) { vuln.TestCORS(opts, ch) })

	found := false
	for _, r := range results {
		if r.Type == vuln.VulnCORS && r.Severity == vuln.SeverityCritical {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a critical CORS finding for wildcard origin + credentials, got %+v", results)
	}
}

func TestCORSReflectsOrigin(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	opts := vuln.CORSOptions{ScanOptions: vuln.ScanOptions{URL: srv.URL, Timeout: 5}, TestOrigin: "https://evil.com"}
	results := runAndDrain(t, func(ch chan<- vuln.VulnResult) { vuln.TestCORS(opts, ch) })

	found := false
	for _, r := range results {
		if r.Type == vuln.VulnCORS && r.Severity == vuln.SeverityHigh {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a high-severity CORS finding for reflected origin, got %+v", results)
	}
}

func TestCORSNullOrigin(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Origin") == "null" {
			w.Header().Set("Access-Control-Allow-Origin", "null")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	opts := vuln.CORSOptions{ScanOptions: vuln.ScanOptions{URL: srv.URL, Timeout: 5}, TestOrigin: "null"}
	results := runAndDrain(t, func(ch chan<- vuln.VulnResult) { vuln.TestCORS(opts, ch) })

	found := false
	for _, r := range results {
		if r.Type == vuln.VulnCORS {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a CORS finding for accepted null origin, got %+v", results)
	}
}

func TestCORSSecure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// No CORS headers at all - secure default.
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	opts := vuln.CORSOptions{ScanOptions: vuln.ScanOptions{URL: srv.URL, Timeout: 5}, TestOrigin: "https://evil.com"}
	results := runAndDrain(t, func(ch chan<- vuln.VulnResult) { vuln.TestCORS(opts, ch) })
	if len(results) != 0 {
		t.Errorf("expected no CORS findings for a server with no CORS headers, got %+v", results)
	}
}

func TestCORSFullModeTestsGET(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.Header().Set("Access-Control-Allow-Origin", "*")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	opts := vuln.CORSOptions{ScanOptions: vuln.ScanOptions{URL: srv.URL, Timeout: 5}, TestOrigin: "https://evil.com", Full: true}
	results := runAndDrain(t, func(ch chan<- vuln.VulnResult) { vuln.TestCORS(opts, ch) })

	found := false
	for _, r := range results {
		if r.Parameter == "GET Request CORS" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a GET-request CORS finding in Full mode, got %+v", results)
	}
}

func TestCORSInvalidURL(t *testing.T) {
	opts := vuln.CORSOptions{ScanOptions: vuln.ScanOptions{URL: "://bad", Timeout: 5}}
	results := runAndDrain(t, func(ch chan<- vuln.VulnResult) { vuln.TestCORS(opts, ch) })
	if len(results) != 0 {
		t.Error("TestCORS with an invalid URL should produce no results")
	}
}

func TestGraphQLIntrospectionEnabled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"data":{"__schema":{"queryType":{"name":"Query"},"types":[{"fields":[{"name":"password"}]}]}}}`))
	}))
	defer srv.Close()

	opts := vuln.GraphQLOptions{ScanOptions: vuln.ScanOptions{URL: srv.URL, Timeout: 5}}
	results := runAndDrain(t, func(ch chan<- vuln.VulnResult) { vuln.TestGraphQL(opts, ch) })

	// TestGraphQL breaks out of the introspection-queries loop as soon as it
	// finds one, so the sensitive-type-name check never runs against the
	// same response - only the Introspection finding is expected here.
	found := false
	for _, r := range results {
		if r.Type == vuln.VulnGraphQL && r.Parameter == "Introspection" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected an introspection-enabled finding, got %+v", results)
	}
}

func TestGraphQLSensitiveFieldWithoutIntrospection(t *testing.T) {
	// A response that doesn't look like introspection output (no __schema /
	// __type) but leaks a sensitive field name should still be flagged.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"errors":[{"message":"field 'password' is not queryable"}]}`))
	}))
	defer srv.Close()

	opts := vuln.GraphQLOptions{ScanOptions: vuln.ScanOptions{URL: srv.URL, Timeout: 5}}
	results := runAndDrain(t, func(ch chan<- vuln.VulnResult) { vuln.TestGraphQL(opts, ch) })

	found := false
	for _, r := range results {
		if r.Type == vuln.VulnGraphQL && r.Parameter == "Schema" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a sensitive-field finding (password) since the body isn't introspection output, got %+v", results)
	}
}

func TestGraphQLFieldSuggestions(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"errors":[{"message":"Cannot query field \"badfield\". Did you mean \"goodfield\"?"}]}`))
	}))
	defer srv.Close()

	opts := vuln.GraphQLOptions{ScanOptions: vuln.ScanOptions{URL: srv.URL, Timeout: 5}}
	results := runAndDrain(t, func(ch chan<- vuln.VulnResult) { vuln.TestGraphQL(opts, ch) })

	found := false
	for _, r := range results {
		if r.Parameter == "Field Suggestions" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a field-suggestions finding, got %+v", results)
	}
}

func TestGraphQLBatchingDoS(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if len(body) > 0 && body[0] == '[' {
			w.Write([]byte(`[{"data":{"__typename":"Query"}},{"data":{"__typename":"Query"}}]`))
			return
		}
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	opts := vuln.GraphQLOptions{ScanOptions: vuln.ScanOptions{URL: srv.URL, Timeout: 5}, DoS: true}
	results := runAndDrain(t, func(ch chan<- vuln.VulnResult) { vuln.TestGraphQL(opts, ch) })

	found := false
	for _, r := range results {
		if r.Parameter == "Batching" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a query-batching DoS finding, got %+v", results)
	}
}
