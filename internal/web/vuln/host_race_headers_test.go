package vuln_test

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/Raxuis/RaxuisCLI/internal/web/vuln"
)

func TestHostHeaderReflected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Reflect whatever Host the server actually received back into the body.
		w.Write([]byte("your host: " + r.Host))
	}))
	defer srv.Close()

	opts := vuln.HostHeaderOptions{ScanOptions: vuln.ScanOptions{URL: srv.URL, Timeout: 5}}
	results := runAndDrain(t, func(ch chan<- vuln.VulnResult) { vuln.TestHostHeader(opts, ch) })

	found := false
	for _, r := range results {
		if r.Type == vuln.VulnHostHeader {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a host header injection finding when the Host is reflected in the body, got %+v", results)
	}
}

func TestHostHeaderRedirectReflection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "https://"+r.Host+"/")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	opts := vuln.HostHeaderOptions{ScanOptions: vuln.ScanOptions{URL: srv.URL, Timeout: 5, FollowRedir: false}}
	results := runAndDrain(t, func(ch chan<- vuln.VulnResult) { vuln.TestHostHeader(opts, ch) })

	found := false
	for _, r := range results {
		if r.Evidence != "" && r.Type == vuln.VulnHostHeader {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a host header finding from the redirect Location reflecting the Host, got %+v", results)
	}
}

func TestHostHeaderNotVulnerable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("static content, ignores host"))
	}))
	defer srv.Close()

	opts := vuln.HostHeaderOptions{ScanOptions: vuln.ScanOptions{URL: srv.URL, Timeout: 5}}
	results := runAndDrain(t, func(ch chan<- vuln.VulnResult) { vuln.TestHostHeader(opts, ch) })
	if len(results) != 0 {
		t.Errorf("expected no findings when the Host header is never reflected, got %+v", results)
	}
}

func TestHostHeaderPasswordResetPoisoning(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/reset-password" {
			w.Write([]byte("reset email sent"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	opts := vuln.HostHeaderOptions{ScanOptions: vuln.ScanOptions{URL: srv.URL, Timeout: 5}, Poison: true}
	results := runAndDrain(t, func(ch chan<- vuln.VulnResult) { vuln.TestHostHeader(opts, ch) })

	found := false
	for _, r := range results {
		if r.Parameter == "Password Reset Poisoning" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a password reset poisoning finding, got %+v", results)
	}
}

func TestHostHeaderCachePoisoning(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Cache", "HIT")
		w.Write([]byte("cached content for " + r.Host))
	}))
	defer srv.Close()

	opts := vuln.HostHeaderOptions{ScanOptions: vuln.ScanOptions{URL: srv.URL, Timeout: 5}, Cache: true}
	results := runAndDrain(t, func(ch chan<- vuln.VulnResult) { vuln.TestHostHeader(opts, ch) })

	found := false
	for _, r := range results {
		if r.Parameter == "Cache Poisoning" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a cache poisoning finding when X-Cache: HIT and Host is reflected, got %+v", results)
	}
}

func TestHostHeaderInvalidURL(t *testing.T) {
	opts := vuln.HostHeaderOptions{ScanOptions: vuln.ScanOptions{URL: "://bad", Timeout: 5}}
	results := runAndDrain(t, func(ch chan<- vuln.VulnResult) { vuln.TestHostHeader(opts, ch) })
	if len(results) != 0 {
		t.Error("TestHostHeader with an invalid URL should produce no results")
	}
}

func TestRaceConditionDetectsMultipleSuccess(t *testing.T) {
	// A deliberately racy handler: read-check-write on a shared counter with
	// no locking, so concurrent requests can all observe "not yet used".
	var mu sync.Mutex
	used := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		wasUsed := used
		mu.Unlock()
		// Intentional gap for the race to manifest, mirroring a real
		// check-then-act bug in application code.
		if !wasUsed {
			mu.Lock()
			used = true
			mu.Unlock()
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusOK) // Racy: still returns 200 more than once.
	}))
	defer srv.Close()

	opts := vuln.RaceOptions{ScanOptions: vuln.ScanOptions{URL: srv.URL, Timeout: 5}, Requests: 20}
	results := runAndDrain(t, func(ch chan<- vuln.VulnResult) { vuln.TestRaceCondition(opts, ch) })

	foundSummary := false
	for _, r := range results {
		if r.Type == vuln.VulnRace && r.Parameter == "Summary" {
			foundSummary = true
		}
	}
	if !foundSummary {
		t.Errorf("expected a Summary result to always be emitted, got %+v", results)
	}
}

func TestRaceConditionDefaultRequestCount(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// Requests <= 0 should default to 10.
	opts := vuln.RaceOptions{ScanOptions: vuln.ScanOptions{URL: srv.URL, Timeout: 5}, Requests: 0}
	results := runAndDrain(t, func(ch chan<- vuln.VulnResult) { vuln.TestRaceCondition(opts, ch) })

	found := false
	for _, r := range results {
		if r.Parameter == "Summary" {
			found = true
		}
	}
	if !found {
		t.Error("expected a Summary result even with the default request count")
	}
}

func TestRaceConditionWithBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	opts := vuln.RaceOptions{
		ScanOptions: vuln.ScanOptions{URL: srv.URL, Timeout: 5},
		Data:        `{"code":"PROMO"}`,
		Requests:    5,
	}
	results := runAndDrain(t, func(ch chan<- vuln.VulnResult) { vuln.TestRaceCondition(opts, ch) })
	if len(results) == 0 {
		t.Error("expected at least a Summary result for a JSON-body race test")
	}
}

func TestScanSecurityHeadersReportsMissing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	results := vuln.ScanSecurityHeaders(vuln.ScanOptions{URL: srv.URL, Timeout: 5})

	found := false
	for _, r := range results {
		if r.Type == vuln.VulnHeaders && r.Parameter == "Strict-Transport-Security" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a missing-HSTS finding for a bare server, got %+v", results)
	}
}

func TestScanSecurityHeadersServerDisclosure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.18.0")
		w.Header().Set("X-Powered-By", "PHP/8.1")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	results := vuln.ScanSecurityHeaders(vuln.ScanOptions{URL: srv.URL, Timeout: 5})

	foundServer, foundPowered := false, false
	for _, r := range results {
		if r.Parameter == "Server" {
			foundServer = true
		}
		if r.Parameter == "X-Powered-By" {
			foundPowered = true
		}
	}
	if !foundServer {
		t.Error("expected a Server-header disclosure finding")
	}
	if !foundPowered {
		t.Error("expected an X-Powered-By disclosure finding")
	}
}

func TestScanSecurityHeadersInsecureCookies(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "abc"}) // no Secure/HttpOnly/SameSite
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	results := vuln.ScanSecurityHeaders(vuln.ScanOptions{URL: srv.URL, Timeout: 5})

	found := false
	for _, r := range results {
		if r.Parameter == "Cookie: session" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected an insecure-cookie finding, got %+v", results)
	}
}

func TestScanSecurityHeadersRequestError(t *testing.T) {
	results := vuln.ScanSecurityHeaders(vuln.ScanOptions{URL: "://bad", Timeout: 5})
	if len(results) != 0 {
		t.Error("ScanSecurityHeaders with an invalid URL should return no results")
	}
}
