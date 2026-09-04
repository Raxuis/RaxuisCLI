package httpclient

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"raxuiscli/internal/shared/models"
)

func TestCreateClientAppliesTimeoutDefault(t *testing.T) {
	client := CreateClient(models.ScanOptions{})
	if client.Timeout.Seconds() != DefaultTimeout {
		t.Errorf("CreateClient with no timeout = %v, want %d seconds", client.Timeout, DefaultTimeout)
	}
}

func TestCreateClientDoesNotFollowRedirectsByDefault(t *testing.T) {
	redirected := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/final" {
			redirected = true
			w.Write([]byte("final"))
			return
		}
		http.Redirect(w, r, "/final", http.StatusFound)
	}))
	defer srv.Close()

	client := CreateClient(models.ScanOptions{Timeout: 5, FollowRedir: false})
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("client.Get returned error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Errorf("status = %d, want %d (redirect should not be followed)", resp.StatusCode, http.StatusFound)
	}
	if redirected {
		t.Error("client followed the redirect despite FollowRedir=false")
	}
}

func TestCreateClientFollowsRedirectsWhenEnabled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/final" {
			w.Write([]byte("final"))
			return
		}
		http.Redirect(w, r, "/final", http.StatusFound)
	}))
	defer srv.Close()

	client := CreateClient(models.ScanOptions{Timeout: 5, FollowRedir: true})
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("client.Get returned error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200 (redirect should be followed)", resp.StatusCode)
	}
}

func TestCreateClientFromRequest(t *testing.T) {
	client := CreateClientFromRequest(models.RequestOptions{})
	if client.Timeout.Seconds() != DefaultTimeout {
		t.Errorf("CreateClientFromRequest with no timeout = %v, want %d seconds", client.Timeout, DefaultTimeout)
	}
}

func TestDoRequestSetsHeaders(t *testing.T) {
	var gotMethod, gotUA, gotCookie, gotCustom string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotUA = r.Header.Get("User-Agent")
		gotCookie = r.Header.Get("Cookie")
		gotCustom = r.Header.Get("X-Custom")
		w.Write([]byte("body content"))
	}))
	defer srv.Close()

	client := CreateClient(models.ScanOptions{Timeout: 5})
	opts := models.ScanOptions{
		Method:    "POST",
		UserAgent: "MyAgent/1.0",
		Cookie:    "session=abc",
		Headers:   map[string]string{"X-Custom": "value"},
	}

	resp, body, err := DoRequest(client, srv.URL, opts)
	if err != nil {
		t.Fatalf("DoRequest returned error: %v", err)
	}
	defer resp.Body.Close()

	if gotMethod != "POST" {
		t.Errorf("method = %q, want POST", gotMethod)
	}
	if gotUA != "MyAgent/1.0" {
		t.Errorf("User-Agent = %q, want MyAgent/1.0", gotUA)
	}
	if gotCookie != "session=abc" {
		t.Errorf("Cookie = %q, want session=abc", gotCookie)
	}
	if gotCustom != "value" {
		t.Errorf("X-Custom header = %q, want value", gotCustom)
	}
	if body != "body content" {
		t.Errorf("body = %q, want %q", body, "body content")
	}
}

func TestDoRequestDefaultMethodAndUserAgent(t *testing.T) {
	var gotMethod, gotUA string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotUA = r.Header.Get("User-Agent")
	}))
	defer srv.Close()

	client := CreateClient(models.ScanOptions{Timeout: 5})
	_, _, err := DoRequest(client, srv.URL, models.ScanOptions{})
	if err != nil {
		t.Fatalf("DoRequest returned error: %v", err)
	}

	if gotMethod != "GET" {
		t.Errorf("default method = %q, want GET", gotMethod)
	}
	if gotUA != DefaultUserAgent+"-VulnScanner" {
		t.Errorf("default User-Agent = %q, want %q", gotUA, DefaultUserAgent+"-VulnScanner")
	}
}

func TestDoRequestInvalidURL(t *testing.T) {
	client := CreateClient(models.ScanOptions{Timeout: 5})
	_, _, err := DoRequest(client, "://not-a-valid-url", models.ScanOptions{})
	if err == nil {
		t.Error("DoRequest with a malformed URL should return an error")
	}
}

func TestBuildTestURLDoesNotMutateOriginal(t *testing.T) {
	// Regression test: BuildTestURL must copy the URL rather than mutate it in
	// place, since callers invoke it concurrently from many goroutines against
	// the same parsed *url.URL (this exact bug caused a data race, found via
	// `go test -race`, in internal/web/vuln - see vuln.go's buildTestURL).
	parsed, err := url.Parse("https://example.com/path?existing=1")
	if err != nil {
		t.Fatalf("url.Parse failed: %v", err)
	}
	originalRawQuery := parsed.RawQuery

	result := BuildTestURL(parsed, "new", "value")

	if parsed.RawQuery != originalRawQuery {
		t.Errorf("BuildTestURL mutated the original URL's RawQuery: got %q, want unchanged %q", parsed.RawQuery, originalRawQuery)
	}
	if result == parsed.String() {
		t.Error("BuildTestURL result should differ from the (unmutated) original URL string")
	}
}

func TestBuildTestURLEncodesParam(t *testing.T) {
	parsed, _ := url.Parse("https://example.com/search")
	result := BuildTestURL(parsed, "q", "<script>")

	reparsed, err := url.Parse(result)
	if err != nil {
		t.Fatalf("BuildTestURL produced an unparseable URL %q: %v", result, err)
	}
	if got := reparsed.Query().Get("q"); got != "<script>" {
		t.Errorf("BuildTestURL query param q = %q, want %q", got, "<script>")
	}
}

func TestGetUserAgent(t *testing.T) {
	if got := GetUserAgent("Custom/1.0"); got != "Custom/1.0" {
		t.Errorf("GetUserAgent(Custom/1.0) = %q, want %q", got, "Custom/1.0")
	}
	if got := GetUserAgent(""); got != DefaultUserAgent {
		t.Errorf("GetUserAgent(\"\") = %q, want default %q", got, DefaultUserAgent)
	}
}
