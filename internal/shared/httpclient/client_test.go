package httpclient

import (
	"context"
	"errors"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Raxuis/RaxuisCLI/internal/shared/models"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}

type trackingReadCloser struct {
	io.Reader
	closed bool
}

func (body *trackingReadCloser) Close() error {
	body.closed = true
	return nil
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) {
	return 0, errors.New("interrupted body")
}

func TestDoRequestContextHonorsCancellation(t *testing.T) {
	started := make(chan struct{})
	handlerDone := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
		close(handlerDone)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errs := make(chan error, 1)
	go func() {
		resp, _, _, err := DoRequestContext(ctx, CreateClient(models.ScanOptions{}), srv.URL, models.ScanOptions{}, 1024)
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
		errs <- err
	}()

	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("request did not reach the blocking handler")
	}
	cancel()

	select {
	case err := <-errs:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("DoRequestContext error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("DoRequestContext did not return after cancellation")
	}
	select {
	case <-handlerDone:
	case <-time.After(time.Second):
		t.Fatal("handler did not observe request cancellation")
	}
}

func TestDoRequestContextSupportsMaxInt64Cap(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("body"))
	}))
	defer srv.Close()

	resp, body, truncated, err := DoRequestContext(context.Background(), CreateClient(models.ScanOptions{}), srv.URL, models.ScanOptions{}, math.MaxInt64)
	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		t.Fatalf("DoRequestContext returned error: %v", err)
	}
	if resp == nil || body != "body" || truncated {
		t.Errorf("response = %v, body = %q, truncated = %t; want full body without truncation", resp, body, truncated)
	}
}

func TestDoRequestContextWrapsRequestConstructionError(t *testing.T) {
	resp, _, _, err := DoRequestContext(context.Background(), CreateClient(models.ScanOptions{}), "://not-a-valid-url", models.ScanOptions{}, 1024)
	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "failed to create request:") {
		t.Fatalf("DoRequestContext error = %v, want wrapped request-construction error", err)
	}
}

func TestDoRequestContextWrapsTransportError(t *testing.T) {
	want := errors.New("transport unavailable")
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, want
	})}

	resp, _, _, err := DoRequestContext(context.Background(), client, "http://example.com", models.ScanOptions{}, 1024)
	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
	}
	if err == want || !errors.Is(err, want) || !strings.Contains(err.Error(), "request failed:") {
		t.Fatalf("DoRequestContext error = %v, want wrapped transport error", err)
	}
}

func TestDoRequestContextTruncatesBodyAtConfiguredCap(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("abcdef"))
	}))
	defer srv.Close()

	resp, body, truncated, err := DoRequestContext(context.Background(), CreateClient(models.ScanOptions{}), srv.URL, models.ScanOptions{}, 4)
	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		t.Fatalf("DoRequestContext returned error: %v", err)
	}
	if resp == nil {
		t.Fatal("DoRequestContext returned a nil response")
	}
	if body != "abcd" {
		t.Errorf("body = %q, want %q", body, "abcd")
	}
	if !truncated {
		t.Error("truncated = false, want true")
	}
}

func TestDoRequestContextReturnsInterruptedBodyError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			t.Fatal("response writer does not support hijacking")
		}
		conn, buf, err := hijacker.Hijack()
		if err != nil {
			t.Fatalf("Hijack: %v", err)
		}
		_, _ = buf.WriteString("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nshort")
		_ = buf.Flush()
		_ = conn.Close()
	}))
	defer srv.Close()

	resp, _, _, err := DoRequestContext(context.Background(), CreateClient(models.ScanOptions{}), srv.URL, models.ScanOptions{}, 1024)
	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
	}
	if err == nil {
		t.Fatal("DoRequestContext returned nil error for an interrupted response body")
	}
}

func TestDoRequestContextClosesBodyAfterReadSuccessAndFailure(t *testing.T) {
	tests := []struct {
		name    string
		reader  io.Reader
		wantErr bool
	}{
		{name: "success", reader: strings.NewReader("ok")},
		{name: "read failure", reader: failingReader{}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := &trackingReadCloser{Reader: tt.reader}
			client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusOK, Body: body, Header: make(http.Header)}, nil
			})}

			resp, _, _, err := DoRequestContext(context.Background(), client, "http://example.com", models.ScanOptions{}, 1024)
			if resp != nil && resp.Body != nil {
				defer resp.Body.Close()
			}
			if (err != nil) != tt.wantErr {
				t.Fatalf("DoRequestContext error = %v, want error=%t", err, tt.wantErr)
			}
			if !body.closed {
				t.Fatal("response body was not closed")
			}
		})
	}
}

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
	resp, _, err := DoRequest(client, srv.URL, models.ScanOptions{})
	if err != nil {
		t.Fatalf("DoRequest returned error: %v", err)
	}
	defer resp.Body.Close()

	if gotMethod != "GET" {
		t.Errorf("default method = %q, want GET", gotMethod)
	}
	if gotUA != DefaultUserAgent+"-VulnScanner" {
		t.Errorf("default User-Agent = %q, want %q", gotUA, DefaultUserAgent+"-VulnScanner")
	}
}

func TestDoRequestInvalidURL(t *testing.T) {
	client := CreateClient(models.ScanOptions{Timeout: 5})
	resp, _, err := DoRequest(client, "://not-a-valid-url", models.ScanOptions{})
	if resp != nil {
		defer resp.Body.Close()
		t.Error("DoRequest with a malformed URL should not return a response")
	}
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
