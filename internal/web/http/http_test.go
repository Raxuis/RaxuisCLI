package http

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestDoRequestContextHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := DoRequestContext(ctx, RequestOptions{URL: "http://example.com"}, 1024)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("DoRequestContext error = %v, want context.Canceled", err)
	}
}

func TestDoRequestContextTruncatesBodyAtConfiguredCap(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("abcdef"))
	}))
	defer srv.Close()

	resp, err := DoRequestContext(context.Background(), RequestOptions{URL: srv.URL}, 4)
	if err != nil {
		t.Fatalf("DoRequestContext returned error: %v", err)
	}
	if resp.Body != "abcd" {
		t.Errorf("Body = %q, want %q", resp.Body, "abcd")
	}
	if !resp.Truncated {
		t.Error("Truncated = false, want true")
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

	_, err := DoRequestContext(context.Background(), RequestOptions{URL: srv.URL}, 1024)
	if err == nil {
		t.Fatal("DoRequestContext returned nil error for an interrupted response body")
	}
}

func TestDoRequestContextRejectsMalformedProxy(t *testing.T) {
	_, err := DoRequestContext(context.Background(), RequestOptions{
		URL:   "http://example.com",
		Proxy: "://not-a-valid-proxy",
	}, 1024)
	if err == nil {
		t.Fatal("DoRequestContext returned nil error for a malformed proxy URL")
	}
}

func TestDoRequestBasicGET(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("hello"))
	}))
	defer srv.Close()

	resp, err := DoRequest(RequestOptions{URL: srv.URL})
	if err != nil {
		t.Fatalf("DoRequest returned error: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", resp.StatusCode)
	}
	if resp.Body != "hello" {
		t.Errorf("Body = %q, want %q", resp.Body, "hello")
	}
}

func TestDoRequestSetsHeadersAndDefaults(t *testing.T) {
	var gotUA, gotMethod, gotCookie, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Get("User-Agent")
		gotMethod = r.Method
		gotCookie = r.Header.Get("Cookie")
		if u, p, ok := r.BasicAuth(); ok {
			gotAuth = u + ":" + p
		}
	}))
	defer srv.Close()

	_, err := DoRequest(RequestOptions{
		URL:       srv.URL,
		Cookie:    "session=abc",
		BasicAuth: "user:pass",
	})
	if err != nil {
		t.Fatalf("DoRequest returned error: %v", err)
	}

	if gotMethod != "GET" {
		t.Errorf("default Method = %q, want GET", gotMethod)
	}
	if gotUA != "RaxuisCLI/1.0" {
		t.Errorf("default UserAgent = %q, want RaxuisCLI/1.0", gotUA)
	}
	if gotCookie != "session=abc" {
		t.Errorf("Cookie = %q, want session=abc", gotCookie)
	}
	if gotAuth != "user:pass" {
		t.Errorf("BasicAuth = %q, want user:pass", gotAuth)
	}
}

func TestDoRequestCustomHeaders(t *testing.T) {
	var gotCustom string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCustom = r.Header.Get("X-Custom")
	}))
	defer srv.Close()

	_, err := DoRequest(RequestOptions{URL: srv.URL, Headers: map[string]string{"X-Custom": "value"}})
	if err != nil {
		t.Fatalf("DoRequest returned error: %v", err)
	}
	if gotCustom != "value" {
		t.Errorf("X-Custom = %q, want value", gotCustom)
	}
}

func TestDoRequestBodyContentTypeDetection(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{"json", `{"a":1}`, "application/json"},
		{"form", "a=1&b=2", "application/x-www-form-urlencoded"},
		{"plain", "plain text no equals", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotCT string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotCT = r.Header.Get("Content-Type")
			}))
			defer srv.Close()

			_, err := DoRequest(RequestOptions{URL: srv.URL, Method: "POST", Body: tt.body})
			if err != nil {
				t.Fatalf("DoRequest returned error: %v", err)
			}
			if gotCT != tt.want {
				t.Errorf("Content-Type = %q, want %q", gotCT, tt.want)
			}
		})
	}
}

func TestDoRequestExplicitContentTypeNotOverridden(t *testing.T) {
	var gotCT string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCT = r.Header.Get("Content-Type")
	}))
	defer srv.Close()

	_, err := DoRequest(RequestOptions{
		URL:     srv.URL,
		Method:  "POST",
		Body:    `{"a":1}`,
		Headers: map[string]string{"Content-Type": "text/plain"},
	})
	if err != nil {
		t.Fatalf("DoRequest returned error: %v", err)
	}
	if gotCT != "text/plain" {
		t.Errorf("Content-Type = %q, want text/plain (explicit header should win)", gotCT)
	}
}

func TestDoRequestDoesNotFollowRedirectsByDefault(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/final" {
			w.Write([]byte("final"))
			return
		}
		http.Redirect(w, r, "/final", http.StatusFound)
	}))
	defer srv.Close()

	resp, err := DoRequest(RequestOptions{URL: srv.URL, FollowRedir: false})
	if err != nil {
		t.Fatalf("DoRequest returned error: %v", err)
	}
	if resp.StatusCode != http.StatusFound {
		t.Errorf("StatusCode = %d, want 302 (redirect not followed)", resp.StatusCode)
	}
	if len(resp.RedirectChain) != 1 {
		t.Errorf("RedirectChain = %v, want 1 entry", resp.RedirectChain)
	}
}

func TestDoRequestFollowsRedirectsWhenEnabled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/final" {
			w.Write([]byte("final"))
			return
		}
		http.Redirect(w, r, "/final", http.StatusFound)
	}))
	defer srv.Close()

	resp, err := DoRequest(RequestOptions{URL: srv.URL, FollowRedir: true})
	if err != nil {
		t.Fatalf("DoRequest returned error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want 200 (redirect followed)", resp.StatusCode)
	}
	if resp.Body != "final" {
		t.Errorf("Body = %q, want final", resp.Body)
	}
}

func TestDoRequestTLSInfo(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("secure"))
	}))
	defer srv.Close()

	resp, err := DoRequest(RequestOptions{URL: srv.URL, Insecure: true})
	if err != nil {
		t.Fatalf("DoRequest returned error: %v", err)
	}
	if resp.TLS == nil {
		t.Fatal("expected TLS info to be populated for an HTTPS response")
	}
	if resp.TLS.Version == "" {
		t.Error("TLS.Version should not be empty")
	}
}

func TestDoRequestInsecureSkipsVerify(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	// Without Insecure:true this should fail due to the self-signed cert.
	if _, err := DoRequest(RequestOptions{URL: srv.URL}); err == nil {
		t.Error("DoRequest against a self-signed TLS server without Insecure=true should fail")
	}

	if _, err := DoRequest(RequestOptions{URL: srv.URL, Insecure: true}); err != nil {
		t.Errorf("DoRequest with Insecure=true should succeed, got: %v", err)
	}
}

func TestDoRequestInvalidURL(t *testing.T) {
	if _, err := DoRequest(RequestOptions{URL: "://not-a-valid-url"}); err == nil {
		t.Error("DoRequest with a malformed URL should return an error")
	}
}

func TestDoRequestConnectionRefused(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to reserve an address: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close() // nothing listens here anymore

	if _, err := DoRequest(RequestOptions{URL: "http://" + addr, Timeout: 1}); err == nil {
		t.Error("DoRequest against a closed port should return an error")
	}
}

func TestTLSVersionString(t *testing.T) {
	tests := []struct {
		version uint16
		want    string
	}{
		{0x0301, "TLS 1.0"},
		{0x0302, "TLS 1.1"},
		{0x0303, "TLS 1.2"},
		{0x0304, "TLS 1.3"},
		{0x9999, "Unknown (0x9999)"},
	}
	for _, tt := range tests {
		if got := tlsVersionString(tt.version); got != tt.want {
			t.Errorf("tlsVersionString(%#04x) = %q, want %q", tt.version, got, tt.want)
		}
	}
}

func TestAnalyzeSecurityHeadersFullScore(t *testing.T) {
	headers := http.Header{}
	headers.Set("Strict-Transport-Security", "max-age=31536000")
	headers.Set("Content-Security-Policy", "default-src 'self'")
	headers.Set("X-Content-Type-Options", "nosniff")
	headers.Set("X-Frame-Options", "DENY")
	headers.Set("Referrer-Policy", "no-referrer")
	headers.Set("Permissions-Policy", "geolocation=()")

	analysis := AnalyzeSecurityHeaders(headers)
	if analysis.Grade != "A" && analysis.Grade != "B" {
		t.Errorf("expected a high grade with all secure headers set, got %s (score %d)", analysis.Grade, analysis.Score)
	}
	if len(analysis.Missing) != 0 {
		t.Errorf("Missing = %v, want none", analysis.Missing)
	}
}

func TestAnalyzeSecurityHeadersEmpty(t *testing.T) {
	analysis := AnalyzeSecurityHeaders(http.Header{})
	if analysis.Grade != "F" {
		t.Errorf("Grade with no security headers = %q, want F", analysis.Grade)
	}
	if len(analysis.Missing) == 0 {
		t.Error("expected several missing required headers")
	}
}

func TestAnalyzeSecurityHeadersUnsafeCSP(t *testing.T) {
	headers := http.Header{}
	headers.Set("Content-Security-Policy", "script-src 'unsafe-inline'")

	analysis := AnalyzeSecurityHeaders(headers)
	found := false
	for _, h := range analysis.Headers {
		if h.Name == "Content-Security-Policy" {
			if h.Secure {
				t.Error("CSP with unsafe-inline should not be marked secure")
			}
			found = true
		}
	}
	if !found {
		t.Error("CSP header check missing from results")
	}
}

func TestAnalyzeSecurityHeadersServerExposed(t *testing.T) {
	headers := http.Header{}
	headers.Set("Server", "nginx/1.18.0")

	analysis := AnalyzeSecurityHeaders(headers)
	foundWarning := false
	for _, w := range analysis.Warnings {
		if strings.Contains(w, "nginx") {
			foundWarning = true
		}
	}
	if !foundWarning {
		t.Errorf("expected a warning about the exposed Server header, got %v", analysis.Warnings)
	}
}

func TestGenerateCurl(t *testing.T) {
	curl := GenerateCurl(RequestOptions{
		Method:      "POST",
		URL:         "https://example.com/api",
		Insecure:    true,
		FollowRedir: false,
		Headers:     map[string]string{"X-Test": "1"},
		UserAgent:   "Custom/2.0",
		Cookie:      "session=abc",
		BasicAuth:   "user:pass",
		Body:        `{"a":1}`,
		Proxy:       "http://proxy.local:8080",
	})

	for _, want := range []string{"curl", "-X POST", "-k", "-L", "X-Test: 1", "Custom/2.0", "session=abc", "user:pass", `{"a":1}`, "proxy.local", "example.com/api"} {
		if !strings.Contains(curl, want) {
			t.Errorf("GenerateCurl output missing %q; got: %s", want, curl)
		}
	}
}

func TestGenerateCurlDefaults(t *testing.T) {
	curl := GenerateCurl(RequestOptions{Method: "GET", URL: "https://example.com", FollowRedir: true})
	if strings.Contains(curl, "-X") {
		t.Errorf("GenerateCurl for a plain GET should not include -X, got: %s", curl)
	}
	if strings.Contains(curl, "-L") {
		t.Errorf("GenerateCurl with FollowRedir=true should not include -L, got: %s", curl)
	}
}

func TestDetectTechnologyHeaders(t *testing.T) {
	headers := http.Header{}
	headers.Set("Server", "nginx/1.18.0")
	headers.Set("X-Powered-By", "PHP/8.1")

	techs := DetectTechnology(headers, "")
	if !containsStrHelper(techs, "Nginx") {
		t.Errorf("DetectTechnology should detect Nginx from Server header, got %v", techs)
	}
	if !containsStrHelper(techs, "PHP") {
		t.Errorf("DetectTechnology should detect PHP from X-Powered-By header, got %v", techs)
	}
}

func TestDetectTechnologyBody(t *testing.T) {
	techs := DetectTechnology(http.Header{}, "<html><body class='wp-content'>react app</body></html>")
	if !containsStrHelper(techs, "WordPress") {
		t.Errorf("DetectTechnology should detect WordPress from body, got %v", techs)
	}
	if !containsStrHelper(techs, "React") {
		t.Errorf("DetectTechnology should detect React from body, got %v", techs)
	}
}

func TestDetectTechnologyNoDuplicates(t *testing.T) {
	headers := http.Header{}
	headers.Set("X-Generator", "wordpress")
	techs := DetectTechnology(headers, "wp-content everywhere wp-content wp-content")

	count := 0
	for _, tech := range techs {
		if tech == "WordPress" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("DetectTechnology should not report WordPress more than once, got %d times in %v", count, techs)
	}
}

func TestDetectTechnologyNone(t *testing.T) {
	techs := DetectTechnology(http.Header{}, "plain body with nothing recognizable")
	if len(techs) != 0 {
		t.Errorf("DetectTechnology on a plain body should return no techs, got %v", techs)
	}
}

func TestFormatJSON(t *testing.T) {
	got := FormatJSON(`{"b":2,"a":1}`)
	if !strings.Contains(got, "\"a\": 1") || !strings.Contains(got, "\"b\": 2") {
		t.Errorf("FormatJSON should pretty-print the JSON body, got: %s", got)
	}
}

func TestFormatJSONInvalidReturnsOriginal(t *testing.T) {
	input := "not json at all"
	if got := FormatJSON(input); got != input {
		t.Errorf("FormatJSON on invalid JSON should return the original string, got %q", got)
	}
}

func captureStdoutHelper(t *testing.T, fn func()) string {
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

func TestDisplayResponse(t *testing.T) {
	resp := &Response{
		Status:        "200 OK",
		Duration:      0,
		ContentLength: 5,
		Body:          "hello world this is a long body",
		Headers:       http.Header{"Content-Type": []string{"text/plain"}},
		RedirectChain: []string{"http://example.com/first"},
		TLS:           &TLSInfo{Version: "TLS 1.3", CipherSuite: "TLS_AES_128_GCM_SHA256"},
	}

	out := captureStdoutHelper(t, func() {
		DisplayResponse(resp, true, 10)
	})

	for _, want := range []string{"200 OK", "Content-Type", "TLS 1.3", "example.com/first", "truncated"} {
		if !strings.Contains(out, want) {
			t.Errorf("DisplayResponse output missing %q; got:\n%s", want, out)
		}
	}
}

func TestDisplayResponseNoBody(t *testing.T) {
	resp := &Response{Status: "204 No Content", Headers: http.Header{}}
	out := captureStdoutHelper(t, func() {
		DisplayResponse(resp, false, 0)
	})
	if strings.Contains(out, "[Body]") {
		t.Error("DisplayResponse with showBody=false should not print a Body section")
	}
}

func TestDisplayHeaderAnalysis(t *testing.T) {
	analysis := AnalyzeSecurityHeaders(http.Header{})
	out := captureStdoutHelper(t, func() {
		DisplayHeaderAnalysis(analysis)
	})
	for _, want := range []string{"SECURITY HEADERS ANALYSIS", "Security Score", "Missing Headers"} {
		if !strings.Contains(out, want) {
			t.Errorf("DisplayHeaderAnalysis output missing %q; got:\n%s", want, out)
		}
	}
}

func TestDisplayTechnologies(t *testing.T) {
	out := captureStdoutHelper(t, func() {
		DisplayTechnologies([]string{"React", "Nginx"})
	})
	if !strings.Contains(out, "React") || !strings.Contains(out, "Nginx") {
		t.Errorf("DisplayTechnologies output missing techs; got:\n%s", out)
	}
}

func TestDisplayTechnologiesEmpty(t *testing.T) {
	out := captureStdoutHelper(t, func() {
		DisplayTechnologies(nil)
	})
	if out != "" {
		t.Errorf("DisplayTechnologies with no techs should print nothing, got %q", out)
	}
}

func containsStrHelper(list []string, want string) bool {
	for _, item := range list {
		if item == want {
			return true
		}
	}
	return false
}
