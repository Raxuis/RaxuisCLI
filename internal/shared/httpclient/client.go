package httpclient

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"time"

	"raxuiscli/internal/shared/models"
)

const (
	DefaultUserAgent = "RaxuisCLI/1.0"
	DefaultTimeout   = 10
	DefaultThreads   = 10
)

// CreateClient creates an HTTP client with the given options
func CreateClient(opts models.ScanOptions) *http.Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: opts.Insecure,
		},
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: opts.Threads,
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(timeout) * time.Second,
	}

	if !opts.FollowRedir {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	return client
}

// CreateClientFromRequest creates an HTTP client from RequestOptions
func CreateClientFromRequest(opts models.RequestOptions) *http.Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: opts.Insecure,
		},
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(timeout) * time.Second,
	}

	if !opts.FollowRedir {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	return client
}

// DoRequest performs an HTTP request and returns the response with body. It is
// kept for compatibility with callers that do not need cancellation or a body
// limit.
func DoRequest(client *http.Client, targetURL string, opts models.ScanOptions) (*http.Response, string, error) {
	resp, body, _, err := DoRequestContext(context.Background(), client, targetURL, opts, 0)
	return resp, body, err
}

// DoRequestContext performs an HTTP request with cancellation and an optional
// response-body limit. A positive maxBodyBytes limits the returned body and
// reports whether it was truncated. A non-positive limit preserves DoRequest's
// unbounded behavior.
func DoRequestContext(ctx context.Context, client *http.Client, targetURL string, opts models.ScanOptions, maxBodyBytes int64) (*http.Response, string, bool, error) {
	if ctx == nil {
		return nil, "", false, fmt.Errorf("request context must not be nil")
	}
	if client == nil {
		return nil, "", false, fmt.Errorf("HTTP client must not be nil")
	}

	method := opts.Method
	if method == "" {
		method = "GET"
	}

	req, err := http.NewRequestWithContext(ctx, method, targetURL, nil)
	if err != nil {
		return nil, "", false, fmt.Errorf("failed to create request: %w", err)
	}

	if opts.UserAgent != "" {
		req.Header.Set("User-Agent", opts.UserAgent)
	} else {
		req.Header.Set("User-Agent", DefaultUserAgent+"-VulnScanner")
	}

	if opts.Cookie != "" {
		req.Header.Set("Cookie", opts.Cookie)
	}

	for key, value := range opts.Headers {
		req.Header.Set(key, value)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, "", false, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, truncated, err := readResponseBody(resp.Body, maxBodyBytes)
	if err != nil {
		return resp, "", false, fmt.Errorf("failed to read response: %w", err)
	}
	return resp, string(body), truncated, nil
}

func readResponseBody(body io.Reader, maxBodyBytes int64) ([]byte, bool, error) {
	if maxBodyBytes <= 0 {
		contents, err := io.ReadAll(body)
		return contents, false, err
	}
	if maxBodyBytes == math.MaxInt64 {
		contents, err := io.ReadAll(io.LimitReader(body, maxBodyBytes))
		return contents, false, err
	}

	contents, err := io.ReadAll(io.LimitReader(body, maxBodyBytes+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(contents)) > maxBodyBytes {
		return contents[:maxBodyBytes], true, nil
	}
	return contents, false, nil
}

// BuildTestURL builds a URL with a test payload for a parameter
func BuildTestURL(parsedURL *url.URL, param, payload string) string {
	// Create a copy of the URL to avoid modifying the original
	testURL := *parsedURL
	query := testURL.Query()
	query.Set(param, payload)
	testURL.RawQuery = query.Encode()
	return testURL.String()
}

// GetUserAgent returns the user agent to use, defaulting if empty
func GetUserAgent(userAgent string) string {
	if userAgent != "" {
		return userAgent
	}
	return DefaultUserAgent
}
