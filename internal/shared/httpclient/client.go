package httpclient

import (
	"crypto/tls"
	"io"
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

// DoRequest performs an HTTP request and returns the response with body
func DoRequest(client *http.Client, targetURL string, opts models.ScanOptions) (*http.Response, string, error) {
	method := opts.Method
	if method == "" {
		method = "GET"
	}

	req, err := http.NewRequest(method, targetURL, nil)
	if err != nil {
		return nil, "", err
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
		return nil, "", err
	}

	body, _ := io.ReadAll(resp.Body)
	return resp, string(body), nil
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
