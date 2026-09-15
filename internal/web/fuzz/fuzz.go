package fuzz

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// FuzzType represents the type of fuzzing
type FuzzType string

const (
	FuzzDir   FuzzType = "dir"
	FuzzParam FuzzType = "param"
	FuzzVhost FuzzType = "vhost"
)

// FuzzOptions holds fuzzing configuration
type FuzzOptions struct {
	Type         FuzzType
	URL          string
	Wordlist     string
	Words        []string
	Threads      int
	Timeout      int
	UserAgent    string
	Cookie       string
	Headers      map[string]string
	Extensions   []string
	FilterStatus []int
	FilterSize   []int
	FilterWords  []int
	MatchStatus  []int
	MatchSize    []int
	FollowRedir  bool
	Insecure     bool
	RateLimit    int // requests per second
	Recursive    bool
	MaxDepth     int
	Method       string
	Data         string
}

// FuzzResult holds a single fuzzing result
type FuzzResult struct {
	Input         string
	URL           string
	StatusCode    int
	ContentLength int64
	WordCount     int
	LineCount     int
	Duration      time.Duration
	Redirect      string
	Error         error
}

// FuzzResults holds all fuzzing results
type FuzzResults struct {
	Type     FuzzType
	BaseURL  string
	Total    int
	Found    int
	Errors   int
	Duration time.Duration
	Results  []FuzzResult
}

// LoadWordlist loads words from a file
func LoadWordlist(filepath string) ([]string, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to open wordlist: %v", err)
	}
	defer file.Close()

	var words []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		word := strings.TrimSpace(scanner.Text())
		if word != "" && !strings.HasPrefix(word, "#") {
			words = append(words, word)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading wordlist: %v", err)
	}

	return words, nil
}

// CommonDirectories returns common directories to fuzz
func CommonDirectories() []string {
	return []string{
		"admin", "administrator", "login", "wp-admin", "wp-login.php",
		"admin.php", "administrator.php", "phpmyadmin", "pma",
		"backup", "backups", "bak", "old", "temp", "tmp",
		"test", "testing", "dev", "development", "staging",
		"api", "api/v1", "api/v2", "rest", "graphql",
		"uploads", "upload", "files", "images", "img", "static", "assets",
		"includes", "inc", "lib", "libs", "vendor", "node_modules",
		"config", "conf", "configuration", "settings",
		"database", "db", "sql", "mysql", "data",
		"logs", "log", "debug", "error", "errors",
		"private", "secret", "hidden", ".git", ".svn", ".env",
		"cgi-bin", "scripts", "bin", "shell",
		"dashboard", "panel", "console", "portal",
		"user", "users", "account", "accounts", "profile",
		"docs", "documentation", "help", "readme",
		"robots.txt", "sitemap.xml", ".htaccess", "web.config",
		"server-status", "server-info", "phpinfo.php", "info.php",
	}
}

// CommonParams returns common parameters to fuzz
func CommonParams() []string {
	return []string{
		"id", "page", "file", "path", "dir", "search", "q", "query",
		"url", "uri", "redirect", "return", "next", "goto", "target",
		"user", "username", "name", "email", "pass", "password",
		"admin", "debug", "test", "cmd", "exec", "command",
		"cat", "action", "do", "module", "view", "type",
		"sort", "order", "limit", "offset", "start", "count",
		"callback", "jsonp", "format", "output", "lang", "locale",
		"token", "key", "api_key", "apikey", "secret", "auth",
		"include", "require", "template", "tpl", "theme",
		"load", "read", "fetch", "get", "data",
	}
}

// FuzzDirectory performs directory fuzzing
func FuzzDirectory(opts FuzzOptions, resultChan chan<- FuzzResult, doneChan chan<- bool) {
	defer func() { doneChan <- true }()

	client := createHTTPClient(opts)

	// Rate limiter
	var limiter <-chan time.Time
	if opts.RateLimit > 0 {
		limiter = time.Tick(time.Second / time.Duration(opts.RateLimit))
	}

	// Semaphore for concurrent requests
	sem := make(chan struct{}, opts.Threads)

	var wg sync.WaitGroup

	baseURL := strings.TrimSuffix(opts.URL, "/")

	for _, word := range opts.Words {
		if opts.RateLimit > 0 {
			<-limiter
		}

		// With extensions
		paths := []string{word}
		for _, ext := range opts.Extensions {
			paths = append(paths, word+"."+ext)
		}

		for _, path := range paths {
			wg.Add(1)
			sem <- struct{}{}

			go func(p string) {
				defer wg.Done()
				defer func() { <-sem }()

				targetURL := baseURL + "/" + p
				result := doFuzzRequest(client, targetURL, opts)
				result.Input = p

				// Apply filters
				if shouldIncludeResult(result, opts) {
					resultChan <- result
				}
			}(path)
		}
	}

	wg.Wait()
}

// FuzzParameter performs parameter fuzzing
func FuzzParameter(opts FuzzOptions, resultChan chan<- FuzzResult, doneChan chan<- bool) {
	defer func() { doneChan <- true }()

	client := createHTTPClient(opts)

	var limiter <-chan time.Time
	if opts.RateLimit > 0 {
		limiter = time.Tick(time.Second / time.Duration(opts.RateLimit))
	}

	sem := make(chan struct{}, opts.Threads)
	var wg sync.WaitGroup

	// Parse base URL
	parsedURL, err := url.Parse(opts.URL)
	if err != nil {
		resultChan <- FuzzResult{Error: err}
		return
	}

	baseQuery := parsedURL.Query()

	for _, word := range opts.Words {
		if opts.RateLimit > 0 {
			<-limiter
		}

		wg.Add(1)
		sem <- struct{}{}

		go func(param string) {
			defer wg.Done()
			defer func() { <-sem }()

			// Copy the URL so concurrent goroutines don't race on the shared parsedURL.
			testURL := *parsedURL

			// Add parameter to URL
			query := url.Values{}
			for k, v := range baseQuery {
				query[k] = v
			}
			query.Set(param, "FUZZ")

			testURL.RawQuery = query.Encode()
			targetURL := testURL.String()

			result := doFuzzRequest(client, targetURL, opts)
			result.Input = param

			if shouldIncludeResult(result, opts) {
				resultChan <- result
			}
		}(word)
	}

	wg.Wait()
}

// FuzzVirtualHost performs virtual host fuzzing
func FuzzVirtualHost(opts FuzzOptions, resultChan chan<- FuzzResult, doneChan chan<- bool) {
	defer func() { doneChan <- true }()

	client := createHTTPClient(opts)

	var limiter <-chan time.Time
	if opts.RateLimit > 0 {
		limiter = time.Tick(time.Second / time.Duration(opts.RateLimit))
	}

	sem := make(chan struct{}, opts.Threads)
	var wg sync.WaitGroup

	// Get baseline response
	baselineResult := doFuzzRequest(client, opts.URL, opts)

	for _, word := range opts.Words {
		if opts.RateLimit > 0 {
			<-limiter
		}

		wg.Add(1)
		sem <- struct{}{}

		go func(vhost string) {
			defer wg.Done()
			defer func() { <-sem }()

			// Set Host header
			vhostOpts := opts
			if vhostOpts.Headers == nil {
				vhostOpts.Headers = make(map[string]string)
			}
			vhostOpts.Headers["Host"] = vhost

			result := doFuzzRequest(client, opts.URL, vhostOpts)
			result.Input = vhost

			// Compare with baseline
			if result.StatusCode != baselineResult.StatusCode ||
				result.ContentLength != baselineResult.ContentLength {
				if shouldIncludeResult(result, opts) {
					resultChan <- result
				}
			}
		}(word)
	}

	wg.Wait()
}

// createHTTPClient creates an HTTP client for fuzzing
func createHTTPClient(opts FuzzOptions) *http.Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: opts.Insecure,
		},
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: opts.Threads,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(opts.Timeout) * time.Second,
	}

	if !opts.FollowRedir {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	return client
}

// doFuzzRequest performs a single fuzz request
func doFuzzRequest(client *http.Client, targetURL string, opts FuzzOptions) FuzzResult {
	result := FuzzResult{
		URL: targetURL,
	}

	method := opts.Method
	if method == "" {
		method = "GET"
	}

	var body io.Reader
	if opts.Data != "" {
		body = strings.NewReader(opts.Data)
	}

	req, err := http.NewRequest(method, targetURL, body)
	if err != nil {
		result.Error = err
		return result
	}

	// Set headers
	if opts.UserAgent != "" {
		req.Header.Set("User-Agent", opts.UserAgent)
	} else {
		req.Header.Set("User-Agent", "RaxuisCLI-Fuzzer/1.0")
	}

	if opts.Cookie != "" {
		req.Header.Set("Cookie", opts.Cookie)
	}

	for key, value := range opts.Headers {
		// net/http sends the wire Host header from req.Host (falling back to
		// the URL's host), never from req.Header - Header.Set("Host", ...)
		// alone is silently ignored by the transport. Without this, vhost
		// fuzzing (FuzzVirtualHost) never actually varied the Host header it
		// was probing with.
		if strings.EqualFold(key, "Host") {
			req.Host = value
			continue
		}
		req.Header.Set(key, value)
	}

	start := time.Now()
	resp, err := client.Do(req)
	result.Duration = time.Since(start)

	if err != nil {
		result.Error = err
		return result
	}
	defer resp.Body.Close()

	result.StatusCode = resp.StatusCode
	result.ContentLength = resp.ContentLength

	// Read body for word/line count
	bodyBytes, _ := io.ReadAll(resp.Body)
	bodyStr := string(bodyBytes)
	result.WordCount = len(strings.Fields(bodyStr))
	result.LineCount = len(strings.Split(bodyStr, "\n"))

	if result.ContentLength < 0 {
		result.ContentLength = int64(len(bodyBytes))
	}

	// Check for redirect
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		result.Redirect = resp.Header.Get("Location")
	}

	return result
}

// shouldIncludeResult checks if result should be included based on filters
func shouldIncludeResult(result FuzzResult, opts FuzzOptions) bool {
	if result.Error != nil {
		return false
	}

	// Match filters (whitelist)
	if len(opts.MatchStatus) > 0 {
		found := false
		for _, s := range opts.MatchStatus {
			if result.StatusCode == s {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Filter status (blacklist)
	for _, s := range opts.FilterStatus {
		if result.StatusCode == s {
			return false
		}
	}

	// Filter size
	for _, s := range opts.FilterSize {
		if int(result.ContentLength) == s {
			return false
		}
	}

	// Filter words
	for _, w := range opts.FilterWords {
		if result.WordCount == w {
			return false
		}
	}

	// Default: show 2xx and 3xx responses
	if len(opts.MatchStatus) == 0 && len(opts.FilterStatus) == 0 {
		if result.StatusCode >= 400 {
			return false
		}
	}

	return true
}

// DisplayResults displays fuzzing results
func DisplayResults(results *FuzzResults) {
	fmt.Fprintf(stdoutW, "\n[FUZZING RESULTS - %s]\n", strings.ToUpper(string(results.Type)))
	fmt.Fprintln(stdoutW, strings.Repeat("=", 70))

	fmt.Fprintf(stdoutW, "Target: %s\n", results.BaseURL)
	fmt.Fprintf(stdoutW, "Total requests: %d\n", results.Total)
	fmt.Fprintf(stdoutW, "Found: %d\n", results.Found)
	fmt.Fprintf(stdoutW, "Errors: %d\n", results.Errors)
	fmt.Fprintf(stdoutW, "Duration: %v\n", results.Duration)

	if len(results.Results) == 0 {
		fmt.Fprintln(stdoutW, "\nNo results found")
		return
	}

	// Sort by status code
	sort.Slice(results.Results, func(i, j int) bool {
		return results.Results[i].StatusCode < results.Results[j].StatusCode
	})

	fmt.Fprintf(stdoutW, "\n%-40s %-6s %-10s %-8s %s\n", "PATH/INPUT", "STATUS", "SIZE", "WORDS", "REDIRECT")
	fmt.Fprintln(stdoutW, strings.Repeat("-", 70))

	for _, r := range results.Results {
		input := r.Input
		if len(input) > 38 {
			input = input[:35] + "..."
		}

		redirect := ""
		if r.Redirect != "" {
			redirect = "-> " + r.Redirect
			if len(redirect) > 30 {
				redirect = redirect[:27] + "..."
			}
		}

		fmt.Fprintf(stdoutW, "%-40s %-6d %-10d %-8d %s\n",
			input,
			r.StatusCode,
			r.ContentLength,
			r.WordCount,
			redirect,
		)
	}

	fmt.Fprintln(stdoutW)
}

// DisplayProgress displays fuzzing progress
func DisplayProgress(current, total int, found int, rate float64) {
	percent := float64(current) / float64(total) * 100
	fmt.Fprintf(stdoutW, "\r[%d/%d] %.1f%% | Found: %d | Rate: %.1f req/s",
		current, total, percent, found, rate)
}
