package http

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// RequestOptions holds HTTP request configuration
type RequestOptions struct {
	Method      string
	URL         string
	Headers     map[string]string
	Body        string
	Timeout     int
	FollowRedir bool
	Insecure    bool
	Proxy       string
	UserAgent   string
	Cookie      string
	BasicAuth   string
}

// Response holds HTTP response data
type Response struct {
	StatusCode    int
	Status        string
	Headers       http.Header
	Body          string
	ContentLength int64
	Duration      time.Duration
	RedirectChain []string
	TLS           *TLSInfo
}

// TLSInfo holds TLS connection information
type TLSInfo struct {
	Version     string
	CipherSuite string
	ServerName  string
}

// SecurityHeader represents a security header check
type SecurityHeader struct {
	Name        string
	Value       string
	Present     bool
	Secure      bool
	Description string
	Severity    string
}

// HeaderAnalysis holds security header analysis results
type HeaderAnalysis struct {
	Headers  []SecurityHeader
	Score    int
	MaxScore int
	Grade    string
	Warnings []string
	Missing  []string
}

// DoRequest performs an HTTP request
func DoRequest(opts RequestOptions) (*Response, error) {
	if opts.Method == "" {
		opts.Method = "GET"
	}
	if opts.Timeout == 0 {
		opts.Timeout = 10
	}
	if opts.UserAgent == "" {
		opts.UserAgent = "RaxuisCLI/1.0"
	}

	// Create HTTP client
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: opts.Insecure,
		},
	}

	if opts.Proxy != "" {
		proxyURL, err := url.Parse(opts.Proxy)
		if err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(opts.Timeout) * time.Second,
	}

	// Track redirects
	var redirectChain []string
	if !opts.FollowRedir {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			redirectChain = append(redirectChain, req.URL.String())
			return http.ErrUseLastResponse
		}
	} else {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			redirectChain = append(redirectChain, req.URL.String())
			if len(via) >= 10 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		}
	}

	// Create request
	var bodyReader io.Reader
	if opts.Body != "" {
		bodyReader = strings.NewReader(opts.Body)
	}

	req, err := http.NewRequest(opts.Method, opts.URL, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	// Set headers
	req.Header.Set("User-Agent", opts.UserAgent)

	for key, value := range opts.Headers {
		req.Header.Set(key, value)
	}

	if opts.Cookie != "" {
		req.Header.Set("Cookie", opts.Cookie)
	}

	if opts.BasicAuth != "" {
		parts := strings.SplitN(opts.BasicAuth, ":", 2)
		if len(parts) == 2 {
			req.SetBasicAuth(parts[0], parts[1])
		}
	}

	// Auto-detect content type for body
	if opts.Body != "" && req.Header.Get("Content-Type") == "" {
		if strings.HasPrefix(strings.TrimSpace(opts.Body), "{") {
			req.Header.Set("Content-Type", "application/json")
		} else if strings.Contains(opts.Body, "=") {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	}

	// Perform request
	start := time.Now()
	resp, err := client.Do(req)
	duration := time.Since(start)

	if err != nil {
		return nil, fmt.Errorf("request failed: %v", err)
	}
	defer resp.Body.Close()

	// Read body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %v", err)
	}

	response := &Response{
		StatusCode:    resp.StatusCode,
		Status:        resp.Status,
		Headers:       resp.Header,
		Body:          string(body),
		ContentLength: resp.ContentLength,
		Duration:      duration,
		RedirectChain: redirectChain,
	}

	// TLS info
	if resp.TLS != nil {
		response.TLS = &TLSInfo{
			Version:     tlsVersionString(resp.TLS.Version),
			CipherSuite: tls.CipherSuiteName(resp.TLS.CipherSuite),
			ServerName:  resp.TLS.ServerName,
		}
	}

	return response, nil
}

// tlsVersionString converts TLS version to string
func tlsVersionString(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (0x%04x)", version)
	}
}

// AnalyzeSecurityHeaders analyzes response headers for security issues
func AnalyzeSecurityHeaders(headers http.Header) *HeaderAnalysis {
	analysis := &HeaderAnalysis{
		MaxScore: 100,
	}

	// Security headers to check
	checks := []struct {
		Name        string
		Required    bool
		Weight      int
		CheckFunc   func(string) (bool, string)
		Description string
	}{
		{
			Name:        "Strict-Transport-Security",
			Required:    true,
			Weight:      15,
			Description: "Enforces HTTPS connections",
			CheckFunc: func(v string) (bool, string) {
				if v == "" {
					return false, "Missing HSTS header"
				}
				if !strings.Contains(v, "max-age=") {
					return false, "HSTS missing max-age"
				}
				return true, "HSTS properly configured"
			},
		},
		{
			Name:        "Content-Security-Policy",
			Required:    true,
			Weight:      20,
			Description: "Prevents XSS and injection attacks",
			CheckFunc: func(v string) (bool, string) {
				if v == "" {
					return false, "Missing CSP header"
				}
				if strings.Contains(v, "unsafe-inline") {
					return false, "CSP allows unsafe-inline"
				}
				if strings.Contains(v, "unsafe-eval") {
					return false, "CSP allows unsafe-eval"
				}
				return true, "CSP configured"
			},
		},
		{
			Name:        "X-Content-Type-Options",
			Required:    true,
			Weight:      10,
			Description: "Prevents MIME type sniffing",
			CheckFunc: func(v string) (bool, string) {
				if v == "" {
					return false, "Missing X-Content-Type-Options"
				}
				if v != "nosniff" {
					return false, "X-Content-Type-Options should be 'nosniff'"
				}
				return true, "Properly set to nosniff"
			},
		},
		{
			Name:        "X-Frame-Options",
			Required:    true,
			Weight:      10,
			Description: "Prevents clickjacking attacks",
			CheckFunc: func(v string) (bool, string) {
				if v == "" {
					return false, "Missing X-Frame-Options"
				}
				v = strings.ToUpper(v)
				if v != "DENY" && v != "SAMEORIGIN" {
					return false, "X-Frame-Options should be DENY or SAMEORIGIN"
				}
				return true, "Clickjacking protection enabled"
			},
		},
		{
			Name:        "X-XSS-Protection",
			Required:    false,
			Weight:      5,
			Description: "Legacy XSS protection (deprecated)",
			CheckFunc: func(v string) (bool, string) {
				if v == "" {
					return true, "Not set (deprecated header)"
				}
				if strings.Contains(v, "1") && strings.Contains(v, "mode=block") {
					return true, "Legacy XSS protection enabled"
				}
				return true, "Present"
			},
		},
		{
			Name:        "Referrer-Policy",
			Required:    true,
			Weight:      10,
			Description: "Controls referrer information",
			CheckFunc: func(v string) (bool, string) {
				if v == "" {
					return false, "Missing Referrer-Policy"
				}
				secure := []string{"no-referrer", "strict-origin", "strict-origin-when-cross-origin", "same-origin"}
				for _, s := range secure {
					if strings.Contains(v, s) {
						return true, "Secure referrer policy"
					}
				}
				return false, "Potentially insecure referrer policy"
			},
		},
		{
			Name:        "Permissions-Policy",
			Required:    false,
			Weight:      10,
			Description: "Controls browser features",
			CheckFunc: func(v string) (bool, string) {
				if v == "" {
					return false, "Missing Permissions-Policy"
				}
				return true, "Feature policy configured"
			},
		},
		{
			Name:        "X-Permitted-Cross-Domain-Policies",
			Required:    false,
			Weight:      5,
			Description: "Controls cross-domain policies",
			CheckFunc: func(v string) (bool, string) {
				if v == "" {
					return true, "Not set"
				}
				if v == "none" {
					return true, "Cross-domain policies disabled"
				}
				return true, "Present"
			},
		},
		{
			Name:        "Cache-Control",
			Required:    false,
			Weight:      5,
			Description: "Controls caching behavior",
			CheckFunc: func(v string) (bool, string) {
				if v == "" {
					return false, "No cache control"
				}
				if strings.Contains(v, "no-store") || strings.Contains(v, "private") {
					return true, "Sensitive caching controls"
				}
				return true, "Cache control present"
			},
		},
		{
			Name:        "Server",
			Required:    false,
			Weight:      10,
			Description: "Server identification (should be hidden)",
			CheckFunc: func(v string) (bool, string) {
				if v == "" {
					return true, "Server header hidden"
				}
				return false, fmt.Sprintf("Server exposed: %s", v)
			},
		},
	}

	score := 0
	for _, check := range checks {
		value := headers.Get(check.Name)
		secure, desc := check.CheckFunc(value)

		severity := "INFO"
		if check.Required && !secure {
			severity = "MEDIUM"
			analysis.Missing = append(analysis.Missing, check.Name)
		}
		if !secure && value != "" {
			severity = "LOW"
			analysis.Warnings = append(analysis.Warnings, desc)
		}

		if secure {
			score += check.Weight
		}

		analysis.Headers = append(analysis.Headers, SecurityHeader{
			Name:        check.Name,
			Value:       value,
			Present:     value != "",
			Secure:      secure,
			Description: desc,
			Severity:    severity,
		})
	}

	analysis.Score = score

	// Calculate grade
	switch {
	case score >= 90:
		analysis.Grade = "A"
	case score >= 80:
		analysis.Grade = "B"
	case score >= 70:
		analysis.Grade = "C"
	case score >= 60:
		analysis.Grade = "D"
	default:
		analysis.Grade = "F"
	}

	return analysis
}

// GenerateCurl generates a curl command from request options
func GenerateCurl(opts RequestOptions) string {
	parts := []string{"curl"}

	if opts.Method != "GET" {
		parts = append(parts, "-X", opts.Method)
	}

	if opts.Insecure {
		parts = append(parts, "-k")
	}

	if !opts.FollowRedir {
		parts = append(parts, "-L")
	}

	for key, value := range opts.Headers {
		parts = append(parts, "-H", fmt.Sprintf("'%s: %s'", key, value))
	}

	if opts.UserAgent != "" && opts.UserAgent != "RaxuisCLI/1.0" {
		parts = append(parts, "-A", fmt.Sprintf("'%s'", opts.UserAgent))
	}

	if opts.Cookie != "" {
		parts = append(parts, "-b", fmt.Sprintf("'%s'", opts.Cookie))
	}

	if opts.BasicAuth != "" {
		parts = append(parts, "-u", fmt.Sprintf("'%s'", opts.BasicAuth))
	}

	if opts.Body != "" {
		parts = append(parts, "-d", fmt.Sprintf("'%s'", opts.Body))
	}

	if opts.Proxy != "" {
		parts = append(parts, "-x", opts.Proxy)
	}

	parts = append(parts, fmt.Sprintf("'%s'", opts.URL))

	return strings.Join(parts, " ")
}

// DetectTechnology attempts to detect technologies from headers
func DetectTechnology(headers http.Header, body string) []string {
	var techs []string

	// Check headers
	headerChecks := map[string]map[string]string{
		"Server": {
			"nginx":      "Nginx",
			"apache":     "Apache",
			"iis":        "Microsoft IIS",
			"cloudflare": "Cloudflare",
			"gunicorn":   "Gunicorn (Python)",
		},
		"X-Powered-By": {
			"php":     "PHP",
			"asp.net": "ASP.NET",
			"express": "Express.js",
			"next.js": "Next.js",
			"servlet": "Java Servlet",
		},
		"X-Generator": {
			"wordpress": "WordPress",
			"drupal":    "Drupal",
			"joomla":    "Joomla",
		},
	}

	for header, checks := range headerChecks {
		value := strings.ToLower(headers.Get(header))
		for pattern, tech := range checks {
			if strings.Contains(value, pattern) {
				techs = append(techs, tech)
			}
		}
	}

	// Check body for common patterns
	bodyLower := strings.ToLower(body)
	bodyChecks := map[string]string{
		"wp-content":  "WordPress",
		"wp-includes": "WordPress",
		"/drupal":     "Drupal",
		"joomla":      "Joomla",
		"react":       "React",
		"vue.js":      "Vue.js",
		"angular":     "Angular",
		"jquery":      "jQuery",
		"bootstrap":   "Bootstrap",
		"laravel":     "Laravel",
		"django":      "Django",
		"rails":       "Ruby on Rails",
		"__next":      "Next.js",
		"_nuxt":       "Nuxt.js",
	}

	for pattern, tech := range bodyChecks {
		if strings.Contains(bodyLower, pattern) {
			// Avoid duplicates
			found := false
			for _, t := range techs {
				if t == tech {
					found = true
					break
				}
			}
			if !found {
				techs = append(techs, tech)
			}
		}
	}

	return techs
}

// DisplayResponse displays HTTP response
func DisplayResponse(resp *Response, showBody bool, maxBodyLen int) {
	fmt.Println("\n[HTTP RESPONSE]")
	fmt.Println(strings.Repeat("=", 60))

	// Status
	fmt.Printf("\nStatus: %s\n", resp.Status)
	fmt.Printf("Duration: %v\n", resp.Duration)

	if resp.ContentLength > 0 {
		fmt.Printf("Content-Length: %d bytes\n", resp.ContentLength)
	}

	// TLS info
	if resp.TLS != nil {
		fmt.Printf("\n[TLS]\n")
		fmt.Printf("Version: %s\n", resp.TLS.Version)
		fmt.Printf("Cipher: %s\n", resp.TLS.CipherSuite)
	}

	// Redirects
	if len(resp.RedirectChain) > 0 {
		fmt.Printf("\n[Redirect Chain]\n")
		for i, url := range resp.RedirectChain {
			fmt.Printf("  %d. %s\n", i+1, url)
		}
	}

	// Headers
	fmt.Printf("\n[Headers]\n")
	keys := make([]string, 0, len(resp.Headers))
	for k := range resp.Headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		for _, v := range resp.Headers[k] {
			fmt.Printf("  %s: %s\n", k, v)
		}
	}

	// Body
	if showBody && resp.Body != "" {
		fmt.Printf("\n[Body]\n")
		body := resp.Body
		if maxBodyLen > 0 && len(body) > maxBodyLen {
			body = body[:maxBodyLen] + "\n... (truncated)"
		}
		fmt.Println(body)
	}
}

// DisplayHeaderAnalysis displays security header analysis
func DisplayHeaderAnalysis(analysis *HeaderAnalysis) {
	fmt.Println("\n[SECURITY HEADERS ANALYSIS]")
	fmt.Println(strings.Repeat("=", 60))

	fmt.Printf("\nSecurity Score: %d/%d (Grade: %s)\n", analysis.Score, analysis.MaxScore, analysis.Grade)

	fmt.Printf("\n%-35s %-10s %s\n", "HEADER", "STATUS", "DETAILS")
	fmt.Println(strings.Repeat("-", 60))

	for _, h := range analysis.Headers {
		status := "OK"
		if !h.Secure {
			status = h.Severity
		}
		if !h.Present && h.Severity == "MEDIUM" {
			status = "MISSING"
		}

		fmt.Printf("%-35s %-10s %s\n", h.Name, status, h.Description)
	}

	if len(analysis.Missing) > 0 {
		fmt.Printf("\n[Missing Headers]\n")
		for _, h := range analysis.Missing {
			fmt.Printf("  - %s\n", h)
		}
	}

	if len(analysis.Warnings) > 0 {
		fmt.Printf("\n[Warnings]\n")
		for _, w := range analysis.Warnings {
			fmt.Printf("  - %s\n", w)
		}
	}

	fmt.Println()
}

// DisplayTechnologies displays detected technologies
func DisplayTechnologies(techs []string) {
	if len(techs) == 0 {
		return
	}

	fmt.Println("\n[DETECTED TECHNOLOGIES]")
	fmt.Println(strings.Repeat("=", 60))

	for _, tech := range techs {
		fmt.Printf("  - %s\n", tech)
	}
	fmt.Println()
}

// FormatJSON formats JSON body for display
func FormatJSON(body string) string {
	var data interface{}
	if err := json.Unmarshal([]byte(body), &data); err != nil {
		return body
	}
	formatted, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return body
	}
	return string(formatted)
}
