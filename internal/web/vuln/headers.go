package vuln

import (
	"fmt"
	"net/http"
	"strings"
)

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
