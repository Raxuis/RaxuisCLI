package vuln

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/Raxuis/RaxuisCLI/internal/shared/payloads"
)

// TestCORS tests for CORS misconfiguration vulnerabilities
func TestCORS(opts CORSOptions, resultChan chan<- VulnResult) {
	client := createClient(opts.ScanOptions)

	// Extract target domain for dynamic payloads
	parsedURL, err := url.Parse(opts.URL)
	if err != nil {
		return
	}
	targetDomain := parsedURL.Hostname()

	origins := payloads.GetCORSTestOrigins(targetDomain)
	if opts.TestOrigin != "" {
		origins = []string{opts.TestOrigin}
	}

	for _, testOrigin := range origins {
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
			req, err := http.NewRequest("GET", opts.URL, nil)
			if err != nil {
				continue
			}
			req.Header.Set("Origin", origin)

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

			if allowOrigin != "" && (allowOrigin == "*" || allowOrigin == origin) {
				resultChan <- VulnResult{
					Type:        VulnCORS,
					Severity:    SeverityMedium,
					URL:         opts.URL,
					Parameter:   "GET Request CORS",
					Payload:     origin,
					Evidence:    fmt.Sprintf("Allow-Origin: %s, Allow-Credentials: %s", allowOrigin, allowCreds),
					Description: "CORS headers present on GET request, not just preflight.",
					Remediation: "Review CORS configuration for all request types.",
				}
				break
			}
		}
	}
}
