package vuln

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"raxuiscli/internal/shared/payloads"
)

// TestNoSQLi tests for NoSQL injection vulnerabilities
func TestNoSQLi(opts NoSQLiOptions, resultChan chan<- VulnResult) {
	nosqliPayloads := payloads.GetNoSQLiPayloads(opts.PayloadLevel)

	client := createClient(opts.ScanOptions)
	parsedURL, err := url.Parse(opts.URL)
	if err != nil {
		return
	}

	// Test URL parameters
	params := parsedURL.Query()
	for param := range params {
		for _, payload := range nosqliPayloads {
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
			for _, errPattern := range payloads.NoSQLErrorPatterns {
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
		for _, payload := range nosqliPayloads {
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
			for _, indicator := range payloads.AuthBypassIndicators {
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

// Helper to inject NoSQL payload into JSON
func injectNoSQLPayload(jsonData, payload string) string {
	// Simple injection: replace string values with payload
	if strings.Contains(jsonData, `":"`) {
		re := regexp.MustCompile(`":\s*"[^"]*"`)
		return re.ReplaceAllStringFunc(jsonData, func(match string) string {
			return `": ` + payload
		})
	}
	return ""
}
