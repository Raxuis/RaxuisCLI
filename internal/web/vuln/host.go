package vuln

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/Raxuis/RaxuisCLI/internal/shared/payloads"
)

// TestHostHeader tests for host header injection vulnerabilities
func TestHostHeader(opts HostHeaderOptions, resultChan chan<- VulnResult) {
	client := createClient(opts.ScanOptions)

	parsedURL, err := url.Parse(opts.URL)
	if err != nil {
		return
	}
	originalHost := parsedURL.Host

	for _, payload := range payloads.HostHeaderPayloads {
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
		for _, endpoint := range payloads.PasswordResetEndpoints {
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
