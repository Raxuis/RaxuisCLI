package vuln

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/Raxuis/RaxuisCLI/internal/shared/payloads"
)

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
	redirectPayloads := payloads.GetOpenRedirectPayloads()

	for param := range params {
		// Check if this looks like a redirect parameter
		isRedirectParam := payloads.IsRedirectParam(param)

		for _, payload := range redirectPayloads {
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
