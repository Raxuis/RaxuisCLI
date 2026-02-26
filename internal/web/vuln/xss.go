package vuln

import (
	"net/url"
	"strings"
	"sync"

	"raxuiscli/internal/shared/payloads"
)

// TestXSS tests for XSS vulnerabilities
func TestXSS(opts ScanOptions, resultChan chan<- VulnResult) {
	xssPayloads := payloads.GetXSSPayloads(opts.PayloadLevel)

	client := createClient(opts)
	parsedURL, err := url.Parse(opts.URL)
	if err != nil {
		return
	}

	params := parsedURL.Query()
	sem := make(chan struct{}, opts.Threads)
	var wg sync.WaitGroup

	for param := range params {
		for _, payload := range xssPayloads {
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
