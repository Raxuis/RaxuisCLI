package vuln

import (
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"raxuiscli/internal/shared/payloads"
)

// TestSQLi tests for SQL injection vulnerabilities
func TestSQLi(opts ScanOptions, resultChan chan<- VulnResult) {
	sqliPayloads := payloads.GetSQLiPayloads(opts.PayloadLevel)

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
		for _, payload := range sqliPayloads {
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
				if matched, pattern := payloads.MatchesSQLError(body); matched {
					resultChan <- VulnResult{
						Type:        VulnSQLi,
						Severity:    SeverityCritical,
						URL:         testURL,
						Parameter:   p,
						Payload:     pay,
						Evidence:    fmt.Sprintf("SQL error detected: %s", pattern),
						Description: "Error-based SQL Injection vulnerability detected. The application reveals SQL errors in responses.",
						Remediation: "Use parameterized queries. Implement proper error handling. Never expose database errors.",
					}
					return
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
