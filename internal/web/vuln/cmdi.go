package vuln

import (
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"raxuiscli/internal/shared/payloads"
)

// TestCommandInjection tests for command injection vulnerabilities
func TestCommandInjection(opts ScanOptions, resultChan chan<- VulnResult) {
	cmdPayloads := payloads.GetCmdInjPayloads(opts.PayloadLevel)

	client := createClient(opts)
	parsedURL, err := url.Parse(opts.URL)
	if err != nil {
		return
	}

	params := parsedURL.Query()
	sem := make(chan struct{}, opts.Threads)
	var wg sync.WaitGroup

	for param := range params {
		for _, payload := range cmdPayloads {
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
				if matched, pattern := payloads.MatchesCmdOutput(body); matched {
					resultChan <- VulnResult{
						Type:        VulnCmdInj,
						Severity:    SeverityCritical,
						URL:         testURL,
						Parameter:   p,
						Payload:     pay,
						Evidence:    fmt.Sprintf("Command output detected: %s", pattern),
						Description: "Command Injection vulnerability detected. The application executes arbitrary system commands.",
						Remediation: "Never pass user input directly to system commands. Use allowlists for permitted commands. Implement strict input validation.",
					}
					return
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
