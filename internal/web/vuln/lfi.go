package vuln

import (
	"fmt"
	"net/url"
	"sync"

	"raxuiscli/internal/shared/payloads"
)

// TestLFI tests for Local File Inclusion vulnerabilities
func TestLFI(opts ScanOptions, resultChan chan<- VulnResult) {
	lfiPayloads := payloads.GetLFIPayloads(opts.PayloadLevel)

	client := createClient(opts)
	parsedURL, err := url.Parse(opts.URL)
	if err != nil {
		return
	}

	params := parsedURL.Query()
	sem := make(chan struct{}, opts.Threads)
	var wg sync.WaitGroup

	for param := range params {
		for _, payload := range lfiPayloads {
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
				if matched, pattern := payloads.MatchesLFISuccess(body); matched {
					resultChan <- VulnResult{
						Type:        VulnLFI,
						Severity:    SeverityCritical,
						URL:         testURL,
						Parameter:   p,
						Payload:     pay,
						Evidence:    fmt.Sprintf("Pattern matched: %s", pattern),
						Description: "Local File Inclusion vulnerability detected. The application allows reading arbitrary files from the server.",
						Remediation: "Validate file paths strictly. Use allowlists for permitted files. Disable dangerous PHP wrappers.",
					}
					return
				}
			}(param, payload)
		}
	}

	wg.Wait()
}
