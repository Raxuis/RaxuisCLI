package vuln

import (
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

// TestRaceCondition tests for race condition vulnerabilities
func TestRaceCondition(opts RaceOptions, resultChan chan<- VulnResult) {
	if opts.Requests <= 0 {
		opts.Requests = 10
	}

	client := createClient(opts.ScanOptions)
	client.Timeout = time.Duration(opts.Timeout) * time.Second

	method := opts.Method
	if method == "" {
		method = "POST"
	}

	// Prepare all requests upfront
	var requests []*http.Request
	for i := 0; i < opts.Requests; i++ {
		var body io.Reader
		if opts.Data != "" {
			body = strings.NewReader(opts.Data)
		}

		req, err := http.NewRequest(method, opts.URL, body)
		if err != nil {
			continue
		}

		if opts.UserAgent != "" {
			req.Header.Set("User-Agent", opts.UserAgent)
		} else {
			req.Header.Set("User-Agent", "RaxuisCLI-RaceTest/1.0")
		}

		if opts.Cookie != "" {
			req.Header.Set("Cookie", opts.Cookie)
		}

		for key, value := range opts.Headers {
			req.Header.Set(key, value)
		}

		if opts.Data != "" {
			if strings.HasPrefix(opts.Data, "{") {
				req.Header.Set("Content-Type", "application/json")
			} else {
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			}
		}

		requests = append(requests, req)
	}

	// Results collection
	type response struct {
		StatusCode int
		Body       string
		Duration   time.Duration
		Error      error
	}

	responses := make([]response, len(requests))
	var wg sync.WaitGroup

	// Fire all requests simultaneously
	startBarrier := make(chan struct{})

	for i, req := range requests {
		wg.Add(1)
		go func(idx int, r *http.Request) {
			defer wg.Done()

			// Wait for start signal
			<-startBarrier

			start := time.Now()

			// Clone request body for each attempt
			var body io.Reader
			if opts.Data != "" {
				body = strings.NewReader(opts.Data)
			}
			newReq, _ := http.NewRequest(r.Method, r.URL.String(), body)
			newReq.Header = r.Header.Clone()

			resp, err := client.Do(newReq)
			elapsed := time.Since(start)

			if err != nil {
				responses[idx] = response{Error: err, Duration: elapsed}
				return
			}

			bodyBytes, _ := io.ReadAll(resp.Body)
			resp.Body.Close()

			responses[idx] = response{
				StatusCode: resp.StatusCode,
				Body:       string(bodyBytes),
				Duration:   elapsed,
			}
		}(i, req)
	}

	// Release all goroutines at once
	close(startBarrier)
	wg.Wait()

	// Analyze results
	statusCodes := make(map[int]int)
	successCount := 0
	var bodies []string
	var durations []time.Duration

	for _, resp := range responses {
		if resp.Error != nil {
			continue
		}
		statusCodes[resp.StatusCode]++
		durations = append(durations, resp.Duration)

		// Count successful operations
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			successCount++
			bodies = append(bodies, resp.Body)
		}
	}

	// Check for race condition indicators
	// 1. Multiple successes when only one should occur
	if successCount > 1 {
		resultChan <- VulnResult{
			Type:        VulnRace,
			Severity:    SeverityHigh,
			URL:         opts.URL,
			Parameter:   fmt.Sprintf("%d concurrent requests", opts.Requests),
			Payload:     opts.Data,
			Evidence:    fmt.Sprintf("%d/%d requests succeeded (expected 1)", successCount, opts.Requests),
			Description: "Race condition detected. Multiple concurrent requests succeeded when only one should.",
			Remediation: "Implement proper locking/mutex. Use database transactions with row-level locking.",
		}
	}

	// 2. Different responses to identical requests
	uniqueResponses := make(map[string]int)
	for _, body := range bodies {
		// Normalize response (remove timestamps, etc.)
		normalized := normalizeResponse(body)
		uniqueResponses[normalized]++
	}

	if len(uniqueResponses) > 1 && len(bodies) > 2 {
		resultChan <- VulnResult{
			Type:        VulnRace,
			Severity:    SeverityMedium,
			URL:         opts.URL,
			Parameter:   "Response Inconsistency",
			Payload:     opts.Data,
			Evidence:    fmt.Sprintf("%d unique responses from %d requests", len(uniqueResponses), len(bodies)),
			Description: "Inconsistent responses detected. The application may have TOCTOU vulnerabilities.",
			Remediation: "Ensure atomic operations. Review state management for race conditions.",
		}
	}

	// 3. Timing analysis - large variance may indicate race
	if len(durations) > 2 {
		var totalDuration time.Duration
		minDuration := durations[0]
		maxDuration := durations[0]

		for _, d := range durations {
			totalDuration += d
			if d < minDuration {
				minDuration = d
			}
			if d > maxDuration {
				maxDuration = d
			}
		}

		avgDuration := totalDuration / time.Duration(len(durations))
		variance := maxDuration - minDuration

		// High variance with some very fast responses may indicate bypassed checks
		if variance > 2*avgDuration && minDuration < avgDuration/2 {
			resultChan <- VulnResult{
				Type:        VulnRace,
				Severity:    SeverityLow,
				URL:         opts.URL,
				Parameter:   "Timing Analysis",
				Payload:     opts.Data,
				Evidence:    fmt.Sprintf("High timing variance: min=%v, max=%v, avg=%v", minDuration, maxDuration, avgDuration),
				Description: "High response time variance detected. Some requests may have bypassed validation.",
				Remediation: "Review server-side validation timing. Implement consistent processing.",
			}
		}
	}

	// Summary
	if len(statusCodes) > 0 {
		statusSummary := ""
		for code, count := range statusCodes {
			statusSummary += fmt.Sprintf("%d(%dx) ", code, count)
		}
		resultChan <- VulnResult{
			Type:        VulnRace,
			Severity:    SeverityInfo,
			URL:         opts.URL,
			Parameter:   "Summary",
			Evidence:    fmt.Sprintf("Status codes: %s", statusSummary),
			Description: "Race condition test completed.",
			Remediation: "Review results for anomalies.",
		}
	}
}

// Helper function to normalize response for comparison
func normalizeResponse(body string) string {
	// Remove common dynamic elements
	patterns := []string{
		`"timestamp":\s*"[^"]*"`,
		`"time":\s*\d+`,
		`"date":\s*"[^"]*"`,
		`"id":\s*"[^"]*"`,
		`"request_id":\s*"[^"]*"`,
	}

	result := body
	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		result = re.ReplaceAllString(result, "")
	}
	return result
}
