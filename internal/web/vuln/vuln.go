package vuln

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"raxuiscli/internal/shared/constants"
	"raxuiscli/internal/shared/models"
	"raxuiscli/internal/shared/payloads"
)

// Re-export types for backward compatibility
type VulnType = constants.VulnType
type Severity = constants.Severity
type VulnResult = models.VulnResult
type ScanOptions = models.ScanOptions
type CORSOptions = models.CORSOptions
type NoSQLiOptions = models.NoSQLiOptions
type XXEOptions = models.XXEOptions
type GraphQLOptions = models.GraphQLOptions
type HostHeaderOptions = models.HostHeaderOptions
type RaceOptions = models.RaceOptions
type CORSResult = models.CORSResult
type RaceResult = models.RaceResult
type GraphQLSchema = models.GraphQLSchema

// Re-export constants for backward compatibility
const (
	VulnXSS        = constants.VulnXSS
	VulnSQLi       = constants.VulnSQLi
	VulnLFI        = constants.VulnLFI
	VulnRFI        = constants.VulnRFI
	VulnSSRF       = constants.VulnSSRF
	VulnCmdInj     = constants.VulnCmdInj
	VulnHeaders    = constants.VulnHeaders
	VulnOpen       = constants.VulnOpen
	VulnCORS       = constants.VulnCORS
	VulnNoSQLi     = constants.VulnNoSQLi
	VulnXXE        = constants.VulnXXE
	VulnGraphQL    = constants.VulnGraphQL
	VulnHostHeader = constants.VulnHostHeader
	VulnRace       = constants.VulnRace

	SeverityCritical = constants.SeverityCritical
	SeverityHigh     = constants.SeverityHigh
	SeverityMedium   = constants.SeverityMedium
	SeverityLow      = constants.SeverityLow
	SeverityInfo     = constants.SeverityInfo
)

// Re-export payloads for backward compatibility
var (
	XSSPayloads          = payloads.XSSPayloads
	SQLiPayloads         = payloads.SQLiPayloads
	LFIPayloads          = payloads.LFIPayloads
	CmdInjPayloads       = payloads.CmdInjPayloads
	OpenRedirectPayloads = payloads.OpenRedirectPayloads
	NoSQLiPayloads       = payloads.NoSQLiPayloads
	XXEPayloads          = payloads.XXEPayloads
	GraphQLQueries       = payloads.GraphQLQueries
	GraphQLDoSQueries    = payloads.GraphQLDoSQueries
	HostHeaderPayloads   = payloads.HostHeaderPayloads
	CORSTestOrigins      = payloads.CORSTestOrigins
	SQLErrorPatterns     = payloads.SQLErrorPatterns
	LFISuccessPatterns   = payloads.LFISuccessPatterns
)

// QuickScan performs a quick vulnerability scan
func QuickScan(opts ScanOptions, resultChan chan<- VulnResult, doneChan chan<- bool) {
	defer func() { doneChan <- true }()

	// Test security headers first
	headerResults := ScanSecurityHeaders(opts)
	for _, r := range headerResults {
		resultChan <- r
	}

	var wg sync.WaitGroup

	// Run all tests concurrently
	wg.Add(5)

	go func() {
		defer wg.Done()
		TestXSS(opts, resultChan)
	}()

	go func() {
		defer wg.Done()
		TestSQLi(opts, resultChan)
	}()

	go func() {
		defer wg.Done()
		TestLFI(opts, resultChan)
	}()

	go func() {
		defer wg.Done()
		TestCommandInjection(opts, resultChan)
	}()

	go func() {
		defer wg.Done()
		TestOpenRedirect(opts, resultChan)
	}()

	wg.Wait()
}

// DisplayResults displays vulnerability results
func DisplayResults(results []VulnResult) {
	if len(results) == 0 {
		fmt.Println("\n[NO VULNERABILITIES FOUND]")
		return
	}

	fmt.Println("\n[VULNERABILITY SCAN RESULTS]")
	fmt.Println(strings.Repeat("=", 80))

	// Group by severity
	bySeverity := map[Severity][]VulnResult{
		SeverityCritical: {},
		SeverityHigh:     {},
		SeverityMedium:   {},
		SeverityLow:      {},
		SeverityInfo:     {},
	}

	for _, r := range results {
		bySeverity[r.Severity] = append(bySeverity[r.Severity], r)
	}

	// Summary
	fmt.Printf("\nSummary:\n")
	fmt.Printf("  Critical: %d\n", len(bySeverity[SeverityCritical]))
	fmt.Printf("  High:     %d\n", len(bySeverity[SeverityHigh]))
	fmt.Printf("  Medium:   %d\n", len(bySeverity[SeverityMedium]))
	fmt.Printf("  Low:      %d\n", len(bySeverity[SeverityLow]))
	fmt.Printf("  Info:     %d\n", len(bySeverity[SeverityInfo]))

	// Display by severity
	for _, severity := range []Severity{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo} {
		vulns := bySeverity[severity]
		if len(vulns) == 0 {
			continue
		}

		fmt.Printf("\n[%s]\n", severity)
		fmt.Println(strings.Repeat("-", 40))

		for i, v := range vulns {
			fmt.Printf("\n%d. %s\n", i+1, v.Type)
			fmt.Printf("   URL: %s\n", truncate(v.URL, 70))
			if v.Parameter != "" {
				fmt.Printf("   Parameter: %s\n", v.Parameter)
			}
			if v.Payload != "" {
				fmt.Printf("   Payload: %s\n", truncate(v.Payload, 50))
			}
			fmt.Printf("   Evidence: %s\n", truncate(v.Evidence, 60))
			fmt.Printf("   Description: %s\n", v.Description)
			fmt.Printf("   Remediation: %s\n", v.Remediation)
		}
	}

	fmt.Println()
}

// GetPayloads returns payloads for a specific vulnerability type
func GetPayloads(vulnType VulnType, level int) []string {
	switch vulnType {
	case VulnXSS:
		return payloads.GetXSSPayloads(level)
	case VulnSQLi:
		return payloads.GetSQLiPayloads(level)
	case VulnLFI:
		return payloads.GetLFIPayloads(level)
	case VulnCmdInj:
		return payloads.GetCmdInjPayloads(level)
	case VulnOpen:
		return payloads.GetOpenRedirectPayloads()
	case VulnNoSQLi:
		return payloads.GetNoSQLiPayloads(level)
	case VulnXXE:
		return payloads.XXEPayloads
	default:
		return nil
	}
}

// Helper functions

func createClient(opts ScanOptions) *http.Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: opts.Insecure,
		},
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: opts.Threads,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(opts.Timeout) * time.Second,
	}

	if !opts.FollowRedir {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	return client
}

func doRequest(client *http.Client, targetURL string, opts ScanOptions) (*http.Response, string, error) {
	method := opts.Method
	if method == "" {
		method = "GET"
	}

	req, err := http.NewRequest(method, targetURL, nil)
	if err != nil {
		return nil, "", err
	}

	if opts.UserAgent != "" {
		req.Header.Set("User-Agent", opts.UserAgent)
	} else {
		req.Header.Set("User-Agent", "RaxuisCLI-VulnScanner/1.0")
	}

	if opts.Cookie != "" {
		req.Header.Set("Cookie", opts.Cookie)
	}

	for key, value := range opts.Headers {
		req.Header.Set(key, value)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, "", err
	}

	body, _ := io.ReadAll(resp.Body)
	return resp, string(body), nil
}

func buildTestURL(parsedURL *url.URL, param, payload string) string {
	query := parsedURL.Query()
	query.Set(param, payload)
	parsedURL.RawQuery = query.Encode()
	return parsedURL.String()
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
