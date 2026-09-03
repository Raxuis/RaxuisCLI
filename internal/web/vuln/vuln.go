package vuln

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"raxuiscli/internal/shared/constants"
	"raxuiscli/internal/shared/httpclient"
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

// quickScanTests holds the vulnerability checks QuickScan runs concurrently.
// Every check shares the signature func(ScanOptions, chan<- VulnResult), so
// adding a new one only means appending to this slice - QuickScan itself
// doesn't need to change.
var quickScanTests = []func(ScanOptions, chan<- VulnResult){
	TestXSS,
	TestSQLi,
	TestLFI,
	TestCommandInjection,
	TestOpenRedirect,
}

// QuickScan performs a quick vulnerability scan
func QuickScan(opts ScanOptions, resultChan chan<- VulnResult, doneChan chan<- bool) {
	defer func() { doneChan <- true }()

	// Test security headers first
	headerResults := ScanSecurityHeaders(opts)
	for _, r := range headerResults {
		resultChan <- r
	}

	var wg sync.WaitGroup
	wg.Add(len(quickScanTests))

	for _, test := range quickScanTests {
		go func(test func(ScanOptions, chan<- VulnResult)) {
			defer wg.Done()
			test(opts, resultChan)
		}(test)
	}

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
//
// These delegate to internal/shared/httpclient so the whole vuln package
// shares one HTTP client/request implementation instead of maintaining its
// own copy. buildTestURL in particular must go through httpclient.BuildTestURL,
// which clones the URL before mutating it - the test functions here call it
// from many concurrent goroutines against the same parsed URL, and mutating
// it in place caused a data race (found via `go test -race`).

func createClient(opts ScanOptions) *http.Client {
	return httpclient.CreateClient(opts)
}

func doRequest(client *http.Client, targetURL string, opts ScanOptions) (*http.Response, string, error) {
	return httpclient.DoRequest(client, targetURL, opts)
}

func buildTestURL(parsedURL *url.URL, param, payload string) string {
	return httpclient.BuildTestURL(parsedURL, param, payload)
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
