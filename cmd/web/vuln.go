package web

import (
	"fmt"
	"strings"
	"time"

	"github.com/Raxuis/RaxuisCLI/cmd"

	"github.com/spf13/cobra"

	"github.com/Raxuis/RaxuisCLI/internal/shared/urlnorm"
	"github.com/Raxuis/RaxuisCLI/internal/web/vuln"
)

var vulnCmd = &cobra.Command{
	Use:   "vuln",
	Short: "Vulnerability scanning and testing",
	Long: `Scan for common web vulnerabilities.

Supports XSS, SQL injection, LFI, command injection, and security header analysis.

Examples:
  raxuiscli vuln scan https://example.com/page?id=1
  raxuiscli vuln xss "https://site.com?q=test"
  raxuiscli vuln sqli "https://site.com?id=1"
  raxuiscli vuln headers https://example.com`,
}

var vulnScanCmd = &cobra.Command{
	Use:   "scan [url]",
	Short: "Quick vulnerability scan",
	Long: `Perform a quick scan for common vulnerabilities.

Tests for XSS, SQLi, LFI, command injection, open redirects, and security headers.

Examples:
  raxuiscli vuln scan "https://example.com/search?q=test"
  raxuiscli vuln scan "https://site.com/page?id=1&name=test" --level 3
  raxuiscli vuln scan https://example.com --threads 20`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			fmt.Println("Please provide a URL with parameters to test")
			return
		}

		url := args[0]
		url = urlnorm.EnsureScheme(url)

		timeout, _ := cmd.Flags().GetInt("timeout")
		threads, _ := cmd.Flags().GetInt("threads")
		insecure, _ := cmd.Flags().GetBool("insecure")
		level, _ := cmd.Flags().GetInt("level")
		userAgent, _ := cmd.Flags().GetString("user-agent")
		cookie, _ := cmd.Flags().GetString("cookie")

		opts := vuln.ScanOptions{
			URL:          url,
			Timeout:      timeout,
			Threads:      threads,
			Insecure:     insecure,
			PayloadLevel: level,
			UserAgent:    userAgent,
			Cookie:       cookie,
		}

		fmt.Printf("[VULNERABILITY SCAN]\n")
		fmt.Println(strings.Repeat("=", 60))
		fmt.Printf("Target: %s\n", url)
		fmt.Printf("Level: %d (1=basic, 2=normal, 3=aggressive)\n", level)
		fmt.Printf("Threads: %d\n\n", threads)
		fmt.Println("Scanning...")

		resultChan := make(chan vuln.VulnResult, 100)
		doneChan := make(chan bool)

		var results []vuln.VulnResult
		start := time.Now()

		go vuln.QuickScan(opts, resultChan, doneChan)

		for {
			select {
			case result := <-resultChan:
				results = append(results, result)
				fmt.Printf("  [%s] %s - %s\n", result.Severity, result.Type, result.Parameter)
			case <-doneChan:
				fmt.Printf("\nScan completed in %v\n", time.Since(start))
				vuln.DisplayResults(results)
				return
			}
		}
	},
}

var vulnXSSCmd = &cobra.Command{
	Use:   "xss [url]",
	Short: "Test for XSS vulnerabilities",
	Long: `Test URL parameters for Cross-Site Scripting vulnerabilities.

Examples:
  raxuiscli vuln xss "https://site.com/search?q=test"
  raxuiscli vuln xss "https://site.com?name=foo&msg=bar" --level 3`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			fmt.Println("Please provide a URL with parameters to test")
			return
		}

		url := args[0]
		url = urlnorm.EnsureScheme(url)

		timeout, _ := cmd.Flags().GetInt("timeout")
		threads, _ := cmd.Flags().GetInt("threads")
		insecure, _ := cmd.Flags().GetBool("insecure")
		level, _ := cmd.Flags().GetInt("level")
		userAgent, _ := cmd.Flags().GetString("user-agent")
		cookie, _ := cmd.Flags().GetString("cookie")

		opts := vuln.ScanOptions{
			URL:          url,
			Timeout:      timeout,
			Threads:      threads,
			Insecure:     insecure,
			PayloadLevel: level,
			UserAgent:    userAgent,
			Cookie:       cookie,
		}

		fmt.Printf("[XSS TESTING]\n")
		fmt.Println(strings.Repeat("=", 60))
		fmt.Printf("Target: %s\n", url)
		fmt.Printf("Level: %d\n\n", level)

		resultChan := make(chan vuln.VulnResult, 100)
		var results []vuln.VulnResult

		go func() {
			vuln.TestXSS(opts, resultChan)
			close(resultChan)
		}()

		for result := range resultChan {
			results = append(results, result)
			fmt.Printf("  [FOUND] Parameter: %s\n", result.Parameter)
		}

		if len(results) == 0 {
			fmt.Println("No XSS vulnerabilities detected")
		} else {
			vuln.DisplayResults(results)
		}
	},
}

var vulnSQLiCmd = &cobra.Command{
	Use:   "sqli [url]",
	Short: "Test for SQL injection vulnerabilities",
	Long: `Test URL parameters for SQL Injection vulnerabilities.

Supports error-based, time-based, and boolean-based detection.

Examples:
  raxuiscli vuln sqli "https://site.com/user?id=1"
  raxuiscli vuln sqli "https://site.com?category=1&sort=name" --level 3`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			fmt.Println("Please provide a URL with parameters to test")
			return
		}

		url := args[0]
		url = urlnorm.EnsureScheme(url)

		timeout, _ := cmd.Flags().GetInt("timeout")
		threads, _ := cmd.Flags().GetInt("threads")
		insecure, _ := cmd.Flags().GetBool("insecure")
		level, _ := cmd.Flags().GetInt("level")
		userAgent, _ := cmd.Flags().GetString("user-agent")
		cookie, _ := cmd.Flags().GetString("cookie")

		opts := vuln.ScanOptions{
			URL:          url,
			Timeout:      timeout,
			Threads:      threads,
			Insecure:     insecure,
			PayloadLevel: level,
			UserAgent:    userAgent,
			Cookie:       cookie,
		}

		fmt.Printf("[SQL INJECTION TESTING]\n")
		fmt.Println(strings.Repeat("=", 60))
		fmt.Printf("Target: %s\n", url)
		fmt.Printf("Level: %d\n\n", level)

		resultChan := make(chan vuln.VulnResult, 100)
		var results []vuln.VulnResult

		go func() {
			vuln.TestSQLi(opts, resultChan)
			close(resultChan)
		}()

		for result := range resultChan {
			results = append(results, result)
			fmt.Printf("  [FOUND] %s - %s\n", result.Parameter, result.Evidence)
		}

		if len(results) == 0 {
			fmt.Println("No SQL injection vulnerabilities detected")
		} else {
			vuln.DisplayResults(results)
		}
	},
}

var vulnLFICmd = &cobra.Command{
	Use:   "lfi [url]",
	Short: "Test for Local File Inclusion vulnerabilities",
	Long: `Test URL parameters for Local File Inclusion vulnerabilities.

Examples:
  raxuiscli vuln lfi "https://site.com/page?file=about.php"
  raxuiscli vuln lfi "https://site.com?template=home" --level 3`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			fmt.Println("Please provide a URL with parameters to test")
			return
		}

		url := args[0]
		url = urlnorm.EnsureScheme(url)

		timeout, _ := cmd.Flags().GetInt("timeout")
		threads, _ := cmd.Flags().GetInt("threads")
		insecure, _ := cmd.Flags().GetBool("insecure")
		level, _ := cmd.Flags().GetInt("level")
		userAgent, _ := cmd.Flags().GetString("user-agent")
		cookie, _ := cmd.Flags().GetString("cookie")

		opts := vuln.ScanOptions{
			URL:          url,
			Timeout:      timeout,
			Threads:      threads,
			Insecure:     insecure,
			PayloadLevel: level,
			UserAgent:    userAgent,
			Cookie:       cookie,
		}

		fmt.Printf("[LFI TESTING]\n")
		fmt.Println(strings.Repeat("=", 60))
		fmt.Printf("Target: %s\n", url)
		fmt.Printf("Level: %d\n\n", level)

		resultChan := make(chan vuln.VulnResult, 100)
		var results []vuln.VulnResult

		go func() {
			vuln.TestLFI(opts, resultChan)
			close(resultChan)
		}()

		for result := range resultChan {
			results = append(results, result)
			fmt.Printf("  [FOUND] %s - %s\n", result.Parameter, result.Payload)
		}

		if len(results) == 0 {
			fmt.Println("No LFI vulnerabilities detected")
		} else {
			vuln.DisplayResults(results)
		}
	},
}

var vulnHeadersCmd = &cobra.Command{
	Use:   "headers [url]",
	Short: "Check security headers",
	Long: `Analyze HTTP response headers for security issues.

Checks for missing or misconfigured security headers.

Examples:
  raxuiscli vuln headers https://example.com
  raxuiscli vuln headers https://api.example.com`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			fmt.Println("Please provide a URL")
			return
		}

		url := args[0]
		url = urlnorm.EnsureScheme(url)

		timeout, _ := cmd.Flags().GetInt("timeout")
		insecure, _ := cmd.Flags().GetBool("insecure")
		userAgent, _ := cmd.Flags().GetString("user-agent")

		opts := vuln.ScanOptions{
			URL:       url,
			Timeout:   timeout,
			Insecure:  insecure,
			UserAgent: userAgent,
		}

		fmt.Printf("[SECURITY HEADERS CHECK]\n")
		fmt.Println(strings.Repeat("=", 60))
		fmt.Printf("Target: %s\n\n", url)

		results := vuln.ScanSecurityHeaders(opts)
		vuln.DisplayResults(results)
	},
}

var vulnPayloadsCmd = &cobra.Command{
	Use:   "payloads [type]",
	Short: "List vulnerability payloads",
	Long: `List available payloads for vulnerability testing.

Types: xss, sqli, lfi, cmdi, redirect, nosqli

Examples:
  raxuiscli vuln payloads xss
  raxuiscli vuln payloads sqli --level 3
  raxuiscli vuln payloads nosqli`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			fmt.Println("Available payload types: xss, sqli, lfi, cmdi, redirect, nosqli")
			return
		}

		level, _ := cmd.Flags().GetInt("level")

		var vulnType vuln.VulnType
		switch strings.ToLower(args[0]) {
		case "xss":
			vulnType = vuln.VulnXSS
		case "sqli", "sql":
			vulnType = vuln.VulnSQLi
		case "lfi":
			vulnType = vuln.VulnLFI
		case "cmdi", "cmd", "rce":
			vulnType = vuln.VulnCmdInj
		case "redirect", "open-redirect":
			vulnType = vuln.VulnOpen
		case "nosqli", "nosql":
			vulnType = vuln.VulnNoSQLi
		default:
			fmt.Println("Unknown payload type. Available: xss, sqli, lfi, cmdi, redirect, nosqli")
			return
		}

		payloads := vuln.GetPayloads(vulnType, level)

		fmt.Printf("[%s PAYLOADS - Level %d]\n", strings.ToUpper(args[0]), level)
		fmt.Println(strings.Repeat("=", 60))

		for i, p := range payloads {
			fmt.Printf("%3d. %s\n", i+1, p)
		}

		fmt.Printf("\nTotal: %d payloads\n", len(payloads))
	},
}

// CORS command
var vulnCORSCmd = &cobra.Command{
	Use:   "cors [url]",
	Short: "Test for CORS misconfiguration",
	Long: `Test for Cross-Origin Resource Sharing (CORS) misconfigurations.

Checks for:
- Wildcard (*) origin acceptance
- Null origin acceptance
- Reflected origin without validation
- Credentials exposure with permissive CORS

Examples:
  raxuiscli vuln cors https://api.example.com
  raxuiscli vuln cors https://api.example.com --origin "https://evil.com"
  raxuiscli vuln cors https://api.example.com --full`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			fmt.Println("Please provide a URL to test")
			return
		}

		url := args[0]
		url = urlnorm.EnsureScheme(url)

		timeout, _ := cmd.Flags().GetInt("timeout")
		insecure, _ := cmd.Flags().GetBool("insecure")
		userAgent, _ := cmd.Flags().GetString("user-agent")
		origin, _ := cmd.Flags().GetString("origin")
		full, _ := cmd.Flags().GetBool("full")

		opts := vuln.CORSOptions{
			ScanOptions: vuln.ScanOptions{
				URL:       url,
				Timeout:   timeout,
				Insecure:  insecure,
				UserAgent: userAgent,
			},
			TestOrigin: origin,
			Full:       full,
		}

		fmt.Printf("[CORS MISCONFIGURATION TEST]\n")
		fmt.Println(strings.Repeat("=", 60))
		fmt.Printf("Target: %s\n", url)
		if origin != "" {
			fmt.Printf("Custom Origin: %s\n", origin)
		}
		fmt.Println()

		resultChan := make(chan vuln.VulnResult, 100)
		var results []vuln.VulnResult

		go func() {
			vuln.TestCORS(opts, resultChan)
			close(resultChan)
		}()

		for result := range resultChan {
			results = append(results, result)
			fmt.Printf("  [%s] %s: %s\n", result.Severity, result.Parameter, result.Evidence)
		}

		if len(results) == 0 {
			fmt.Println("No CORS misconfigurations detected")
		} else {
			vuln.DisplayResults(results)
		}
	},
}

// NoSQLi command
var vulnNoSQLiCmd = &cobra.Command{
	Use:   "nosqli [url]",
	Short: "Test for NoSQL injection",
	Long: `Test for NoSQL Injection vulnerabilities (MongoDB focused).

Supports:
- URL parameter injection
- JSON body injection
- Authentication bypass detection
- Time-based blind injection

Examples:
  raxuiscli vuln nosqli "https://api.com/users?id=1"
  raxuiscli vuln nosqli "https://api.com/login" -d '{"user":"test","pass":"test"}'
  raxuiscli vuln nosqli "https://api.com" --type mongodb --level 3`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			fmt.Println("Please provide a URL to test")
			return
		}

		url := args[0]
		url = urlnorm.EnsureScheme(url)

		timeout, _ := cmd.Flags().GetInt("timeout")
		threads, _ := cmd.Flags().GetInt("threads")
		insecure, _ := cmd.Flags().GetBool("insecure")
		level, _ := cmd.Flags().GetInt("level")
		userAgent, _ := cmd.Flags().GetString("user-agent")
		data, _ := cmd.Flags().GetString("data")
		dbType, _ := cmd.Flags().GetString("type")

		isJSON := strings.HasPrefix(strings.TrimSpace(data), "{")

		opts := vuln.NoSQLiOptions{
			ScanOptions: vuln.ScanOptions{
				URL:          url,
				Timeout:      timeout,
				Threads:      threads,
				Insecure:     insecure,
				PayloadLevel: level,
				UserAgent:    userAgent,
			},
			Data:   data,
			DBType: dbType,
			IsJSON: isJSON,
		}

		fmt.Printf("[NoSQL INJECTION TEST]\n")
		fmt.Println(strings.Repeat("=", 60))
		fmt.Printf("Target: %s\n", url)
		fmt.Printf("Level: %d\n", level)
		if data != "" {
			fmt.Printf("Data: %s\n", data)
		}
		fmt.Println()

		resultChan := make(chan vuln.VulnResult, 100)
		var results []vuln.VulnResult

		go func() {
			vuln.TestNoSQLi(opts, resultChan)
			close(resultChan)
		}()

		for result := range resultChan {
			results = append(results, result)
			fmt.Printf("  [%s] %s - %s\n", result.Severity, result.Parameter, result.Evidence)
		}

		if len(results) == 0 {
			fmt.Println("No NoSQL injection vulnerabilities detected")
		} else {
			vuln.DisplayResults(results)
		}
	},
}

// XXE command
var vulnXXECmd = &cobra.Command{
	Use:   "xxe [url]",
	Short: "Test for XXE vulnerabilities",
	Long: `Test for XML External Entity (XXE) vulnerabilities.

Supports:
- File disclosure attacks
- Out-of-band (OOB) XXE with callback
- Error-based XXE
- PHP filter bypass

Examples:
  raxuiscli vuln xxe https://api.com/upload
  raxuiscli vuln xxe https://api.com --payload file
  raxuiscli vuln xxe https://api.com --oob http://callback.attacker.com`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			fmt.Println("Please provide a URL to test")
			return
		}

		url := args[0]
		url = urlnorm.EnsureScheme(url)

		timeout, _ := cmd.Flags().GetInt("timeout")
		insecure, _ := cmd.Flags().GetBool("insecure")
		userAgent, _ := cmd.Flags().GetString("user-agent")
		oobCallback, _ := cmd.Flags().GetString("oob")
		payloadType, _ := cmd.Flags().GetString("payload")

		opts := vuln.XXEOptions{
			ScanOptions: vuln.ScanOptions{
				URL:       url,
				Timeout:   timeout,
				Insecure:  insecure,
				UserAgent: userAgent,
			},
			OOBCallback: oobCallback,
			PayloadType: payloadType,
		}

		fmt.Printf("[XXE VULNERABILITY TEST]\n")
		fmt.Println(strings.Repeat("=", 60))
		fmt.Printf("Target: %s\n", url)
		if oobCallback != "" {
			fmt.Printf("OOB Callback: %s\n", oobCallback)
		}
		if payloadType != "" {
			fmt.Printf("Payload Type: %s\n", payloadType)
		}
		fmt.Println()

		resultChan := make(chan vuln.VulnResult, 100)
		var results []vuln.VulnResult

		go func() {
			vuln.TestXXE(opts, resultChan)
			close(resultChan)
		}()

		for result := range resultChan {
			results = append(results, result)
			fmt.Printf("  [%s] %s - %s\n", result.Severity, result.Parameter, result.Evidence)
		}

		if len(results) == 0 {
			fmt.Println("No XXE vulnerabilities detected")
			fmt.Println("\nNote: Use --oob with a callback server for blind XXE detection")
		} else {
			vuln.DisplayResults(results)
		}
	},
}

// GraphQL command
var vulnGraphQLCmd = &cobra.Command{
	Use:   "graphql [url]",
	Short: "Test GraphQL endpoint security",
	Long: `Test GraphQL endpoints for security vulnerabilities.

Checks for:
- Introspection enabled (schema exposure)
- Sensitive field names in schema
- Field suggestions (enumeration aid)
- Query batching (DoS potential)
- Nested query depth abuse

Examples:
  raxuiscli vuln graphql https://api.com/graphql
  raxuiscli vuln graphql https://api.com/graphql --introspect
  raxuiscli vuln graphql https://api.com/graphql --dos`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			fmt.Println("Please provide a GraphQL endpoint URL")
			return
		}

		url := args[0]
		url = urlnorm.EnsureScheme(url)

		timeout, _ := cmd.Flags().GetInt("timeout")
		insecure, _ := cmd.Flags().GetBool("insecure")
		userAgent, _ := cmd.Flags().GetString("user-agent")
		introspect, _ := cmd.Flags().GetBool("introspect")
		dos, _ := cmd.Flags().GetBool("dos")

		opts := vuln.GraphQLOptions{
			ScanOptions: vuln.ScanOptions{
				URL:       url,
				Timeout:   timeout,
				Insecure:  insecure,
				UserAgent: userAgent,
			},
			Introspect: introspect,
			DoS:        dos,
		}

		fmt.Printf("[GRAPHQL SECURITY TEST]\n")
		fmt.Println(strings.Repeat("=", 60))
		fmt.Printf("Target: %s\n", url)
		fmt.Printf("DoS Testing: %v\n", dos)
		fmt.Println()

		resultChan := make(chan vuln.VulnResult, 100)
		var results []vuln.VulnResult

		go func() {
			vuln.TestGraphQL(opts, resultChan)
			close(resultChan)
		}()

		for result := range resultChan {
			results = append(results, result)
			fmt.Printf("  [%s] %s - %s\n", result.Severity, result.Parameter, result.Evidence)
		}

		if len(results) == 0 {
			fmt.Println("No GraphQL security issues detected")
		} else {
			vuln.DisplayResults(results)
		}
	},
}

// Host Header command
var vulnHostCmd = &cobra.Command{
	Use:   "host [url]",
	Short: "Test for Host header injection",
	Long: `Test for Host header injection vulnerabilities.

Checks for:
- Host header reflection in response
- Password reset poisoning
- Web cache poisoning
- X-Forwarded-Host injection
- Redirect manipulation

Examples:
  raxuiscli vuln host https://example.com
  raxuiscli vuln host https://example.com --poison
  raxuiscli vuln host https://example.com --cache`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			fmt.Println("Please provide a URL to test")
			return
		}

		url := args[0]
		url = urlnorm.EnsureScheme(url)

		timeout, _ := cmd.Flags().GetInt("timeout")
		insecure, _ := cmd.Flags().GetBool("insecure")
		userAgent, _ := cmd.Flags().GetString("user-agent")
		poison, _ := cmd.Flags().GetBool("poison")
		cache, _ := cmd.Flags().GetBool("cache")

		opts := vuln.HostHeaderOptions{
			ScanOptions: vuln.ScanOptions{
				URL:       url,
				Timeout:   timeout,
				Insecure:  insecure,
				UserAgent: userAgent,
			},
			Poison: poison,
			Cache:  cache,
		}

		fmt.Printf("[HOST HEADER INJECTION TEST]\n")
		fmt.Println(strings.Repeat("=", 60))
		fmt.Printf("Target: %s\n", url)
		fmt.Printf("Password Reset Poisoning: %v\n", poison)
		fmt.Printf("Cache Poisoning: %v\n", cache)
		fmt.Println()

		resultChan := make(chan vuln.VulnResult, 100)
		var results []vuln.VulnResult

		go func() {
			vuln.TestHostHeader(opts, resultChan)
			close(resultChan)
		}()

		for result := range resultChan {
			results = append(results, result)
			fmt.Printf("  [%s] %s - %s\n", result.Severity, result.Parameter, result.Evidence)
		}

		if len(results) == 0 {
			fmt.Println("No Host header injection vulnerabilities detected")
		} else {
			vuln.DisplayResults(results)
		}
	},
}

// Race Condition command
var vulnRaceCmd = &cobra.Command{
	Use:   "race [url]",
	Short: "Test for race condition vulnerabilities",
	Long: `Test for race condition vulnerabilities using concurrent requests.

Useful for detecting:
- Double-spending / limit bypass
- Coupon/promo code reuse
- Vote manipulation
- TOCTOU vulnerabilities

Examples:
  raxuiscli vuln race "https://api.com/transfer" -d '{"amount":100}' --requests 50
  raxuiscli vuln race "https://api.com/redeem" -d '{"code":"PROMO"}' --requests 20
  raxuiscli vuln race "https://api.com/vote" --method POST --requests 30`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			fmt.Println("Please provide a URL to test")
			return
		}

		url := args[0]
		url = urlnorm.EnsureScheme(url)

		timeout, _ := cmd.Flags().GetInt("timeout")
		insecure, _ := cmd.Flags().GetBool("insecure")
		userAgent, _ := cmd.Flags().GetString("user-agent")
		cookie, _ := cmd.Flags().GetString("cookie")
		data, _ := cmd.Flags().GetString("data")
		method, _ := cmd.Flags().GetString("method")
		requests, _ := cmd.Flags().GetInt("requests")

		opts := vuln.RaceOptions{
			ScanOptions: vuln.ScanOptions{
				URL:       url,
				Method:    method,
				Timeout:   timeout,
				Insecure:  insecure,
				UserAgent: userAgent,
				Cookie:    cookie,
			},
			Data:     data,
			Requests: requests,
		}

		fmt.Printf("[RACE CONDITION TEST]\n")
		fmt.Println(strings.Repeat("=", 60))
		fmt.Printf("Target: %s\n", url)
		fmt.Printf("Method: %s\n", method)
		fmt.Printf("Concurrent Requests: %d\n", requests)
		if data != "" {
			fmt.Printf("Data: %s\n", data)
		}
		fmt.Println()
		fmt.Println("Firing concurrent requests...")

		start := time.Now()
		resultChan := make(chan vuln.VulnResult, 100)
		var results []vuln.VulnResult

		go func() {
			vuln.TestRaceCondition(opts, resultChan)
			close(resultChan)
		}()

		for result := range resultChan {
			results = append(results, result)
			if result.Severity != vuln.SeverityInfo {
				fmt.Printf("  [%s] %s - %s\n", result.Severity, result.Parameter, result.Evidence)
			}
		}

		fmt.Printf("\nCompleted in %v\n", time.Since(start))

		// Filter out info-level results for display
		var significantResults []vuln.VulnResult
		for _, r := range results {
			if r.Severity != vuln.SeverityInfo {
				significantResults = append(significantResults, r)
			}
		}

		if len(significantResults) == 0 {
			fmt.Println("No race condition vulnerabilities detected")
		} else {
			vuln.DisplayResults(significantResults)
		}
	},
}

func init() {
	cmd.RootCmd.AddCommand(vulnCmd)

	// Common flags
	commonFlags := func(cmd *cobra.Command) {
		cmd.Flags().IntP("timeout", "t", 10, "Request timeout in seconds")
		cmd.Flags().Int("threads", 10, "Number of concurrent threads")
		cmd.Flags().BoolP("insecure", "k", false, "Skip TLS verification")
		cmd.Flags().Int("level", 2, "Payload level (1=basic, 2=normal, 3=aggressive)")
		cmd.Flags().StringP("user-agent", "A", "", "User-Agent string")
		cmd.Flags().StringP("cookie", "b", "", "Cookie string")
	}

	// Scan command
	vulnCmd.AddCommand(vulnScanCmd)
	commonFlags(vulnScanCmd)

	// XSS command
	vulnCmd.AddCommand(vulnXSSCmd)
	commonFlags(vulnXSSCmd)

	// SQLi command
	vulnCmd.AddCommand(vulnSQLiCmd)
	commonFlags(vulnSQLiCmd)

	// LFI command
	vulnCmd.AddCommand(vulnLFICmd)
	commonFlags(vulnLFICmd)

	// Headers command
	vulnCmd.AddCommand(vulnHeadersCmd)
	vulnHeadersCmd.Flags().IntP("timeout", "t", 10, "Request timeout in seconds")
	vulnHeadersCmd.Flags().BoolP("insecure", "k", false, "Skip TLS verification")
	vulnHeadersCmd.Flags().StringP("user-agent", "A", "", "User-Agent string")

	// Payloads command
	vulnCmd.AddCommand(vulnPayloadsCmd)
	vulnPayloadsCmd.Flags().Int("level", 2, "Payload level (1=basic, 2=normal, 3=aggressive)")

	// CORS command
	vulnCmd.AddCommand(vulnCORSCmd)
	vulnCORSCmd.Flags().IntP("timeout", "t", 10, "Request timeout in seconds")
	vulnCORSCmd.Flags().BoolP("insecure", "k", false, "Skip TLS verification")
	vulnCORSCmd.Flags().StringP("user-agent", "A", "", "User-Agent string")
	vulnCORSCmd.Flags().String("origin", "", "Custom origin to test")
	vulnCORSCmd.Flags().Bool("full", false, "Test with GET requests too (not just preflight)")

	// NoSQLi command
	vulnCmd.AddCommand(vulnNoSQLiCmd)
	commonFlags(vulnNoSQLiCmd)
	vulnNoSQLiCmd.Flags().StringP("data", "d", "", "POST data (JSON for body injection)")
	vulnNoSQLiCmd.Flags().String("type", "mongodb", "Database type (mongodb, couchdb)")

	// XXE command
	vulnCmd.AddCommand(vulnXXECmd)
	vulnXXECmd.Flags().IntP("timeout", "t", 10, "Request timeout in seconds")
	vulnXXECmd.Flags().BoolP("insecure", "k", false, "Skip TLS verification")
	vulnXXECmd.Flags().StringP("user-agent", "A", "", "User-Agent string")
	vulnXXECmd.Flags().String("oob", "", "Out-of-band callback URL for blind XXE")
	vulnXXECmd.Flags().String("payload", "", "Payload type (file, oob, error)")

	// GraphQL command
	vulnCmd.AddCommand(vulnGraphQLCmd)
	vulnGraphQLCmd.Flags().IntP("timeout", "t", 10, "Request timeout in seconds")
	vulnGraphQLCmd.Flags().BoolP("insecure", "k", false, "Skip TLS verification")
	vulnGraphQLCmd.Flags().StringP("user-agent", "A", "", "User-Agent string")
	vulnGraphQLCmd.Flags().Bool("introspect", false, "Focus on introspection testing")
	vulnGraphQLCmd.Flags().Bool("dos", false, "Test for DoS via query batching/nesting")

	// Host Header command
	vulnCmd.AddCommand(vulnHostCmd)
	vulnHostCmd.Flags().IntP("timeout", "t", 10, "Request timeout in seconds")
	vulnHostCmd.Flags().BoolP("insecure", "k", false, "Skip TLS verification")
	vulnHostCmd.Flags().StringP("user-agent", "A", "", "User-Agent string")
	vulnHostCmd.Flags().Bool("poison", false, "Test password reset poisoning")
	vulnHostCmd.Flags().Bool("cache", false, "Test web cache poisoning")

	// Race Condition command
	vulnCmd.AddCommand(vulnRaceCmd)
	vulnRaceCmd.Flags().IntP("timeout", "t", 30, "Request timeout in seconds")
	vulnRaceCmd.Flags().BoolP("insecure", "k", false, "Skip TLS verification")
	vulnRaceCmd.Flags().StringP("user-agent", "A", "", "User-Agent string")
	vulnRaceCmd.Flags().StringP("cookie", "b", "", "Cookie string")
	vulnRaceCmd.Flags().StringP("data", "d", "", "POST data")
	vulnRaceCmd.Flags().StringP("method", "X", "POST", "HTTP method")
	vulnRaceCmd.Flags().Int("requests", 10, "Number of concurrent requests")
}
