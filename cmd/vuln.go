package cmd

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"raxuiscli/internal/vuln"
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
		if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
			url = "https://" + url
		}

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
		if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
			url = "https://" + url
		}

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
		if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
			url = "https://" + url
		}

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
		if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
			url = "https://" + url
		}

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
		if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
			url = "https://" + url
		}

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

Types: xss, sqli, lfi, cmdi, redirect

Examples:
  raxuiscli vuln payloads xss
  raxuiscli vuln payloads sqli --level 3`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			fmt.Println("Available payload types: xss, sqli, lfi, cmdi, redirect")
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
		default:
			fmt.Println("Unknown payload type. Available: xss, sqli, lfi, cmdi, redirect")
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

func init() {
	rootCmd.AddCommand(vulnCmd)

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
}
