package cmd

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	httplib "raxuiscli/internal/http"
)

var httpCmd = &cobra.Command{
	Use:   "http",
	Short: "HTTP request tools and security header analysis",
	Long: `Perform HTTP requests and analyze security headers.

Examples:
  raxuiscli http get https://example.com
  raxuiscli http post https://api.com --data '{"key":"value"}'
  raxuiscli http headers https://example.com`,
}

var httpGetCmd = &cobra.Command{
	Use:   "get [url]",
	Short: "Perform HTTP GET request",
	Long: `Perform an HTTP GET request.

Examples:
  raxuiscli http get https://example.com
  raxuiscli http get https://api.com --header "Authorization: Bearer token"
  raxuiscli http get https://example.com --follow`,
	Run: func(cmd *cobra.Command, args []string) {
		runHTTPRequest(cmd, args, "GET")
	},
}

var httpPostCmd = &cobra.Command{
	Use:   "post [url]",
	Short: "Perform HTTP POST request",
	Long: `Perform an HTTP POST request.

Examples:
  raxuiscli http post https://api.com --data '{"key":"value"}'
  raxuiscli http post https://example.com --data "user=test&pass=123"
  raxuiscli http post https://api.com -d @file.json`,
	Run: func(cmd *cobra.Command, args []string) {
		runHTTPRequest(cmd, args, "POST")
	},
}

var httpPutCmd = &cobra.Command{
	Use:   "put [url]",
	Short: "Perform HTTP PUT request",
	Run: func(cmd *cobra.Command, args []string) {
		runHTTPRequest(cmd, args, "PUT")
	},
}

var httpDeleteCmd = &cobra.Command{
	Use:   "delete [url]",
	Short: "Perform HTTP DELETE request",
	Run: func(cmd *cobra.Command, args []string) {
		runHTTPRequest(cmd, args, "DELETE")
	},
}

var httpHeadCmd = &cobra.Command{
	Use:   "head [url]",
	Short: "Perform HTTP HEAD request",
	Run: func(cmd *cobra.Command, args []string) {
		runHTTPRequest(cmd, args, "HEAD")
	},
}

var httpOptionsCmd = &cobra.Command{
	Use:   "options [url]",
	Short: "Perform HTTP OPTIONS request",
	Long: `Perform an HTTP OPTIONS request to check allowed methods.

Examples:
  raxuiscli http options https://api.com/endpoint`,
	Run: func(cmd *cobra.Command, args []string) {
		runHTTPRequest(cmd, args, "OPTIONS")
	},
}

var httpHeadersCmd = &cobra.Command{
	Use:   "headers [url]",
	Short: "Analyze security headers",
	Long: `Analyze HTTP response headers for security issues.

Checks for:
- Strict-Transport-Security (HSTS)
- Content-Security-Policy (CSP)
- X-Content-Type-Options
- X-Frame-Options
- Referrer-Policy
- Permissions-Policy
- And more...

Examples:
  raxuiscli http headers https://example.com
  raxuiscli http headers https://example.com --verbose`,
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
		verbose, _ := cmd.Flags().GetBool("verbose")

		opts := httplib.RequestOptions{
			Method:      "GET",
			URL:         url,
			Timeout:     timeout,
			Insecure:    insecure,
			FollowRedir: true,
		}

		resp, err := httplib.DoRequest(opts)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}

		if verbose {
			httplib.DisplayResponse(resp, false, 0)
		}

		analysis := httplib.AnalyzeSecurityHeaders(resp.Headers)
		httplib.DisplayHeaderAnalysis(analysis)

		// Detect technologies
		techs := httplib.DetectTechnology(resp.Headers, resp.Body)
		httplib.DisplayTechnologies(techs)
	},
}

var httpTraceCmd = &cobra.Command{
	Use:   "trace [url]",
	Short: "Trace redirects",
	Long: `Follow and display redirect chain.

Examples:
  raxuiscli http trace https://bit.ly/xxxxx
  raxuiscli http trace http://example.com`,
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

		opts := httplib.RequestOptions{
			Method:      "GET",
			URL:         url,
			Timeout:     timeout,
			Insecure:    insecure,
			FollowRedir: true,
		}

		resp, err := httplib.DoRequest(opts)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}

		fmt.Println("\n[REDIRECT TRACE]")
		fmt.Println(strings.Repeat("=", 60))

		fmt.Printf("\nOriginal URL: %s\n", url)

		if len(resp.RedirectChain) > 0 {
			fmt.Println("\nRedirect Chain:")
			for i, redirectURL := range resp.RedirectChain {
				fmt.Printf("  %d. %s\n", i+1, redirectURL)
			}
		} else {
			fmt.Println("\nNo redirects")
		}

		fmt.Printf("\nFinal Status: %s\n", resp.Status)
		fmt.Printf("Duration: %v\n", resp.Duration)
	},
}

var httpCurlCmd = &cobra.Command{
	Use:   "curl [url]",
	Short: "Generate curl command",
	Long: `Generate equivalent curl command for the request.

Examples:
  raxuiscli http curl https://api.com --method POST --data '{"key":"value"}'
  raxuiscli http curl https://example.com --header "Auth: token"`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			fmt.Println("Please provide a URL")
			return
		}

		url := args[0]
		method, _ := cmd.Flags().GetString("method")
		data, _ := cmd.Flags().GetString("data")
		headersSlice, _ := cmd.Flags().GetStringSlice("header")
		userAgent, _ := cmd.Flags().GetString("user-agent")
		cookie, _ := cmd.Flags().GetString("cookie")
		auth, _ := cmd.Flags().GetString("auth")
		insecure, _ := cmd.Flags().GetBool("insecure")
		proxy, _ := cmd.Flags().GetString("proxy")

		headers := make(map[string]string)
		for _, h := range headersSlice {
			parts := strings.SplitN(h, ":", 2)
			if len(parts) == 2 {
				headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
			}
		}

		opts := httplib.RequestOptions{
			Method:    method,
			URL:       url,
			Headers:   headers,
			Body:      data,
			UserAgent: userAgent,
			Cookie:    cookie,
			BasicAuth: auth,
			Insecure:  insecure,
			Proxy:     proxy,
		}

		curlCmd := httplib.GenerateCurl(opts)

		fmt.Println("\n[CURL COMMAND]")
		fmt.Println(strings.Repeat("=", 60))
		fmt.Println(curlCmd)
	},
}

func runHTTPRequest(cmd *cobra.Command, args []string, method string) {
	if len(args) == 0 {
		fmt.Println("Please provide a URL")
		return
	}

	url := args[0]
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		url = "https://" + url
	}

	data, _ := cmd.Flags().GetString("data")
	headersSlice, _ := cmd.Flags().GetStringSlice("header")
	userAgent, _ := cmd.Flags().GetString("user-agent")
	cookie, _ := cmd.Flags().GetString("cookie")
	auth, _ := cmd.Flags().GetString("auth")
	timeout, _ := cmd.Flags().GetInt("timeout")
	insecure, _ := cmd.Flags().GetBool("insecure")
	followRedir, _ := cmd.Flags().GetBool("follow")
	proxy, _ := cmd.Flags().GetString("proxy")
	showBody, _ := cmd.Flags().GetBool("body")
	maxBody, _ := cmd.Flags().GetInt("max-body")
	jsonFormat, _ := cmd.Flags().GetBool("json")

	headers := make(map[string]string)
	for _, h := range headersSlice {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}

	opts := httplib.RequestOptions{
		Method:      method,
		URL:         url,
		Headers:     headers,
		Body:        data,
		Timeout:     timeout,
		FollowRedir: followRedir,
		Insecure:    insecure,
		Proxy:       proxy,
		UserAgent:   userAgent,
		Cookie:      cookie,
		BasicAuth:   auth,
	}

	resp, err := httplib.DoRequest(opts)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	// Format JSON if requested
	if jsonFormat && strings.Contains(resp.Headers.Get("Content-Type"), "json") {
		resp.Body = httplib.FormatJSON(resp.Body)
	}

	httplib.DisplayResponse(resp, showBody, maxBody)

	// Show curl equivalent
	showCurl, _ := cmd.Flags().GetBool("curl")
	if showCurl {
		fmt.Printf("\n[Curl Equivalent]\n%s\n", httplib.GenerateCurl(opts))
	}
}

func init() {
	rootCmd.AddCommand(httpCmd)

	// Common flags for request commands
	requestFlags := func(cmd *cobra.Command) {
		cmd.Flags().StringP("data", "d", "", "Request body data")
		cmd.Flags().StringSliceP("header", "H", nil, "Custom headers (can be used multiple times)")
		cmd.Flags().StringP("user-agent", "A", "", "User-Agent string")
		cmd.Flags().StringP("cookie", "b", "", "Cookie string")
		cmd.Flags().String("auth", "", "Basic auth (user:pass)")
		cmd.Flags().IntP("timeout", "t", 10, "Request timeout in seconds")
		cmd.Flags().BoolP("insecure", "k", false, "Skip TLS verification")
		cmd.Flags().BoolP("follow", "L", false, "Follow redirects")
		cmd.Flags().String("proxy", "", "Proxy URL")
		cmd.Flags().Bool("body", true, "Show response body")
		cmd.Flags().Int("max-body", 5000, "Max body length to display (0 for unlimited)")
		cmd.Flags().Bool("json", false, "Format JSON response")
		cmd.Flags().Bool("curl", false, "Show curl equivalent")
	}

	// GET command
	httpCmd.AddCommand(httpGetCmd)
	requestFlags(httpGetCmd)

	// POST command
	httpCmd.AddCommand(httpPostCmd)
	requestFlags(httpPostCmd)

	// PUT command
	httpCmd.AddCommand(httpPutCmd)
	requestFlags(httpPutCmd)

	// DELETE command
	httpCmd.AddCommand(httpDeleteCmd)
	requestFlags(httpDeleteCmd)

	// HEAD command
	httpCmd.AddCommand(httpHeadCmd)
	requestFlags(httpHeadCmd)

	// OPTIONS command
	httpCmd.AddCommand(httpOptionsCmd)
	requestFlags(httpOptionsCmd)

	// Headers analysis command
	httpCmd.AddCommand(httpHeadersCmd)
	httpHeadersCmd.Flags().IntP("timeout", "t", 10, "Request timeout in seconds")
	httpHeadersCmd.Flags().BoolP("insecure", "k", false, "Skip TLS verification")
	httpHeadersCmd.Flags().BoolP("verbose", "v", false, "Show full response")

	// Trace command
	httpCmd.AddCommand(httpTraceCmd)
	httpTraceCmd.Flags().IntP("timeout", "t", 10, "Request timeout in seconds")
	httpTraceCmd.Flags().BoolP("insecure", "k", false, "Skip TLS verification")

	// Curl generator command
	httpCmd.AddCommand(httpCurlCmd)
	httpCurlCmd.Flags().StringP("method", "X", "GET", "HTTP method")
	httpCurlCmd.Flags().StringP("data", "d", "", "Request body data")
	httpCurlCmd.Flags().StringSliceP("header", "H", nil, "Custom headers")
	httpCurlCmd.Flags().StringP("user-agent", "A", "", "User-Agent string")
	httpCurlCmd.Flags().StringP("cookie", "b", "", "Cookie string")
	httpCurlCmd.Flags().String("auth", "", "Basic auth (user:pass)")
	httpCurlCmd.Flags().BoolP("insecure", "k", false, "Skip TLS verification")
	httpCurlCmd.Flags().String("proxy", "", "Proxy URL")
}
