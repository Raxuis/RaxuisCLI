package cmd

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"raxuiscli/internal/web/fuzz"
)

var fuzzCmd = &cobra.Command{
	Use:   "fuzz",
	Short: "Web fuzzing tools (directory, parameter, vhost)",
	Long: `Perform fuzzing operations on web applications.

Supports directory enumeration, parameter discovery, and virtual host fuzzing.

Examples:
  raxuiscli fuzz dir https://example.com --wordlist dirs.txt
  raxuiscli fuzz param https://example.com/search?q=FUZZ --wordlist params.txt
  raxuiscli fuzz vhost https://example.com --wordlist vhosts.txt`,
}

var fuzzDirCmd = &cobra.Command{
	Use:   "dir [url]",
	Short: "Directory/file brute force",
	Long: `Brute force directories and files on a web server.

Examples:
  raxuiscli fuzz dir https://example.com --wordlist dirs.txt
  raxuiscli fuzz dir https://example.com -w dirs.txt -e php,html,txt
  raxuiscli fuzz dir https://example.com --common
  raxuiscli fuzz dir https://example.com -w dirs.txt --threads 20`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			fmt.Println("Please provide a URL")
			return
		}

		url := args[0]
		if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
			url = "https://" + url
		}

		wordlist, _ := cmd.Flags().GetString("wordlist")
		useCommon, _ := cmd.Flags().GetBool("common")
		extensions, _ := cmd.Flags().GetStringSlice("extensions")
		threads, _ := cmd.Flags().GetInt("threads")
		timeout, _ := cmd.Flags().GetInt("timeout")
		userAgent, _ := cmd.Flags().GetString("user-agent")
		cookie, _ := cmd.Flags().GetString("cookie")
		filterStatus, _ := cmd.Flags().GetIntSlice("filter-status")
		filterSize, _ := cmd.Flags().GetIntSlice("filter-size")
		matchStatus, _ := cmd.Flags().GetIntSlice("match-status")
		followRedir, _ := cmd.Flags().GetBool("follow")
		insecure, _ := cmd.Flags().GetBool("insecure")
		rateLimit, _ := cmd.Flags().GetInt("rate")

		var words []string
		var err error

		if useCommon {
			words = fuzz.CommonDirectories()
			fmt.Printf("Using %d common directories\n", len(words))
		} else if wordlist != "" {
			words, err = fuzz.LoadWordlist(wordlist)
			if err != nil {
				fmt.Printf("Error loading wordlist: %v\n", err)
				return
			}
			fmt.Printf("Loaded %d words from wordlist\n", len(words))
		} else {
			fmt.Println("Please provide --wordlist or --common flag")
			return
		}

		opts := fuzz.FuzzOptions{
			Type:         fuzz.FuzzDir,
			URL:          url,
			Words:        words,
			Threads:      threads,
			Timeout:      timeout,
			UserAgent:    userAgent,
			Cookie:       cookie,
			Extensions:   extensions,
			FilterStatus: filterStatus,
			FilterSize:   filterSize,
			MatchStatus:  matchStatus,
			FollowRedir:  followRedir,
			Insecure:     insecure,
			RateLimit:    rateLimit,
		}

		runFuzzer(opts, fuzz.FuzzDirectory)
	},
}

var fuzzParamCmd = &cobra.Command{
	Use:   "param [url]",
	Short: "Parameter discovery",
	Long: `Discover hidden parameters in web applications.

The URL should contain the base endpoint. Parameters will be appended.

Examples:
  raxuiscli fuzz param https://example.com/api --wordlist params.txt
  raxuiscli fuzz param https://example.com/search --common
  raxuiscli fuzz param "https://example.com/page?id=1" --wordlist params.txt`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			fmt.Println("Please provide a URL")
			return
		}

		url := args[0]
		if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
			url = "https://" + url
		}

		wordlist, _ := cmd.Flags().GetString("wordlist")
		useCommon, _ := cmd.Flags().GetBool("common")
		threads, _ := cmd.Flags().GetInt("threads")
		timeout, _ := cmd.Flags().GetInt("timeout")
		userAgent, _ := cmd.Flags().GetString("user-agent")
		cookie, _ := cmd.Flags().GetString("cookie")
		filterStatus, _ := cmd.Flags().GetIntSlice("filter-status")
		filterSize, _ := cmd.Flags().GetIntSlice("filter-size")
		matchStatus, _ := cmd.Flags().GetIntSlice("match-status")
		followRedir, _ := cmd.Flags().GetBool("follow")
		insecure, _ := cmd.Flags().GetBool("insecure")
		rateLimit, _ := cmd.Flags().GetInt("rate")
		method, _ := cmd.Flags().GetString("method")
		data, _ := cmd.Flags().GetString("data")

		var words []string
		var err error

		if useCommon {
			words = fuzz.CommonParams()
			fmt.Printf("Using %d common parameters\n", len(words))
		} else if wordlist != "" {
			words, err = fuzz.LoadWordlist(wordlist)
			if err != nil {
				fmt.Printf("Error loading wordlist: %v\n", err)
				return
			}
			fmt.Printf("Loaded %d words from wordlist\n", len(words))
		} else {
			fmt.Println("Please provide --wordlist or --common flag")
			return
		}

		opts := fuzz.FuzzOptions{
			Type:         fuzz.FuzzParam,
			URL:          url,
			Words:        words,
			Threads:      threads,
			Timeout:      timeout,
			UserAgent:    userAgent,
			Cookie:       cookie,
			FilterStatus: filterStatus,
			FilterSize:   filterSize,
			MatchStatus:  matchStatus,
			FollowRedir:  followRedir,
			Insecure:     insecure,
			RateLimit:    rateLimit,
			Method:       method,
			Data:         data,
		}

		runFuzzer(opts, fuzz.FuzzParameter)
	},
}

var fuzzVhostCmd = &cobra.Command{
	Use:   "vhost [url]",
	Short: "Virtual host discovery",
	Long: `Discover virtual hosts by fuzzing the Host header.

Examples:
  raxuiscli fuzz vhost https://10.10.10.10 --wordlist vhosts.txt
  raxuiscli fuzz vhost https://target.com --wordlist subdomains.txt`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			fmt.Println("Please provide a URL")
			return
		}

		url := args[0]
		if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
			url = "https://" + url
		}

		wordlist, _ := cmd.Flags().GetString("wordlist")
		domain, _ := cmd.Flags().GetString("domain")
		threads, _ := cmd.Flags().GetInt("threads")
		timeout, _ := cmd.Flags().GetInt("timeout")
		userAgent, _ := cmd.Flags().GetString("user-agent")
		filterStatus, _ := cmd.Flags().GetIntSlice("filter-status")
		filterSize, _ := cmd.Flags().GetIntSlice("filter-size")
		insecure, _ := cmd.Flags().GetBool("insecure")
		rateLimit, _ := cmd.Flags().GetInt("rate")

		if wordlist == "" {
			fmt.Println("Please provide a wordlist with --wordlist")
			return
		}

		words, err := fuzz.LoadWordlist(wordlist)
		if err != nil {
			fmt.Printf("Error loading wordlist: %v\n", err)
			return
		}

		// Append domain suffix if provided
		if domain != "" {
			for i, word := range words {
				if !strings.Contains(word, ".") {
					words[i] = word + "." + domain
				}
			}
		}

		fmt.Printf("Loaded %d vhosts to test\n", len(words))

		opts := fuzz.FuzzOptions{
			Type:         fuzz.FuzzVhost,
			URL:          url,
			Words:        words,
			Threads:      threads,
			Timeout:      timeout,
			UserAgent:    userAgent,
			FilterStatus: filterStatus,
			FilterSize:   filterSize,
			Insecure:     insecure,
			RateLimit:    rateLimit,
		}

		runFuzzer(opts, fuzz.FuzzVirtualHost)
	},
}

func runFuzzer(opts fuzz.FuzzOptions, fuzzerFunc func(fuzz.FuzzOptions, chan<- fuzz.FuzzResult, chan<- bool)) {
	resultChan := make(chan fuzz.FuzzResult, 100)
	doneChan := make(chan bool)

	results := &fuzz.FuzzResults{
		Type:    opts.Type,
		BaseURL: opts.URL,
		Total:   len(opts.Words),
	}

	// Start fuzzer
	start := time.Now()
	go fuzzerFunc(opts, resultChan, doneChan)

	// Collect results
	processed := 0
	lastUpdate := time.Now()

	for {
		select {
		case result := <-resultChan:
			if result.Error != nil {
				results.Errors++
			} else {
				results.Found++
				results.Results = append(results.Results, result)
			}
			processed++

			// Update progress every 100ms
			if time.Since(lastUpdate) > 100*time.Millisecond {
				elapsed := time.Since(start).Seconds()
				rate := float64(processed) / elapsed
				fuzz.DisplayProgress(processed, results.Total, results.Found, rate)
				lastUpdate = time.Now()
			}

		case <-doneChan:
			results.Duration = time.Since(start)
			fmt.Println() // New line after progress
			fuzz.DisplayResults(results)
			return
		}
	}
}

func init() {
	rootCmd.AddCommand(fuzzCmd)

	// Common flags
	commonFlags := func(cmd *cobra.Command) {
		cmd.Flags().StringP("wordlist", "w", "", "Wordlist file")
		cmd.Flags().IntP("threads", "t", 10, "Number of concurrent threads")
		cmd.Flags().Int("timeout", 10, "Request timeout in seconds")
		cmd.Flags().StringP("user-agent", "A", "", "User-Agent string")
		cmd.Flags().StringP("cookie", "b", "", "Cookie string")
		cmd.Flags().IntSlice("filter-status", nil, "Filter out status codes (e.g., --filter-status 404,403)")
		cmd.Flags().IntSlice("filter-size", nil, "Filter out response sizes")
		cmd.Flags().IntSlice("match-status", nil, "Only show these status codes")
		cmd.Flags().BoolP("insecure", "k", false, "Skip TLS verification")
		cmd.Flags().Int("rate", 0, "Rate limit (requests per second, 0 = unlimited)")
	}

	// Dir command
	fuzzCmd.AddCommand(fuzzDirCmd)
	commonFlags(fuzzDirCmd)
	fuzzDirCmd.Flags().Bool("common", false, "Use common directory list")
	fuzzDirCmd.Flags().StringSliceP("extensions", "e", nil, "File extensions to append (e.g., -e php,html)")
	fuzzDirCmd.Flags().BoolP("follow", "L", false, "Follow redirects")

	// Param command
	fuzzCmd.AddCommand(fuzzParamCmd)
	commonFlags(fuzzParamCmd)
	fuzzParamCmd.Flags().Bool("common", false, "Use common parameter list")
	fuzzParamCmd.Flags().BoolP("follow", "L", false, "Follow redirects")
	fuzzParamCmd.Flags().StringP("method", "X", "GET", "HTTP method")
	fuzzParamCmd.Flags().StringP("data", "d", "", "POST data")

	// Vhost command
	fuzzCmd.AddCommand(fuzzVhostCmd)
	commonFlags(fuzzVhostCmd)
	fuzzVhostCmd.Flags().StringP("domain", "d", "", "Append domain suffix to wordlist entries")
}
