package cmd

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"raxuiscli/internal/cookie"
)

var cookieCmd = &cobra.Command{
	Use:   "cookie",
	Short: "Cookie decoding and analysis",
	Long: `Decode and analyze HTTP cookies.

Supports various encoding formats and framework-specific session cookies.

Examples:
  raxuiscli cookie decode "session=abc123"
  raxuiscli cookie analyze "name=value; HttpOnly; Secure"
  raxuiscli cookie flask ".eJw..." --secret "key"`,
}

var cookieDecodeCmd = &cobra.Command{
	Use:   "decode [value]",
	Short: "Decode cookie value",
	Long: `Decode and analyze a cookie value.

Automatically detects and decodes:
- Base64 encoding
- URL encoding
- Hex encoding
- Compressed data (gzip/zlib)
- JSON data
- Framework-specific sessions (Flask, Express, Django, etc.)

Examples:
  raxuiscli cookie decode "eyJhZG1pbiI6dHJ1ZX0="
  raxuiscli cookie decode "name=value"
  raxuiscli cookie decode "%7B%22user%22%3A%22admin%22%7D"`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			fmt.Println("Please provide a cookie value to decode")
			return
		}

		value := args[0]

		// If it's a name=value pair, extract the value (but not if it looks like base64)
		if strings.Contains(value, "=") && !strings.Contains(value, ";") && !strings.HasSuffix(value, "=") && !strings.HasSuffix(value, "==") {
			parts := strings.SplitN(value, "=", 2)
			if len(parts) == 2 && len(parts[0]) < 50 && !strings.ContainsAny(parts[0], "+/") {
				fmt.Printf("Cookie name: %s\n", parts[0])
				value = parts[1]
			}
		}

		decoded := cookie.DecodeCookieValue(value)
		cookie.DisplayDecodedCookie(decoded)
	},
}

var cookieAnalyzeCmd = &cobra.Command{
	Use:   "analyze [cookie-string]",
	Short: "Analyze cookie security",
	Long: `Analyze a cookie string for security issues.

Checks for:
- Missing Secure flag
- Missing HttpOnly flag
- Missing or weak SameSite attribute
- Sensitive data in cookie value
- Expired or long-lived cookies

Examples:
  raxuiscli cookie analyze "session=abc123; HttpOnly; Secure"
  raxuiscli cookie analyze "PHPSESSID=xxx; path=/"
  raxuiscli cookie analyze "user=admin; domain=.example.com"`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			fmt.Println("Please provide a cookie string to analyze")
			return
		}

		cookieStr := args[0]
		parsed := cookie.ParseCookieString(cookieStr)
		cookie.DisplayCookieInfo(parsed)
	},
}

var cookieFlaskCmd = &cobra.Command{
	Use:   "flask [session]",
	Short: "Decode Flask session cookie",
	Long: `Decode and analyze Flask/Werkzeug session cookies.

Flask sessions are signed but not encrypted, allowing the payload to be read.
Provide --secret to verify the signature.

Examples:
  raxuiscli cookie flask ".eJxNjDEOwCAIAP-C..."
  raxuiscli cookie flask ".eJxNjDEOwCAIAP-C..." --secret "development key"`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			fmt.Println("Please provide a Flask session cookie")
			return
		}

		sessionVal := args[0]
		secret, _ := cmd.Flags().GetString("secret")

		session, err := cookie.DecodeFlaskSession(sessionVal, secret)
		if err != nil {
			fmt.Printf("Error decoding Flask session: %v\n", err)
			return
		}

		cookie.DisplayFlaskSession(session)
	},
}

var cookieExpressCmd = &cobra.Command{
	Use:   "express [session]",
	Short: "Decode Express.js session cookie",
	Long: `Decode Express.js/Connect session cookies.

Express sessions typically start with "s:" followed by JSON data and a signature.

Examples:
  raxuiscli cookie express "s:%7B%22user%22%3A%22admin%22%7D.signature"
  raxuiscli cookie express "s:..." --secret "keyboard cat"`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			fmt.Println("Please provide an Express session cookie")
			return
		}

		sessionVal := args[0]
		secret, _ := cmd.Flags().GetString("secret")

		data, err := cookie.DecodeExpressSession(sessionVal, secret)
		if err != nil {
			fmt.Printf("Error decoding Express session: %v\n", err)
			return
		}

		fmt.Println("\n[EXPRESS SESSION]")
		fmt.Println(strings.Repeat("=", 60))

		fmt.Printf("\n[Session Data]\n")
		for key, value := range data {
			fmt.Printf("  %s: %v\n", key, value)
		}
	},
}

var cookieBulkCmd = &cobra.Command{
	Use:   "bulk [cookies...]",
	Short: "Analyze multiple cookies",
	Long: `Analyze multiple cookies at once.

Provide cookies as separate arguments or as a single string separated by semicolons.

Examples:
  raxuiscli cookie bulk "session=abc" "user=admin" "token=xyz"
  raxuiscli cookie bulk "session=abc; user=admin; token=xyz"`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			fmt.Println("Please provide cookie strings to analyze")
			return
		}

		var cookies []string

		// Parse cookies from arguments
		for _, arg := range args {
			// Split by semicolons if multiple cookies in one string
			parts := strings.Split(arg, ";")
			for _, part := range parts {
				part = strings.TrimSpace(part)
				if part != "" && strings.Contains(part, "=") {
					cookies = append(cookies, part)
				}
			}
		}

		if len(cookies) == 0 {
			fmt.Println("No valid cookies found")
			return
		}

		fmt.Printf("[BULK COOKIE ANALYSIS]\n")
		fmt.Println(strings.Repeat("=", 60))
		fmt.Printf("Found %d cookies to analyze\n", len(cookies))

		// Summary counters
		var totalIssues, critical, high, medium, low int

		for i, c := range cookies {
			parsed := cookie.ParseCookieString(c)

			fmt.Printf("\n[Cookie %d: %s]\n", i+1, parsed.Name)
			fmt.Printf("Value: %s\n", truncateCookie(parsed.Value, 40))

			if parsed.Encoding != "none" {
				fmt.Printf("Encoding: %s\n", parsed.Encoding)
			}

			// Count issues
			for _, issue := range parsed.Issues {
				totalIssues++
				switch issue.Severity {
				case "CRITICAL":
					critical++
				case "HIGH":
					high++
				case "MEDIUM":
					medium++
				case "LOW":
					low++
				}
			}

			if len(parsed.Issues) > 0 {
				fmt.Printf("Issues: %d\n", len(parsed.Issues))
				for _, issue := range parsed.Issues {
					fmt.Printf("  [%s] %s\n", issue.Severity, issue.Title)
				}
			} else {
				fmt.Println("Issues: None detected")
			}
		}

		// Summary
		fmt.Printf("\n[SUMMARY]\n")
		fmt.Println(strings.Repeat("-", 40))
		fmt.Printf("Total cookies: %d\n", len(cookies))
		fmt.Printf("Total issues: %d\n", totalIssues)
		if totalIssues > 0 {
			fmt.Printf("  Critical: %d\n", critical)
			fmt.Printf("  High: %d\n", high)
			fmt.Printf("  Medium: %d\n", medium)
			fmt.Printf("  Low: %d\n", low)
		}
	},
}

var cookieDetectCmd = &cobra.Command{
	Use:   "detect [value]",
	Short: "Detect session type",
	Long: `Detect the type/framework of a session cookie.

Supported types:
- Flask (Python)
- Express.js (Node.js)
- Django (Python)
- PHP Serialized
- JWT
- ASP.NET ViewState
- Rails

Examples:
  raxuiscli cookie detect ".eJx..."
  raxuiscli cookie detect "s:json.signature"`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			fmt.Println("Please provide a cookie value")
			return
		}

		value := args[0]
		sessionType := cookie.DetectSessionType(value)

		fmt.Println("\n[SESSION TYPE DETECTION]")
		fmt.Println(strings.Repeat("=", 60))
		fmt.Printf("Value: %s\n", truncateCookie(value, 50))
		fmt.Printf("Detected Type: %s\n", sessionType)

		// Provide additional info based on type
		switch sessionType {
		case "Flask":
			fmt.Println("\nFlask sessions use itsdangerous for signing.")
			fmt.Println("Use 'raxuiscli cookie flask' to decode the payload.")
		case "JWT":
			fmt.Println("\nThis appears to be a JWT token.")
			fmt.Println("Use 'raxuiscli jwt decode' for detailed analysis.")
		case "Express.js":
			fmt.Println("\nExpress.js sessions use connect/express-session.")
			fmt.Println("Use 'raxuiscli cookie express' to decode the payload.")
		case "Django (Pickle)":
			fmt.Println("\nDjango pickled sessions may contain serialized Python objects.")
			fmt.Println("Warning: Unpickling untrusted data is dangerous!")
		case "PHP Serialized":
			fmt.Println("\nPHP serialized data detected.")
			fmt.Println("Warning: Unserializing untrusted data can lead to RCE!")
		case "ASP.NET ViewState":
			fmt.Println("\nASP.NET ViewState detected.")
			fmt.Println("May contain encrypted/signed application state.")
		case "Rails":
			fmt.Println("\nRuby on Rails session detected.")
			fmt.Println("Uses MessageVerifier for signing.")
		}
	},
}

var cookieSensitiveCmd = &cobra.Command{
	Use:   "sensitive [value]",
	Short: "Check for sensitive data",
	Long: `Check cookie value for sensitive data patterns.

Detects:
- Email addresses
- IP addresses
- Credit card numbers
- Phone numbers
- API keys
- Passwords
- Tokens
- User IDs
- Admin flags

Examples:
  raxuiscli cookie sensitive "user=admin&role=superuser"
  raxuiscli cookie sensitive "eyJhZG1pbiI6dHJ1ZX0="`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			fmt.Println("Please provide a cookie value")
			return
		}

		value := args[0]
		decoded := cookie.DecodeCookieValue(value)

		fmt.Println("\n[SENSITIVE DATA CHECK]")
		fmt.Println(strings.Repeat("=", 60))
		fmt.Printf("Original: %s\n", truncateCookie(value, 50))

		if decoded.Encoding != "none" {
			fmt.Printf("Encoding: %s\n", decoded.Encoding)
			fmt.Printf("Decoded: %s\n", truncateCookie(decoded.Decoded, 50))
		}

		if len(decoded.Sensitive) == 0 {
			fmt.Println("\nNo sensitive data patterns detected.")
		} else {
			fmt.Printf("\n[FOUND %d SENSITIVE ITEMS]\n", len(decoded.Sensitive))
			for _, s := range decoded.Sensitive {
				fmt.Printf("\n  Type: %s\n", s.Type)
				fmt.Printf("  Value: %s\n", s.Value)
				fmt.Printf("  Risk: %s\n", s.Risk)
			}
		}
	},
}

func truncateCookie(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}

func init() {
	rootCmd.AddCommand(cookieCmd)

	// Decode command
	cookieCmd.AddCommand(cookieDecodeCmd)

	// Analyze command
	cookieCmd.AddCommand(cookieAnalyzeCmd)

	// Flask command
	cookieCmd.AddCommand(cookieFlaskCmd)
	cookieFlaskCmd.Flags().StringP("secret", "s", "", "Flask secret key for signature verification")

	// Express command
	cookieCmd.AddCommand(cookieExpressCmd)
	cookieExpressCmd.Flags().StringP("secret", "s", "", "Express secret key for signature verification")

	// Bulk command
	cookieCmd.AddCommand(cookieBulkCmd)

	// Detect command
	cookieCmd.AddCommand(cookieDetectCmd)

	// Sensitive command
	cookieCmd.AddCommand(cookieSensitiveCmd)
}
