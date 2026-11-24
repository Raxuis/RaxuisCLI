package web

import (
	"fmt"
	"io"
	"strings"

	"github.com/Raxuis/RaxuisCLI/cmd"

	"github.com/spf13/cobra"

	"github.com/Raxuis/RaxuisCLI/internal/shared/output"
	"github.com/Raxuis/RaxuisCLI/internal/web/cookie"
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
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return fmt.Errorf("please provide a cookie value to decode")
		}

		value := args[0]
		cookieName := ""

		// If it's a name=value pair, extract the value (but not if it looks like base64)
		if strings.Contains(value, "=") && !strings.Contains(value, ";") && !strings.HasSuffix(value, "=") && !strings.HasSuffix(value, "==") {
			parts := strings.SplitN(value, "=", 2)
			if len(parts) == 2 && len(parts[0]) < 50 && !strings.ContainsAny(parts[0], "+/") {
				cookieName = parts[0]
				value = parts[1]
			}
		}

		decoded := cookie.DecodeCookieValue(value)
		return output.Emit(map[string]any{"name": cookieName, "decoded": decoded}, func(io.Writer) {
			if cookieName != "" {
				fmt.Fprintf(output.Std, "Cookie name: %s\n", cookieName)
			}
			cookie.DisplayDecodedCookie(decoded)
		})
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
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return fmt.Errorf("please provide a cookie string to analyze")
		}

		cookieStr := args[0]
		if !strings.Contains(cookieStr, "=") || strings.TrimSpace(strings.SplitN(cookieStr, "=", 2)[0]) == "" {
			return fmt.Errorf("provide a cookie as name=value")
		}
		parsed := cookie.ParseCookieString(cookieStr)
		if output.JSON() {
			return output.Emit(parsed, func(io.Writer) {})
		}
		cookie.DisplayCookieInfo(parsed)
		return nil
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
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return fmt.Errorf("please provide a Flask session cookie")
		}

		sessionVal := args[0]
		secret, _ := cmd.Flags().GetString("secret")

		session, err := cookie.DecodeFlaskSession(sessionVal, secret)
		if err != nil {
			return fmt.Errorf("decoding Flask session: %w", err)
		}

		return output.Emit(session, func(io.Writer) { cookie.DisplayFlaskSession(session) })
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
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return fmt.Errorf("please provide an Express session cookie")
		}

		sessionVal := args[0]
		secret, _ := cmd.Flags().GetString("secret")

		data, err := cookie.DecodeExpressSession(sessionVal, secret)
		if err != nil {
			return fmt.Errorf("decoding Express session: %w", err)
		}

		return output.Emit(data, func(io.Writer) {
			fmt.Fprintln(output.Std, "\n[EXPRESS SESSION]")
			fmt.Fprintln(output.Std, strings.Repeat("=", 60))

			fmt.Fprintf(output.Std, "\n[Session Data]\n")
			for key, value := range data {
				fmt.Fprintf(output.Std, "  %s: %v\n", key, value)
			}
		})
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
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return fmt.Errorf("please provide cookie strings to analyze")
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
			return fmt.Errorf("no valid cookies found")
		}

		if output.JSON() {
			parsed := make([]*cookie.CookieInfo, 0, len(cookies))
			for _, c := range cookies {
				parsed = append(parsed, cookie.ParseCookieString(c))
			}
			return output.Emit(map[string]any{"cookies": parsed, "count": len(parsed)}, func(io.Writer) {})
		}
		fmt.Fprintf(output.Std, "[BULK COOKIE ANALYSIS]\n")
		fmt.Fprintln(output.Std, strings.Repeat("=", 60))
		fmt.Fprintf(output.Std, "Found %d cookies to analyze\n", len(cookies))

		// Summary counters
		var totalIssues, critical, high, medium, low int

		for i, c := range cookies {
			parsed := cookie.ParseCookieString(c)

			fmt.Fprintf(output.Std, "\n[Cookie %d: %s]\n", i+1, parsed.Name)
			fmt.Fprintf(output.Std, "Value: %s\n", truncateCookie(parsed.Value, 40))

			if parsed.Encoding != "none" {
				fmt.Fprintf(output.Std, "Encoding: %s\n", parsed.Encoding)
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
				fmt.Fprintf(output.Std, "Issues: %d\n", len(parsed.Issues))
				for _, issue := range parsed.Issues {
					fmt.Fprintf(output.Std, "  [%s] %s\n", issue.Severity, issue.Title)
				}
			} else {
				fmt.Fprintln(output.Std, "Issues: None detected")
			}
		}

		// Summary
		fmt.Fprintf(output.Std, "\n[SUMMARY]\n")
		fmt.Fprintln(output.Std, strings.Repeat("-", 40))
		fmt.Fprintf(output.Std, "Total cookies: %d\n", len(cookies))
		fmt.Fprintf(output.Std, "Total issues: %d\n", totalIssues)
		if totalIssues > 0 {
			fmt.Fprintf(output.Std, "  Critical: %d\n", critical)
			fmt.Fprintf(output.Std, "  High: %d\n", high)
			fmt.Fprintf(output.Std, "  Medium: %d\n", medium)
			fmt.Fprintf(output.Std, "  Low: %d\n", low)
		}
		return nil
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
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return fmt.Errorf("please provide a cookie value")
		}

		value := args[0]
		sessionType := cookie.DetectSessionType(value)

		if output.JSON() {
			return output.Emit(map[string]any{"value": value, "detected_type": sessionType}, func(io.Writer) {})
		}

		fmt.Fprintln(output.Std, "\n[SESSION TYPE DETECTION]")
		fmt.Fprintln(output.Std, strings.Repeat("=", 60))
		fmt.Fprintf(output.Std, "Value: %s\n", truncateCookie(value, 50))
		fmt.Fprintf(output.Std, "Detected Type: %s\n", sessionType)

		// Provide additional info based on type
		switch sessionType {
		case "Flask":
			fmt.Fprintln(output.Std, "\nFlask sessions use itsdangerous for signing.")
			fmt.Fprintln(output.Std, "Use 'raxuiscli cookie flask' to decode the payload.")
		case "JWT":
			fmt.Fprintln(output.Std, "\nThis appears to be a JWT token.")
			fmt.Fprintln(output.Std, "Use 'raxuiscli jwt decode' for detailed analysis.")
		case "Express.js":
			fmt.Fprintln(output.Std, "\nExpress.js sessions use connect/express-session.")
			fmt.Fprintln(output.Std, "Use 'raxuiscli cookie express' to decode the payload.")
		case "Django (Pickle)":
			fmt.Fprintln(output.Std, "\nDjango pickled sessions may contain serialized Python objects.")
			fmt.Fprintln(output.Std, "Warning: Unpickling untrusted data is dangerous!")
		case "PHP Serialized":
			fmt.Fprintln(output.Std, "\nPHP serialized data detected.")
			fmt.Fprintln(output.Std, "Warning: Unserializing untrusted data can lead to RCE!")
		case "ASP.NET ViewState":
			fmt.Fprintln(output.Std, "\nASP.NET ViewState detected.")
			fmt.Fprintln(output.Std, "May contain encrypted/signed application state.")
		case "Rails":
			fmt.Fprintln(output.Std, "\nRuby on Rails session detected.")
			fmt.Fprintln(output.Std, "Uses MessageVerifier for signing.")
		}
		return nil
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
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return fmt.Errorf("please provide a cookie value")
		}

		value := args[0]
		decoded := cookie.DecodeCookieValue(value)

		if output.JSON() {
			return output.Emit(decoded, func(io.Writer) {})
		}
		fmt.Fprintln(output.Std, "\n[SENSITIVE DATA CHECK]")
		fmt.Fprintln(output.Std, strings.Repeat("=", 60))
		fmt.Fprintf(output.Std, "Original: %s\n", truncateCookie(value, 50))

		if decoded.Encoding != "none" {
			fmt.Fprintf(output.Std, "Encoding: %s\n", decoded.Encoding)
			fmt.Fprintf(output.Std, "Decoded: %s\n", truncateCookie(decoded.Decoded, 50))
		}

		if len(decoded.Sensitive) == 0 {
			fmt.Fprintln(output.Std, "\nNo sensitive data patterns detected.")
		} else {
			fmt.Fprintf(output.Std, "\n[FOUND %d SENSITIVE ITEMS]\n", len(decoded.Sensitive))
			for _, s := range decoded.Sensitive {
				fmt.Fprintf(output.Std, "\n  Type: %s\n", s.Type)
				fmt.Fprintf(output.Std, "  Value: %s\n", s.Value)
				fmt.Fprintf(output.Std, "  Risk: %s\n", s.Risk)
			}
		}
		return nil
	},
}

func truncateCookie(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}

func init() {
	cmd.RootCmd.AddCommand(cookieCmd)

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
