package cookie

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode"
)

// CookieInfo holds parsed cookie information
type CookieInfo struct {
	Name       string
	Value      string
	Domain     string
	Path       string
	Expires    time.Time
	MaxAge     int
	Secure     bool
	HttpOnly   bool
	SameSite   string
	RawValue   string
	DecodedVal string
	Encoding   string
	Issues     []SecurityIssue
}

// SecurityIssue represents a cookie security issue
type SecurityIssue struct {
	Severity    string // CRITICAL, HIGH, MEDIUM, LOW, INFO
	Title       string
	Description string
	Remediation string
}

// FlaskSession holds decoded Flask session data
type FlaskSession struct {
	Payload   map[string]interface{}
	Timestamp time.Time
	Signature string
	Valid     bool
}

// DecodedCookie holds decoded cookie data
type DecodedCookie struct {
	Original    string
	Decoded     string
	Encoding    string
	IsJSON      bool
	JSONData    interface{}
	Sensitive   []SensitiveData
	SessionType string
}

// SensitiveData represents potentially sensitive data found in cookie
type SensitiveData struct {
	Type  string
	Value string
	Risk  string
}

// ParseCookieString parses a cookie string into CookieInfo
func ParseCookieString(cookieStr string) *CookieInfo {
	cookie := &CookieInfo{
		RawValue: cookieStr,
	}

	parts := strings.Split(cookieStr, ";")
	if len(parts) == 0 {
		return cookie
	}

	// First part is name=value
	nameValue := strings.SplitN(strings.TrimSpace(parts[0]), "=", 2)
	if len(nameValue) >= 1 {
		cookie.Name = nameValue[0]
	}
	if len(nameValue) >= 2 {
		cookie.Value = nameValue[1]
	}

	// Parse attributes
	for _, part := range parts[1:] {
		part = strings.TrimSpace(part)
		kv := strings.SplitN(part, "=", 2)
		key := strings.ToLower(kv[0])
		value := ""
		if len(kv) > 1 {
			value = kv[1]
		}

		switch key {
		case "domain":
			cookie.Domain = value
		case "path":
			cookie.Path = value
		case "expires":
			if t, err := time.Parse(time.RFC1123, value); err == nil {
				cookie.Expires = t
			}
		case "max-age":
			_, _ = fmt.Sscanf(value, "%d", &cookie.MaxAge)
		case "secure":
			cookie.Secure = true
		case "httponly":
			cookie.HttpOnly = true
		case "samesite":
			cookie.SameSite = value
		}
	}

	// Decode value
	decoded := DecodeCookieValue(cookie.Value)
	cookie.DecodedVal = decoded.Decoded
	cookie.Encoding = decoded.Encoding

	// Analyze security
	cookie.Issues = AnalyzeCookieSecurity(cookie)

	return cookie
}

// DecodeCookieValue attempts to decode a cookie value
func DecodeCookieValue(value string) *DecodedCookie {
	result := &DecodedCookie{
		Original: value,
		Decoded:  value,
		Encoding: "none",
	}

	// Try URL decoding
	if urlDecoded, err := url.QueryUnescape(value); err == nil && urlDecoded != value {
		result.Decoded = urlDecoded
		result.Encoding = "URL"
		value = urlDecoded
	}

	// Try Base64 decoding
	if decoded, err := base64.StdEncoding.DecodeString(value); err == nil && isPrintable(string(decoded)) {
		result.Decoded = string(decoded)
		result.Encoding = "Base64"
		value = string(decoded)
	} else if decoded, err := base64.URLEncoding.DecodeString(value); err == nil && isPrintable(string(decoded)) {
		result.Decoded = string(decoded)
		result.Encoding = "Base64-URL"
		value = string(decoded)
	} else if decoded, err := base64.RawURLEncoding.DecodeString(value); err == nil && isPrintable(string(decoded)) {
		result.Decoded = string(decoded)
		result.Encoding = "Base64-URL-Raw"
		value = string(decoded)
	}

	// Try hex decoding
	if decoded, err := hex.DecodeString(value); err == nil && isPrintable(string(decoded)) {
		result.Decoded = string(decoded)
		result.Encoding = "Hex"
	}

	// Try to decompress (gzip/zlib)
	if compressed, _ := base64.StdEncoding.DecodeString(result.Original); len(compressed) > 0 {
		if decompressed := tryDecompress(compressed); decompressed != "" {
			result.Decoded = decompressed
			result.Encoding = "Base64+Compressed"
		}
	}

	// Check if JSON
	var jsonData interface{}
	if err := json.Unmarshal([]byte(result.Decoded), &jsonData); err == nil {
		result.IsJSON = true
		result.JSONData = jsonData
	}

	// Detect session type
	result.SessionType = DetectSessionType(result.Original)

	// Find sensitive data
	result.Sensitive = FindSensitiveData(result.Decoded)

	return result
}

// DetectSessionType tries to identify the session cookie type
func DetectSessionType(value string) string {
	// Flask session (starts with . and has base64-like payload)
	if strings.HasPrefix(value, ".") {
		// Check for Flask itsdangerous format: .payload.timestamp.signature or .payload.signature
		if strings.Count(value, ".") >= 2 {
			return "Flask"
		}
		// Also check if it starts with .eJ (compressed zlib base64)
		if len(value) > 3 && (strings.HasPrefix(value[1:], "eJ") || strings.HasPrefix(value[1:], "ey")) {
			return "Flask"
		}
	}

	// Django session
	if strings.HasPrefix(value, "gAJ") || strings.HasPrefix(value, "gAN") {
		return "Django (Pickle)"
	}

	// PHP serialized
	if regexp.MustCompile(`^[aOis]:\d+`).MatchString(value) {
		return "PHP Serialized"
	}

	// JWT-like (3 base64 parts)
	if strings.Count(value, ".") == 2 {
		parts := strings.Split(value, ".")
		allBase64 := true
		for _, p := range parts {
			if _, err := base64.RawURLEncoding.DecodeString(p); err != nil {
				allBase64 = false
				break
			}
		}
		if allBase64 {
			return "JWT"
		}
	}

	// ASP.NET ViewState
	if strings.HasPrefix(value, "/wE") {
		return "ASP.NET ViewState"
	}

	// Express session
	if strings.HasPrefix(value, "s:") && strings.Contains(value, ".") {
		return "Express.js"
	}

	// Rails session
	if strings.Contains(value, "--") && len(value) > 40 {
		return "Rails"
	}

	return "Unknown"
}

// DecodeFlaskSession decodes a Flask session cookie
func DecodeFlaskSession(value string, secret string) (*FlaskSession, error) {
	session := &FlaskSession{}

	// Flask format: base64(payload).timestamp.signature
	// or: .base64(compressed_payload).timestamp.signature

	parts := strings.Split(value, ".")
	if len(parts) < 3 {
		return nil, fmt.Errorf("invalid Flask session format")
	}

	// Handle compressed sessions (start with .)
	payloadIdx := 0
	if value[0] == '.' {
		payloadIdx = 1
	}

	// Decode payload
	payload := parts[payloadIdx]
	decoded, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		// Try with padding
		payload = payload + strings.Repeat("=", (4-len(payload)%4)%4)
		decoded, err = base64.StdEncoding.DecodeString(payload)
		if err != nil {
			return nil, fmt.Errorf("failed to decode payload: %v", err)
		}
	}

	// Try decompression
	if decompressed := tryDecompress(decoded); decompressed != "" {
		decoded = []byte(decompressed)
	}

	// Parse JSON payload
	if err := json.Unmarshal(decoded, &session.Payload); err != nil {
		return nil, fmt.Errorf("failed to parse payload: %v", err)
	}

	// Get timestamp
	if len(parts) > payloadIdx+1 {
		tsBase64 := parts[payloadIdx+1]
		if tsBytes, err := base64.RawURLEncoding.DecodeString(tsBase64); err == nil {
			// Flask timestamp is seconds since 2011-01-01
			if len(tsBytes) >= 4 {
				ts := int64(tsBytes[0])<<24 | int64(tsBytes[1])<<16 | int64(tsBytes[2])<<8 | int64(tsBytes[3])
				epoch := time.Date(2011, 1, 1, 0, 0, 0, 0, time.UTC)
				session.Timestamp = epoch.Add(time.Duration(ts) * time.Second)
			}
		}
	}

	// Get signature
	if len(parts) > payloadIdx+2 {
		session.Signature = parts[payloadIdx+2]
	}

	// Verify signature if secret provided
	if secret != "" {
		session.Valid = verifyFlaskSignature(value, secret)
	}

	return session, nil
}

// verifyFlaskSignature verifies Flask session signature
func verifyFlaskSignature(value, secret string) bool {
	parts := strings.Split(value, ".")
	if len(parts) < 3 {
		return false
	}

	// Get data to sign (everything before last .)
	lastDot := strings.LastIndex(value, ".")
	data := value[:lastDot]

	// Flask uses itsdangerous with HMAC-SHA1
	mac := hmac.New(sha1.New, []byte(secret))
	mac.Write([]byte(data))
	expected := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return hmac.Equal([]byte(expected), []byte(parts[len(parts)-1]))
}

// DecodeExpressSession decodes Express.js session cookie
func DecodeExpressSession(value, secret string) (map[string]interface{}, error) {
	// Express format: s:json.signature
	if !strings.HasPrefix(value, "s:") {
		return nil, fmt.Errorf("not an Express session")
	}

	value = value[2:] // Remove "s:" prefix
	dotIdx := strings.LastIndex(value, ".")
	if dotIdx == -1 {
		return nil, fmt.Errorf("invalid Express session format")
	}

	jsonPart := value[:dotIdx]
	signature := value[dotIdx+1:]

	// URL decode the JSON
	jsonDecoded, err := url.QueryUnescape(jsonPart)
	if err != nil {
		return nil, err
	}

	var data map[string]interface{}
	if err := json.Unmarshal([]byte(jsonDecoded), &data); err != nil {
		return nil, err
	}

	// Verify signature if secret provided
	if secret != "" {
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write([]byte(jsonPart))
		expected := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
		if !hmac.Equal([]byte(expected), []byte(signature)) {
			return data, fmt.Errorf("signature verification failed")
		}
	}

	return data, nil
}

// FindSensitiveData looks for sensitive patterns in decoded data
func FindSensitiveData(data string) []SensitiveData {
	var sensitive []SensitiveData

	patterns := map[string]struct {
		regex *regexp.Regexp
		risk  string
	}{
		"Email": {
			regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`),
			"PII exposure",
		},
		"IP Address": {
			regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`),
			"Information disclosure",
		},
		"Credit Card": {
			regexp.MustCompile(`\b(?:\d{4}[-\s]?){3}\d{4}\b`),
			"Financial data exposure",
		},
		"Phone": {
			regexp.MustCompile(`\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b`),
			"PII exposure",
		},
		"SSN": {
			regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),
			"Critical PII exposure",
		},
		"API Key": {
			regexp.MustCompile(`(?i)(api[_-]?key|apikey|api_secret)["\s:=]+["']?([a-zA-Z0-9_-]{16,})["']?`),
			"Credential exposure",
		},
		"Password": {
			regexp.MustCompile(`(?i)(password|passwd|pwd)["\s:=]+["']?([^\s"']+)["']?`),
			"Credential exposure",
		},
		"Token": {
			regexp.MustCompile(`(?i)(token|access_token|auth_token)["\s:=]+["']?([a-zA-Z0-9_.-]+)["']?`),
			"Authentication bypass risk",
		},
		"Private Key": {
			regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----`),
			"Critical credential exposure",
		},
		"AWS Key": {
			regexp.MustCompile(`(?i)AKIA[0-9A-Z]{16}`),
			"Cloud credential exposure",
		},
		"User ID": {
			regexp.MustCompile(`(?i)(user_?id|uid)["\s:=]+["']?(\d+|[a-f0-9-]{36})["']?`),
			"User enumeration",
		},
		"Admin Flag": {
			regexp.MustCompile(`(?i)(is_?admin|admin|role)["\s:=]+["']?(true|1|admin)["']?`),
			"Privilege escalation risk",
		},
	}

	for name, pattern := range patterns {
		if matches := pattern.regex.FindStringSubmatch(data); len(matches) > 0 {
			value := matches[0]
			if len(matches) > 2 {
				value = matches[2]
			}
			sensitive = append(sensitive, SensitiveData{
				Type:  name,
				Value: truncateString(value, 50),
				Risk:  pattern.risk,
			})
		}
	}

	return sensitive
}

// AnalyzeCookieSecurity analyzes cookie for security issues
func AnalyzeCookieSecurity(cookie *CookieInfo) []SecurityIssue {
	var issues []SecurityIssue

	// Missing Secure flag
	if !cookie.Secure {
		issues = append(issues, SecurityIssue{
			Severity:    "MEDIUM",
			Title:       "Missing Secure Flag",
			Description: "Cookie can be transmitted over unencrypted HTTP connections.",
			Remediation: "Set the Secure flag to ensure cookie is only sent over HTTPS.",
		})
	}

	// Missing HttpOnly flag
	if !cookie.HttpOnly {
		issues = append(issues, SecurityIssue{
			Severity:    "MEDIUM",
			Title:       "Missing HttpOnly Flag",
			Description: "Cookie is accessible via JavaScript, increasing XSS risk.",
			Remediation: "Set HttpOnly flag to prevent JavaScript access to cookie.",
		})
	}

	// Missing or weak SameSite
	if cookie.SameSite == "" {
		issues = append(issues, SecurityIssue{
			Severity:    "LOW",
			Title:       "Missing SameSite Attribute",
			Description: "Cookie may be sent with cross-site requests, increasing CSRF risk.",
			Remediation: "Set SameSite=Strict or SameSite=Lax to prevent CSRF.",
		})
	} else if strings.ToLower(cookie.SameSite) == "none" {
		issues = append(issues, SecurityIssue{
			Severity:    "MEDIUM",
			Title:       "SameSite=None",
			Description: "Cookie is sent with all cross-site requests.",
			Remediation: "Use SameSite=Strict or Lax unless cross-site access is required.",
		})
	}

	// Session name detection
	sessionNames := []string{"session", "sessionid", "phpsessid", "jsessionid", "aspsessionid", "sid", "connect.sid"}
	lowerName := strings.ToLower(cookie.Name)
	for _, name := range sessionNames {
		if strings.Contains(lowerName, name) {
			if !cookie.Secure || !cookie.HttpOnly {
				issues = append(issues, SecurityIssue{
					Severity:    "HIGH",
					Title:       "Insecure Session Cookie",
					Description: "Session cookie lacks proper security flags.",
					Remediation: "Session cookies must have Secure, HttpOnly, and SameSite flags.",
				})
			}
			break
		}
	}

	// Check for sensitive data in cookie
	decoded := DecodeCookieValue(cookie.Value)
	for _, sens := range decoded.Sensitive {
		severity := "MEDIUM"
		if strings.Contains(sens.Risk, "Critical") || sens.Type == "Password" || sens.Type == "Private Key" {
			severity = "CRITICAL"
		} else if sens.Type == "Admin Flag" || sens.Type == "Token" {
			severity = "HIGH"
		}

		issues = append(issues, SecurityIssue{
			Severity:    severity,
			Title:       fmt.Sprintf("Sensitive Data: %s", sens.Type),
			Description: fmt.Sprintf("%s found in cookie. Risk: %s", sens.Type, sens.Risk),
			Remediation: "Avoid storing sensitive data in cookies. Use server-side sessions.",
		})
	}

	// Check expiration
	if !cookie.Expires.IsZero() && cookie.Expires.Before(time.Now()) {
		issues = append(issues, SecurityIssue{
			Severity:    "INFO",
			Title:       "Expired Cookie",
			Description: "Cookie has already expired.",
			Remediation: "Update cookie expiration time.",
		})
	}

	// Long expiration
	if !cookie.Expires.IsZero() && cookie.Expires.After(time.Now().AddDate(1, 0, 0)) {
		issues = append(issues, SecurityIssue{
			Severity:    "LOW",
			Title:       "Long-Lived Cookie",
			Description: "Cookie expiration is more than 1 year in the future.",
			Remediation: "Consider shorter expiration times for security-sensitive cookies.",
		})
	}

	return issues
}

// Helper functions

func isPrintable(s string) bool {
	for _, r := range s {
		if !unicode.IsPrint(r) && !unicode.IsSpace(r) {
			return false
		}
	}
	return true
}

func tryDecompress(data []byte) string {
	// Try gzip
	if reader, err := gzip.NewReader(bytes.NewReader(data)); err == nil {
		if decompressed, err := io.ReadAll(reader); err == nil {
			reader.Close()
			return string(decompressed)
		}
	}

	// Try zlib
	if reader, err := zlib.NewReader(bytes.NewReader(data)); err == nil {
		if decompressed, err := io.ReadAll(reader); err == nil {
			reader.Close()
			return string(decompressed)
		}
	}

	return ""
}

func truncateString(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}

// DisplayCookieInfo displays parsed cookie information
func DisplayCookieInfo(cookie *CookieInfo) {
	fmt.Println("\n[COOKIE ANALYSIS]")
	fmt.Println(strings.Repeat("=", 60))

	fmt.Printf("Name: %s\n", cookie.Name)
	fmt.Printf("Value: %s\n", truncateString(cookie.Value, 60))

	if cookie.DecodedVal != cookie.Value {
		fmt.Printf("\n[Decoded Value]\n")
		fmt.Printf("Encoding: %s\n", cookie.Encoding)
		fmt.Printf("Decoded: %s\n", truncateString(cookie.DecodedVal, 100))
	}

	fmt.Printf("\n[Attributes]\n")
	if cookie.Domain != "" {
		fmt.Printf("  Domain: %s\n", cookie.Domain)
	}
	if cookie.Path != "" {
		fmt.Printf("  Path: %s\n", cookie.Path)
	}
	if !cookie.Expires.IsZero() {
		fmt.Printf("  Expires: %s\n", cookie.Expires.Format(time.RFC1123))
	}
	if cookie.MaxAge > 0 {
		fmt.Printf("  Max-Age: %d seconds\n", cookie.MaxAge)
	}
	fmt.Printf("  Secure: %t\n", cookie.Secure)
	fmt.Printf("  HttpOnly: %t\n", cookie.HttpOnly)
	if cookie.SameSite != "" {
		fmt.Printf("  SameSite: %s\n", cookie.SameSite)
	}

	if len(cookie.Issues) > 0 {
		fmt.Printf("\n[Security Issues]\n")
		for _, issue := range cookie.Issues {
			fmt.Printf("  [%s] %s\n", issue.Severity, issue.Title)
			fmt.Printf("    %s\n", issue.Description)
		}
	}
}

// DisplayDecodedCookie displays decoded cookie information
func DisplayDecodedCookie(decoded *DecodedCookie) {
	fmt.Println("\n[DECODED COOKIE]")
	fmt.Println(strings.Repeat("=", 60))

	fmt.Printf("Original: %s\n", truncateString(decoded.Original, 60))
	fmt.Printf("Encoding: %s\n", decoded.Encoding)
	fmt.Printf("Session Type: %s\n", decoded.SessionType)

	if decoded.IsJSON {
		fmt.Printf("\n[JSON Data]\n")
		formatted, _ := json.MarshalIndent(decoded.JSONData, "", "  ")
		fmt.Println(string(formatted))
	} else {
		fmt.Printf("\nDecoded: %s\n", decoded.Decoded)
	}

	if len(decoded.Sensitive) > 0 {
		fmt.Printf("\n[Sensitive Data Detected]\n")
		for _, s := range decoded.Sensitive {
			fmt.Printf("  [%s] %s: %s\n", s.Risk, s.Type, s.Value)
		}
	}
}

// DisplayFlaskSession displays Flask session information
func DisplayFlaskSession(session *FlaskSession) {
	fmt.Println("\n[FLASK SESSION]")
	fmt.Println(strings.Repeat("=", 60))

	if !session.Timestamp.IsZero() {
		fmt.Printf("Timestamp: %s\n", session.Timestamp.Format(time.RFC3339))
	}

	if session.Signature != "" {
		fmt.Printf("Signature: %s\n", truncateString(session.Signature, 40))
		if session.Valid {
			fmt.Println("Signature: VALID")
		}
	}

	fmt.Printf("\n[Payload]\n")
	formatted, _ := json.MarshalIndent(session.Payload, "", "  ")
	fmt.Println(string(formatted))
}
