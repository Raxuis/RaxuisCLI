package report

import (
	"net"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"
)

// RedactedValue is used in persisted reports wherever a secret was supplied.
const RedactedValue = "<redacted>"

var (
	urlInText = regexp.MustCompile(`(?i)https?://[^\s"'<>]+`)
	secretKV  = regexp.MustCompile(`(?i)\b(api[_-]?key|access[_-]?token|refresh[_-]?token|token|secret|password|passwd)\s*([=:])\s*([^\s;,]+)`)
	bearer    = regexp.MustCompile(`(?i)\bbearer\s+[^\s;,]+`)
	header    = regexp.MustCompile(`(?im)\b(authorization|proxy-authorization|cookie|set-cookie)\s*:\s*[^\r\n]*`)
)

// RedactURL returns a canonical URL with user credentials removed and every
// query value replaced. Invalid URLs are returned with common secret patterns
// redacted rather than rejected, so error reporting remains safe.
func RedactURL(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return redactNonURL(rawURL)
	}
	return canonicalURL(parsed)
}

// CanonicalizeResource provides the canonical, persistence-safe representation
// used as the resource component of a finding ID.
func CanonicalizeResource(resource string) string {
	return RedactURL(resource)
}

// RedactHeaders returns a copy of headers with cookies and authorization values
// removed. It never mutates the request or response headers supplied by callers.
func RedactHeaders(headers http.Header) http.Header {
	redacted := make(http.Header, len(headers))
	for key, values := range headers {
		copied := append([]string(nil), values...)
		if isSensitiveHeader(key) {
			for i := range copied {
				copied[i] = RedactedValue
			}
		}
		redacted[key] = copied
	}
	return redacted
}

// RedactString removes URLs, credentials, sensitive HTTP headers, and common
// key/value secret forms from arbitrary text such as collector errors.
func RedactString(value string) string {
	value = urlInText.ReplaceAllStringFunc(value, RedactURL)
	value = header.ReplaceAllStringFunc(value, func(match string) string {
		separator := strings.IndexByte(match, ':')
		if separator == -1 {
			return RedactedValue
		}
		return match[:separator+1] + " " + RedactedValue
	})
	return redactNonURL(value)
}

func canonicalURL(parsed *url.URL) string {
	copy := *parsed
	parsed = &copy
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	parsed.User = nil
	parsed.Fragment = ""
	parsed.ForceQuery = false

	host := strings.ToLower(parsed.Hostname())
	port := parsed.Port()
	if (parsed.Scheme == "http" && port == "80") || (parsed.Scheme == "https" && port == "443") {
		port = ""
	}
	if port == "" {
		if strings.Contains(host, ":") {
			parsed.Host = "[" + host + "]"
		} else {
			parsed.Host = host
		}
	} else {
		parsed.Host = net.JoinHostPort(host, port)
	}

	cleanPath := path.Clean(parsed.Path)
	if cleanPath == "." || cleanPath == "" {
		cleanPath = "/"
	}
	parsed.Path = cleanPath
	parsed.RawPath = ""
	parsed.RawQuery = redactQuery(parsed.RawQuery)
	return parsed.String()
}

func redactQuery(rawQuery string) string {
	if rawQuery == "" {
		return ""
	}

	parts := strings.Split(rawQuery, "&")
	redacted := make([]string, 0, len(parts))
	for _, part := range parts {
		if part == "" {
			continue
		}
		key, _, hasValue := strings.Cut(part, "=")
		if hasValue {
			redacted = append(redacted, key+"="+RedactedValue)
		} else {
			redacted = append(redacted, key)
		}
	}
	sort.Strings(redacted)
	return strings.Join(redacted, "&")
}

func redactNonURL(value string) string {
	value = bearer.ReplaceAllString(value, "Bearer "+RedactedValue)
	return secretKV.ReplaceAllString(value, "$1$2"+RedactedValue)
}

func isSensitiveHeader(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "authorization", "proxy-authorization", "cookie", "set-cookie":
		return true
	default:
		return false
	}
}
