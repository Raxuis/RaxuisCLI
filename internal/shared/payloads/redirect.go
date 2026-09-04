package payloads

// OpenRedirectPayloads contains payloads for open redirect testing
var OpenRedirectPayloads = []string{
	"//evil.com",
	"https://evil.com",
	"/\\evil.com",
	"////evil.com",
	"https:evil.com",
	"//evil.com/%2f..",
	"///evil.com",
	"////evil.com/",
	"https://evil.com/redirect",
	"//evil%E3%80%82com",
}

// RedirectParamNames contains common parameter names used for redirects
var RedirectParamNames = []string{
	"url",
	"redirect",
	"return",
	"next",
	"goto",
	"target",
	"dest",
	"destination",
	"rurl",
	"return_url",
	"continue",
	"redirect_uri",
	"redirect_url",
	"callback",
	"forward",
	"to",
	"out",
	"view",
	"link",
}

// GetOpenRedirectPayloads returns open redirect payloads
func GetOpenRedirectPayloads() []string {
	return OpenRedirectPayloads
}

// IsRedirectParam checks if a parameter name looks like a redirect parameter
func IsRedirectParam(param string) bool {
	paramLower := toLower(param)
	for _, rp := range RedirectParamNames {
		if containsStr(paramLower, rp) {
			return true
		}
	}
	return false
}

func toLower(s string) string {
	result := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			result[i] = c + 32
		} else {
			result[i] = c
		}
	}
	return string(result)
}

func containsStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
