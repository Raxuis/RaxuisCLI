package payloads

// CORSTestOrigins contains origins to test for CORS misconfigurations
// TARGETDOMAIN is a placeholder that should be replaced with the actual target domain
var CORSTestOrigins = []string{
	"null",
	"https://evil.com",
	"https://attacker.com",
	"https://TARGETDOMAIN.evil.com",     // Subdomain of attacker
	"https://TARGETDOMAINevil.com",      // Prefix match bypass
	"https://evil.TARGETDOMAIN",         // Suffix match bypass
	"https://eviltargetdomain.com",      // Contains match bypass
	"https://TARGETDOMAIN.com.evil.com", // Domain in subdomain
}

// GetCORSTestOrigins returns CORS test origins with domain placeholder replaced
func GetCORSTestOrigins(targetDomain string) []string {
	if targetDomain == "" {
		return CORSTestOrigins
	}

	result := make([]string, len(CORSTestOrigins))
	for i, origin := range CORSTestOrigins {
		result[i] = replacePlaceholder(origin, "TARGETDOMAIN", targetDomain)
	}
	return result
}

func replacePlaceholder(s, old, new string) string {
	result := make([]byte, 0, len(s))
	for i := 0; i < len(s); {
		if i+len(old) <= len(s) && s[i:i+len(old)] == old {
			result = append(result, new...)
			i += len(old)
		} else {
			result = append(result, s[i])
			i++
		}
	}
	return string(result)
}
