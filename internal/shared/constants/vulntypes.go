package constants

// VulnType represents vulnerability type
type VulnType string

const (
	VulnXSS        VulnType = "XSS"
	VulnSQLi       VulnType = "SQLi"
	VulnLFI        VulnType = "LFI"
	VulnRFI        VulnType = "RFI"
	VulnSSRF       VulnType = "SSRF"
	VulnCmdInj     VulnType = "Command Injection"
	VulnHeaders    VulnType = "Security Headers"
	VulnOpen       VulnType = "Open Redirect"
	VulnCORS       VulnType = "CORS Misconfiguration"
	VulnNoSQLi     VulnType = "NoSQL Injection"
	VulnXXE        VulnType = "XXE"
	VulnGraphQL    VulnType = "GraphQL Security"
	VulnHostHeader VulnType = "Host Header Injection"
	VulnRace       VulnType = "Race Condition"
)

// String returns the string representation of the vulnerability type
func (v VulnType) String() string {
	return string(v)
}

// Description returns a brief description of the vulnerability type
func (v VulnType) Description() string {
	switch v {
	case VulnXSS:
		return "Cross-Site Scripting allows attackers to inject malicious scripts"
	case VulnSQLi:
		return "SQL Injection allows attackers to manipulate database queries"
	case VulnLFI:
		return "Local File Inclusion allows attackers to read local files"
	case VulnRFI:
		return "Remote File Inclusion allows attackers to include remote files"
	case VulnSSRF:
		return "Server-Side Request Forgery allows attackers to make server requests"
	case VulnCmdInj:
		return "Command Injection allows attackers to execute system commands"
	case VulnHeaders:
		return "Missing or misconfigured security headers"
	case VulnOpen:
		return "Open Redirect allows attackers to redirect users to malicious sites"
	case VulnCORS:
		return "CORS Misconfiguration allows unauthorized cross-origin requests"
	case VulnNoSQLi:
		return "NoSQL Injection allows attackers to manipulate NoSQL queries"
	case VulnXXE:
		return "XML External Entity allows attackers to read files or make requests"
	case VulnGraphQL:
		return "GraphQL security issues including introspection and DoS"
	case VulnHostHeader:
		return "Host Header Injection can lead to cache poisoning or password reset attacks"
	case VulnRace:
		return "Race Condition allows attackers to exploit timing issues"
	default:
		return "Unknown vulnerability type"
	}
}
