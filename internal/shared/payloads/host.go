package payloads

// HostHeaderPayload represents a host header injection payload
type HostHeaderPayload struct {
	Header string
	Value  string
	Desc   string
}

// HostHeaderPayloads contains payloads for host header injection testing
var HostHeaderPayloads = []HostHeaderPayload{
	{"Host", "evil.com", "Basic host header override"},
	{"Host", "localhost", "Localhost bypass"},
	{"Host", "127.0.0.1", "Loopback bypass"},
	{"X-Forwarded-Host", "evil.com", "X-Forwarded-Host injection"},
	{"X-Host", "evil.com", "X-Host injection"},
	{"X-Forwarded-Server", "evil.com", "X-Forwarded-Server injection"},
	{"X-Original-URL", "/admin", "X-Original-URL injection"},
	{"X-Rewrite-URL", "/admin", "X-Rewrite-URL injection"},
	{"Host", "target.com:evil.com", "Port-based host injection"},
	{"Host", "target.com@evil.com", "User-based host injection"},
	{"Host", "evil.com#target.com", "Fragment-based injection"},
	{"Host", "target.com\r\nX-Injected: header", "CRLF in host"},
}

// PasswordResetEndpoints contains common password reset endpoint paths
var PasswordResetEndpoints = []string{
	"/reset-password",
	"/forgot-password",
	"/password/reset",
	"/account/recover",
	"/auth/forgot",
}

// GetHostHeaderPayloads returns all host header payloads
func GetHostHeaderPayloads() []HostHeaderPayload {
	return HostHeaderPayloads
}
