package web

import (
	"context"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/idna"

	"raxuiscli/internal/crypto/certinfo"
	"raxuiscli/internal/shared/constants"
	"raxuiscli/internal/shared/models"
	"raxuiscli/internal/shared/report"
	webhttp "raxuiscli/internal/web/http"
)

const (
	defaultTimeout      = 10 * time.Second
	defaultMaxBodyBytes = int64(1 << 20)
)

// Options controls a passive web audit. The default request is a single GET
// request with redirects disabled. Callers must opt in before a redirect can
// contact another target.
type Options struct {
	Timeout        time.Duration
	MaxBodyBytes   int64
	AllowRedirects bool
	InsecureTLS    bool
	Headers        map[string]string
	Cookie         string
	UserAgent      string
	HTTPCollector  HTTPCollector
	TLSCollector   TLSCollector
	Now            func() time.Time
}

// HTTPCollector retrieves the facts needed for a passive header audit. It is
// injectable so callers can test orchestration without a network connection.
type HTTPCollector interface {
	CollectHTTP(context.Context, *url.URL, Options) (HTTPCollection, error)
}

// HTTPCollection is the non-sensitive HTTP data retained by the audit layer.
// Response bodies are deliberately excluded because this audit only needs
// headers and their unbounded contents must never become report data.
type HTTPCollection struct {
	StatusCode    int
	Headers       http.Header
	BodyTruncated bool
}

// TLSCollector collects an HTTPS peer chain. It is intentionally separate
// from HTTP collection: an invalid chain remains an audit finding, while an
// unavailable TLS connection is a partial operational error.
type TLSCollector interface {
	CollectTLS(context.Context, string, int) (*certinfo.ChainInfo, error)
}

// Audit performs a bounded, passive HTTP/TLS inspection. Collector failures
// are included in a partial report so useful data from another collector is not
// discarded. Input validation failures are returned as errors because there is
// no meaningful audit target to report.
func Audit(ctx context.Context, rawTarget string, options Options) (report.Report, error) {
	if ctx == nil {
		return report.Report{}, fmt.Errorf("audit context must not be nil")
	}
	target, err := parseTarget(rawTarget)
	if err != nil {
		return report.Report{}, err
	}

	now := options.Now
	if now == nil {
		now = time.Now
	}
	startedAt := now()
	if startedAt.IsZero() {
		// A test or caller clock may deliberately return zero. Capture one
		// effective instant so report metadata and every TLS decision agree.
		startedAt = time.Now()
	}
	timeout := options.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	auditContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	httpCollector := options.HTTPCollector
	if httpCollector == nil {
		httpCollector = defaultHTTPCollector{}
	}
	tlsCollector := options.TLSCollector
	if tlsCollector == nil {
		tlsCollector = defaultTLSCollector{at: startedAt}
	}

	resource := target.String()
	var findings []models.VulnResult
	var observations []report.Observation
	var reportErrors []report.ReportError

	httpResult, httpErr := httpCollector.CollectHTTP(auditContext, target, options)
	if httpErr != nil {
		reportErrors = append(reportErrors, report.ReportError{Code: "http.collect", Message: httpErr.Error()})
	} else {
		findings = append(findings, HTTPHeaderFindings(resource, headerResults(resource, httpResult.Headers))...)
		if httpResult.StatusCode > 0 {
			observations = append(observations, report.Observation{Key: "http.status", Value: strconv.Itoa(httpResult.StatusCode)})
		}
		if httpResult.BodyTruncated {
			observations = append(observations, report.Observation{Key: "http.body_truncated", Value: "true"})
		}
	}

	if target.Scheme == "http" {
		observations = append(observations, report.Observation{Key: "tls.skipped", Value: "target scheme is http"})
	} else {
		chain, tlsErr := tlsCollector.CollectTLS(auditContext, target.Hostname(), targetPort(target))
		if tlsErr != nil {
			reportErrors = append(reportErrors, report.ReportError{Code: "tls.collect", Message: tlsErr.Error()})
		} else if chain == nil || len(chain.Certificates) == 0 {
			reportErrors = append(reportErrors, report.ReportError{Code: "tls.collect", Message: "TLS collector returned no certificates"})
		} else {
			validations := make([]certinfo.ValidationResult, 0, len(chain.Certificates))
			for index := range chain.Certificates {
				validation := certinfo.ValidateCertificateAt(&chain.Certificates[index], startedAt)
				if validation != nil {
					validations = append(validations, *validation)
				}
			}
			findings = append(findings, CertificateFindings(resource, *chain, validations)...)
			observations = append(observations, TLSObservations(*chain)...)
		}
	}

	status := "success"
	if len(reportErrors) > 0 {
		status = "partial"
	}
	finishedAt := now()
	if finishedAt.IsZero() {
		finishedAt = startedAt
	}
	duration := finishedAt.Sub(startedAt)
	if duration < 0 {
		duration = 0
	}
	return report.NewReport(report.ToolInfo{}, report.AuditInfo{
		Kind:      "web",
		Target:    resource,
		StartedAt: startedAt,
		Duration:  duration,
		Status:    status,
	}, findings, observations, reportErrors), nil
}

func parseTarget(rawTarget string) (*url.URL, error) {
	target, err := url.ParseRequestURI(rawTarget)
	if err != nil || target.Scheme == "" || target.Host == "" || target.Hostname() == "" {
		return nil, fmt.Errorf("audit target must be an absolute http or https URL")
	}
	target.Scheme = strings.ToLower(target.Scheme)
	if target.Scheme != "http" && target.Scheme != "https" {
		return nil, fmt.Errorf("audit target scheme must be http or https")
	}
	port, hasPort, err := auditTargetPort(target)
	if err != nil {
		return nil, err
	}
	host, err := normalizeHostname(target.Hostname())
	if err != nil {
		return nil, err
	}
	if hasPort {
		target.Host = net.JoinHostPort(host, strconv.Itoa(port))
	} else if strings.Contains(host, ":") {
		target.Host = "[" + host + "]"
	} else {
		target.Host = host
	}
	return target, nil
}

func targetPort(target *url.URL) int {
	port, _, err := auditTargetPort(target)
	if err == nil {
		return port
	}
	return 0
}

func auditTargetPort(target *url.URL) (int, bool, error) {
	host := target.Host
	var rawPort string
	hasPort := false
	if strings.HasPrefix(host, "[") {
		end := strings.LastIndexByte(host, ']')
		if end == -1 {
			return 0, false, fmt.Errorf("audit target has an invalid IPv6 host")
		}
		suffix := host[end+1:]
		if suffix != "" {
			if !strings.HasPrefix(suffix, ":") {
				return 0, false, fmt.Errorf("audit target has an invalid port")
			}
			hasPort, rawPort = true, suffix[1:]
		}
	} else if separator := strings.LastIndexByte(host, ':'); separator >= 0 {
		hasPort, rawPort = true, host[separator+1:]
	}
	if !hasPort {
		return 443, false, nil
	}
	port, err := strconv.Atoi(rawPort)
	if err != nil || port < 1 || port > 65535 {
		return 0, true, fmt.Errorf("audit target port must be between 1 and 65535")
	}
	return port, true, nil
}

func normalizeHostname(host string) (string, error) {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "" {
		return "", fmt.Errorf("audit target hostname must not be empty")
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.String(), nil
	}
	normalized, err := idna.Lookup.ToASCII(host)
	if err != nil || normalized == "" {
		return "", fmt.Errorf("audit target hostname is invalid")
	}
	return strings.ToLower(normalized), nil
}

type defaultHTTPCollector struct{}

func (defaultHTTPCollector) CollectHTTP(ctx context.Context, target *url.URL, options Options) (HTTPCollection, error) {
	maxBodyBytes := options.MaxBodyBytes
	if maxBodyBytes <= 0 {
		maxBodyBytes = defaultMaxBodyBytes
	}
	response, err := webhttp.DoRequestContext(ctx, webhttp.RequestOptions{
		Method:      http.MethodGet,
		URL:         target.String(),
		Headers:     options.Headers,
		Cookie:      options.Cookie,
		UserAgent:   options.UserAgent,
		Insecure:    options.InsecureTLS,
		FollowRedir: options.AllowRedirects,
		// Keep the HTTP client's compatibility timeout beyond the audit
		// context's deadline. The context is therefore the single deadline
		// governing all collectors.
		Timeout: collectorTimeoutSeconds(options.Timeout),
	}, maxBodyBytes)
	if err != nil {
		return HTTPCollection{}, err
	}
	return HTTPCollection{
		StatusCode:    response.StatusCode,
		Headers:       response.Headers.Clone(),
		BodyTruncated: response.Truncated,
	}, nil
}

func collectorTimeoutSeconds(timeout time.Duration) int {
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	return int(math.Ceil(timeout.Seconds())) + 1
}

type defaultTLSCollector struct {
	at time.Time
}

func (collector defaultTLSCollector) CollectTLS(ctx context.Context, host string, port int) (*certinfo.ChainInfo, error) {
	return certinfo.GetCertFromHostContextAt(ctx, host, port, collector.at)
}

// headerResults adapts the existing passive header checks without performing a
// second request. It mirrors ScanSecurityHeaders' result contract, then Task 6
// converts those legacy rows into stable report findings.
func headerResults(resource string, headers http.Header) []models.VulnResult {
	results := make([]models.VulnResult, 0, 10)
	checks := []struct {
		name        string
		severity    constants.Severity
		description string
		remediation string
	}{
		{"Strict-Transport-Security", constants.SeverityMedium, "Missing HSTS header. The application may be vulnerable to SSL stripping attacks.", "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' header."},
		{"Content-Security-Policy", constants.SeverityMedium, "Missing CSP header. The application may be vulnerable to XSS attacks.", "Implement a Content-Security-Policy header to restrict resource loading."},
		{"X-Content-Type-Options", constants.SeverityLow, "Missing X-Content-Type-Options header. The browser may MIME-sniff responses.", "Add 'X-Content-Type-Options: nosniff' header."},
		{"X-Frame-Options", constants.SeverityMedium, "Missing X-Frame-Options header. The application may be vulnerable to clickjacking.", "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN' header."},
		{"X-XSS-Protection", constants.SeverityLow, "Missing X-XSS-Protection header. Browser XSS filter may not be enabled.", "Add 'X-XSS-Protection: 1; mode=block' header (note: deprecated in favor of CSP)."},
		{"Referrer-Policy", constants.SeverityLow, "Missing Referrer-Policy header. Sensitive information may leak in referrer.", "Add 'Referrer-Policy: strict-origin-when-cross-origin' header."},
		{"Permissions-Policy", constants.SeverityLow, "Missing Permissions-Policy header. Browser features are not restricted.", "Add Permissions-Policy header to control browser features."},
	}
	for _, check := range checks {
		if headers.Get(check.name) == "" {
			results = append(results, models.VulnResult{
				Type: constants.VulnHeaders, Severity: check.severity, URL: resource, Parameter: check.name,
				Evidence: "Header not present", Description: check.description, Remediation: check.remediation,
			})
		}
	}
	if server := headers.Get("Server"); strings.Contains(server, "/") {
		results = append(results, models.VulnResult{
			Type: constants.VulnHeaders, Severity: constants.SeverityInfo, URL: resource, Parameter: "Server", Evidence: server,
			Description: "Server version disclosed. This may help attackers identify vulnerabilities.", Remediation: "Remove or obfuscate the Server header version information.",
		})
	}
	if poweredBy := headers.Get("X-Powered-By"); poweredBy != "" {
		results = append(results, models.VulnResult{
			Type: constants.VulnHeaders, Severity: constants.SeverityInfo, URL: resource, Parameter: "X-Powered-By", Evidence: poweredBy,
			Description: "Technology stack disclosed via X-Powered-By header.", Remediation: "Remove the X-Powered-By header.",
		})
	}
	for _, cookie := range (&http.Response{Header: headers}).Cookies() {
		issues := make([]string, 0, 3)
		if !cookie.Secure {
			issues = append(issues, "missing Secure flag")
		}
		if !cookie.HttpOnly {
			issues = append(issues, "missing HttpOnly flag")
		}
		if cookie.SameSite == http.SameSiteDefaultMode || cookie.SameSite == http.SameSiteNoneMode {
			issues = append(issues, "weak SameSite policy")
		}
		if len(issues) > 0 {
			results = append(results, models.VulnResult{
				Type: constants.VulnHeaders, Severity: constants.SeverityMedium, URL: resource, Parameter: "Cookie: " + cookie.Name,
				Evidence: strings.Join(issues, ", "), Description: "Cookie security flags are not properly set.",
				Remediation: "Set Secure, HttpOnly, and SameSite=Strict flags on sensitive cookies.",
			})
		}
	}
	return results
}
