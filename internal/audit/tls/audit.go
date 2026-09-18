// Package tls turns a TLS/SSL posture scan into a versioned, comparable report.
package tls

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/Raxuis/RaxuisCLI/internal/crypto/tlsscan"
	"github.com/Raxuis/RaxuisCLI/internal/shared/constants"
	"github.com/Raxuis/RaxuisCLI/internal/shared/models"
	"github.com/Raxuis/RaxuisCLI/internal/shared/report"
)

const defaultPort = 443

// Options configures a TLS audit.
type Options struct {
	Port    int
	Timeout time.Duration
}

// Audit scans target and returns a schema-v1 report. The Tool field is left for
// the command layer to populate with build provenance.
func Audit(_ context.Context, target string, opts Options) (report.Report, error) {
	port := opts.Port
	if port <= 0 {
		port = defaultPort
	}
	host, resolvedPort := splitTarget(target, port)

	started := time.Now()
	result := tlsscan.Scan(host, resolvedPort, opts.Timeout)
	duration := time.Since(started)

	resource := fmt.Sprintf("%s:%d", host, resolvedPort)

	status := "complete"
	var reportErrors []report.ReportError
	if result.Error != "" {
		status = "partial"
		reportErrors = append(reportErrors, report.ReportError{
			Code:    "tls.scan_failed",
			Message: result.Error,
		})
	}

	audit := report.AuditInfo{
		Kind:      "tls",
		Target:    resource,
		StartedAt: started,
		Duration:  duration,
		Status:    status,
	}

	return report.NewReport(
		report.ToolInfo{},
		audit,
		toFindings(result, resource),
		toObservations(result),
		reportErrors,
	), nil
}

// remediations maps a tlsscan finding ID to an actionable fix. The report
// schema requires a remediation on every finding.
var remediations = map[string]string{
	"protocol-tls10":     "Disable TLS 1.0 on the server; require TLS 1.2 or higher.",
	"protocol-tls11":     "Disable TLS 1.1 on the server; require TLS 1.2 or higher.",
	"protocol-no-modern": "Enable TLS 1.2 and TLS 1.3.",
	"protocol-no-tls13":  "Enable TLS 1.3 on the server.",
	"cipher-rc4":         "Remove all RC4 cipher suites from the server configuration.",
	"cipher-3des":        "Disable 3DES/DES cipher suites.",
	"cipher-weak":        "Prefer AEAD suites (AES-GCM, ChaCha20) with ECDHE; remove CBC and RSA key-exchange suites.",
	"no-forward-secrecy": "Enable ECDHE (or DHE) cipher suites to provide forward secrecy.",
	"cert-expired":       "Renew the certificate.",
	"cert-expiring":      "Renew the certificate before it expires.",
	"cert-not-yet-valid": "Check the server clock and the certificate validity dates.",
	"cert-self-signed":   "Use a certificate issued by a trusted CA.",
	"cert-hostname":      "Issue a certificate whose SAN matches the served hostname.",
	"cert-weak-sig":      "Reissue the certificate with a SHA-256 (or stronger) signature.",
	"cert-weak-key":      "Reissue with a 2048-bit (or stronger) RSA key, or use ECDSA.",
}

func remediationFor(id string) string {
	if r, ok := remediations[id]; ok {
		return r
	}
	return "Review and harden the server's TLS configuration."
}

// ruleID builds a stable, unique rule identity. The finding class (f.ID) alone
// is not unique when several suites share a class (e.g. cipher-weak), which
// would collide under the report's sha256(rule_id, resource) identity, so the
// title — unique and deterministic within a scan — is folded in.
func ruleID(f tlsscan.Finding) string {
	return "tls." + f.ID + "." + slug(f.Title)
}

func slug(s string) string {
	var b strings.Builder
	lastDash := true
	for _, r := range strings.ToLower(s) {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'):
			b.WriteRune(r)
			lastDash = false
		case !lastDash:
			b.WriteByte('-')
			lastDash = true
		}
	}
	return strings.Trim(b.String(), "-")
}

func toFindings(result *tlsscan.Result, resource string) []models.VulnResult {
	findings := make([]models.VulnResult, 0, len(result.Findings))
	for _, f := range result.Findings {
		findings = append(findings, models.VulnResult{
			RuleID:      ruleID(f),
			Title:       f.Title,
			Type:        constants.VulnType("TLS/SSL"),
			Severity:    constants.Severity(f.Severity),
			Resource:    resource,
			Evidence:    f.Title,
			Description: f.Detail,
			Remediation: remediationFor(f.ID),
			Status:      "open",
		})
	}
	return findings
}

func toObservations(result *tlsscan.Result) []report.Observation {
	observations := []report.Observation{
		{Key: "tls.grade", Value: result.Grade()},
	}
	for _, p := range result.Protocols {
		observations = append(observations, report.Observation{
			Key:   "tls.protocol." + strings.ReplaceAll(p.Name, " ", "_"),
			Value: strconv.FormatBool(p.Supported),
		})
	}
	if c := result.Certificate; c != nil {
		observations = append(observations,
			report.Observation{Key: "tls.cert.subject", Value: c.Subject},
			report.Observation{Key: "tls.cert.expires", Value: c.NotAfter.UTC().Format("2006-01-02")},
			report.Observation{Key: "tls.cert.key", Value: fmt.Sprintf("%s %d", c.KeyType, c.KeyBits)},
			report.Observation{Key: "tls.cert.signature", Value: c.SignatureAlgorithm},
		)
	}
	return observations
}

func splitTarget(target string, defaultPort int) (string, int) {
	if idx := strings.LastIndex(target, ":"); idx != -1 {
		if p, err := strconv.Atoi(target[idx+1:]); err == nil && p > 0 && p <= 65535 {
			return target[:idx], p
		}
	}
	return target, defaultPort
}
