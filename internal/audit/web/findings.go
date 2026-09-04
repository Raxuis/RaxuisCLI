// Package web adapts passive HTTP and TLS analyses into stable report findings.
package web

import (
	"crypto/tls"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"raxuiscli/internal/crypto/certinfo"
	"raxuiscli/internal/shared/constants"
	"raxuiscli/internal/shared/models"
	"raxuiscli/internal/shared/report"
)

const tlsCertificateType constants.VulnType = "TLS Certificate"

// HTTPHeaderFindings converts the legacy security-header analysis into stable
// report findings. The input slice is never changed.
func HTTPHeaderFindings(resource string, results []models.VulnResult) []models.VulnResult {
	findings := make([]models.VulnResult, 0, len(results))
	for _, result := range results {
		if result.Type != constants.VulnHeaders {
			continue
		}

		ruleID, title := headerRule(result.Parameter)
		result.RuleID = ruleID
		result.Title = title
		result.Resource = resource
		if result.Resource == "" {
			result.Resource = result.URL
		}
		result.Status = "open"
		findings = append(findings, result)
	}
	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].RuleID != findings[j].RuleID {
			return findings[i].RuleID < findings[j].RuleID
		}
		return findings[i].Evidence < findings[j].Evidence
	})
	return findings
}

func headerRule(parameter string) (string, string) {
	switch parameter {
	case "Strict-Transport-Security":
		return "http.header.hsts.missing", "HSTS header is missing"
	case "Content-Security-Policy":
		return "http.header.content-security-policy.missing", "Content-Security-Policy header is missing"
	case "X-Content-Type-Options":
		return "http.header.x-content-type-options.missing", "X-Content-Type-Options header is missing"
	case "X-Frame-Options":
		return "http.header.x-frame-options.missing", "X-Frame-Options header is missing"
	case "X-XSS-Protection":
		return "http.header.x-xss-protection.missing", "X-XSS-Protection header is missing"
	case "Referrer-Policy":
		return "http.header.referrer-policy.missing", "Referrer-Policy header is missing"
	case "Permissions-Policy":
		return "http.header.permissions-policy.missing", "Permissions-Policy header is missing"
	case "Server":
		return "http.header.server.version-disclosure", "Server version is disclosed"
	case "X-Powered-By":
		return "http.header.x-powered-by.disclosure", "Technology stack is disclosed"
	}
	if strings.HasPrefix(parameter, "Cookie: ") {
		return "http.cookie.security-flags", "Cookie security flags are weak"
	}
	return "http.header." + ruleComponent(parameter) + ".misconfigured", parameter + " header is misconfigured"
}

func ruleComponent(value string) string {
	var builder strings.Builder
	separator := true
	for _, character := range strings.ToLower(strings.TrimSpace(value)) {
		if unicode.IsLetter(character) || unicode.IsDigit(character) {
			builder.WriteRune(character)
			separator = false
		} else if !separator {
			builder.WriteByte('-')
			separator = true
		}
	}
	component := strings.Trim(builder.String(), "-")
	if component == "" {
		return "unknown"
	}
	return component
}

// CertificateFindings converts previously collected certificate validations and
// chain verification state into stable report findings. Callers choose when to
// validate certificates, keeping this conversion deterministic and side-effect
// free.
func CertificateFindings(resource string, chain certinfo.ChainInfo, validations []certinfo.ValidationResult) []models.VulnResult {
	findings := make([]models.VulnResult, 0, len(validations)*2+1)
	if !chain.Valid && chain.Error != "" {
		findings = append(findings, tlsFinding(resource, "tls.certificate.chain-validation", "Certificate chain validation failed", chain.Error, "Install the complete chain issued by a trusted certificate authority."))
	}

	for _, validation := range validations {
		if validation.Expired {
			findings = append(findings, tlsFinding(resource, "tls.certificate.expired", "Certificate has expired", validationEvidence(validation.ChainErrors, "Certificate has expired"), "Replace the certificate with one valid for the current time."))
		}
		if validation.NotYetValid {
			findings = append(findings, tlsFinding(resource, "tls.certificate.not-yet-valid", "Certificate is not yet valid", validationEvidence(validation.ChainErrors, "Certificate is not yet valid"), "Deploy a certificate whose validity period has begun."))
		}
		if validation.SelfSigned {
			findings = append(findings, tlsFinding(resource, "tls.certificate.self-signed", "Certificate is self-signed", validationEvidence(validation.Warnings, "Certificate is self-signed"), "Use a certificate issued by a trusted certificate authority."))
		}
		for _, warning := range validation.Warnings {
			if strings.HasPrefix(warning, "Weak signature algorithm:") {
				findings = append(findings, tlsFinding(resource, "tls.certificate.weak-signature", "Certificate uses a weak signature algorithm", warning, "Replace the certificate with one using a modern SHA-256-or-stronger signature."))
			}
		}
	}

	return uniqueAndSortFindings(findings)
}

func validationEvidence(values []string, fallback string) string {
	for _, value := range values {
		if value == fallback {
			return value
		}
	}
	return fallback
}

func tlsFinding(resource, ruleID, title, evidence, remediation string) models.VulnResult {
	return models.VulnResult{
		RuleID:      ruleID,
		Title:       title,
		Type:        tlsCertificateType,
		Severity:    constants.SeverityHigh,
		Status:      "open",
		Resource:    resource,
		Evidence:    evidence,
		Description: title,
		Remediation: remediation,
	}
}

func uniqueAndSortFindings(findings []models.VulnResult) []models.VulnResult {
	seen := make(map[string]struct{}, len(findings))
	unique := make([]models.VulnResult, 0, len(findings))
	for _, finding := range findings {
		key := finding.RuleID + "\x00" + finding.Evidence
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		unique = append(unique, finding)
	}
	sort.SliceStable(unique, func(i, j int) bool {
		if unique[i].RuleID != unique[j].RuleID {
			return unique[i].RuleID < unique[j].RuleID
		}
		return unique[i].Evidence < unique[j].Evidence
	})
	return unique
}

// TLSObservations returns stable, non-finding facts from a completed TLS
// handshake. It does not mutate the supplied chain.
func TLSObservations(chain certinfo.ChainInfo) []report.Observation {
	observations := []report.Observation{{Key: "tls.chain_valid", Value: strconv.FormatBool(chain.Valid)}}
	if chain.TLSVersion != 0 {
		observations = append(observations, report.Observation{Key: "tls.version", Value: tls.VersionName(chain.TLSVersion)})
	}
	if chain.CipherSuite != 0 {
		observations = append(observations, report.Observation{Key: "tls.cipher_suite", Value: tls.CipherSuiteName(chain.CipherSuite)})
	}
	sort.SliceStable(observations, func(i, j int) bool { return observations[i].Key < observations[j].Key })
	return observations
}
