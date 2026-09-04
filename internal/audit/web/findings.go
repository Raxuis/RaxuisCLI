// Package web adapts passive HTTP and TLS analyses into stable report findings.
package web

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
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
	return aggregateAndSortFindings(findings)
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
	if finding := verificationFinding(resource, chain, findings); finding != nil {
		findings = append(findings, *finding)
	}

	return aggregateAndSortFindings(findings)
}

func verificationFinding(resource string, chain certinfo.ChainInfo, findings []models.VulnResult) *models.VulnResult {
	if chain.Valid || chain.Error == "" {
		return nil
	}

	if verificationErrorIsTimeValidity(chain.VerificationError) || isAmbiguousValidityError(chain.Error) {
		if hasFindingRule(findings, "tls.certificate.expired") || hasFindingRule(findings, "tls.certificate.not-yet-valid") {
			return nil
		}
		finding := tlsFinding(resource, "tls.certificate.invalid-validity-period", "Certificate validity period is invalid", chain.Error, "Use a certificate whose validity period includes the time of the audit.")
		return &finding
	}

	var hostnameError x509.HostnameError
	if errors.As(chain.VerificationError, &hostnameError) || strings.Contains(strings.ToLower(chain.Error), "not valid for") {
		finding := tlsFinding(resource, "tls.certificate.hostname-mismatch", "Certificate does not match the audited host", chain.Error, "Use a certificate whose DNS names or IP addresses cover the audited host.")
		return &finding
	}

	var invalidError x509.CertificateInvalidError
	if errors.As(chain.VerificationError, &invalidError) {
		switch invalidError.Reason {
		case x509.IncompatibleUsage, x509.CANotAuthorizedForExtKeyUsage:
			finding := tlsFinding(resource, "tls.certificate.incompatible-usage", "Certificate is not authorized for TLS server authentication", chain.Error, "Use a certificate authorized for TLS server authentication.")
			return &finding
		case x509.NoValidChains, x509.NameMismatch, x509.NotAuthorizedToSign:
			finding := tlsFinding(resource, "tls.certificate.chain-validation", "Certificate chain validation failed", chain.Error, "Install the complete chain issued by a trusted certificate authority.")
			return &finding
		default:
			finding := tlsFinding(resource, "tls.certificate.validation-failed", "Certificate validation failed", chain.Error, "Correct the certificate validation error reported by the verifier.")
			return &finding
		}
	}

	var authorityError x509.UnknownAuthorityError
	if errors.As(chain.VerificationError, &authorityError) || isTrustOrChainError(chain.Error) {
		finding := tlsFinding(resource, "tls.certificate.chain-validation", "Certificate chain validation failed", chain.Error, "Install the complete chain issued by a trusted certificate authority.")
		return &finding
	}

	if strings.Contains(strings.ToLower(chain.Error), "incompatible key usage") {
		finding := tlsFinding(resource, "tls.certificate.incompatible-usage", "Certificate is not authorized for TLS server authentication", chain.Error, "Use a certificate authorized for TLS server authentication.")
		return &finding
	}
	if strings.Contains(strings.ToLower(chain.Error), "not yet valid") {
		finding := tlsFinding(resource, "tls.certificate.not-yet-valid", "Certificate is not yet valid", chain.Error, "Deploy a certificate whose validity period has begun.")
		return &finding
	}
	if strings.Contains(strings.ToLower(chain.Error), "certificate has expired") {
		finding := tlsFinding(resource, "tls.certificate.expired", "Certificate has expired", chain.Error, "Replace the certificate with one valid for the current time.")
		return &finding
	}
	finding := tlsFinding(resource, "tls.certificate.validation-failed", "Certificate validation failed", chain.Error, "Correct the certificate validation error reported by the verifier.")
	return &finding
}

func verificationErrorIsTimeValidity(err error) bool {
	var invalidError x509.CertificateInvalidError
	return errors.As(err, &invalidError) && invalidError.Reason == x509.Expired
}

func hasFindingRule(findings []models.VulnResult, ruleID string) bool {
	for _, finding := range findings {
		if finding.RuleID == ruleID {
			return true
		}
	}
	return false
}

func isTrustOrChainError(message string) bool {
	message = strings.ToLower(message)
	return strings.Contains(message, "unknown authority") || strings.Contains(message, "no valid chains") || strings.Contains(message, "signed by unknown")
}

func isAmbiguousValidityError(message string) bool {
	return strings.Contains(strings.ToLower(message), "has expired or is not yet valid")
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

// aggregateAndSortFindings gives each rule/resource identity exactly one
// finding. Report IDs are derived from those two fields, so keeping multiple
// rows would make output unstable and ambiguous. Evidence and remediation are
// deduplicated and sorted before being joined.
func aggregateAndSortFindings(findings []models.VulnResult) []models.VulnResult {
	aggregated := make(map[string]*findingAggregate, len(findings))
	for _, finding := range findings {
		finding.Resource = report.CanonicalizeResource(finding.Resource)
		finding.URL = finding.Resource
		key := finding.RuleID + "\x00" + finding.Resource
		current, exists := aggregated[key]
		if !exists {
			aggregated[key] = newFindingAggregate(finding)
			continue
		}
		current.add(finding)
	}

	result := make([]models.VulnResult, 0, len(aggregated))
	for _, aggregate := range aggregated {
		result = append(result, aggregate.finding())
	}
	sort.SliceStable(result, func(i, j int) bool {
		if result[i].RuleID != result[j].RuleID {
			return result[i].RuleID < result[j].RuleID
		}
		if result[i].Resource != result[j].Resource {
			return result[i].Resource < result[j].Resource
		}
		return result[i].Evidence < result[j].Evidence
	})
	return result
}

type findingAggregate struct {
	base        models.VulnResult
	parameters  map[string]struct{}
	evidence    map[string]struct{}
	remediation map[string]struct{}
}

func newFindingAggregate(finding models.VulnResult) *findingAggregate {
	aggregate := &findingAggregate{
		base:        finding,
		parameters:  make(map[string]struct{}),
		evidence:    make(map[string]struct{}),
		remediation: make(map[string]struct{}),
	}
	aggregate.add(finding)
	return aggregate
}

func (aggregate *findingAggregate) add(finding models.VulnResult) {
	addAtomic(aggregate.parameters, finding.Parameter)
	addAtomic(aggregate.evidence, finding.Evidence)
	addAtomic(aggregate.remediation, finding.Remediation)
	if finding.Severity.Rank() > aggregate.base.Severity.Rank() {
		aggregate.base.Severity = finding.Severity
	}
	aggregate.base.Title = stableValue(aggregate.base.Title, finding.Title)
	aggregate.base.Description = stableValue(aggregate.base.Description, finding.Description)
	aggregate.base.Status = stableValue(aggregate.base.Status, finding.Status)
	if aggregate.base.Type == "" || (finding.Type != "" && string(finding.Type) < string(aggregate.base.Type)) {
		aggregate.base.Type = finding.Type
	}
}

func (aggregate *findingAggregate) finding() models.VulnResult {
	finding := aggregate.base
	finding.Parameter = joinAtomic(aggregate.parameters)
	finding.Evidence = joinAtomic(aggregate.evidence)
	finding.Remediation = joinAtomic(aggregate.remediation)
	return finding
}

func addAtomic(values map[string]struct{}, value string) {
	if value != "" {
		values[value] = struct{}{}
	}
}

func joinAtomic(values map[string]struct{}) string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return strings.Join(result, "; ")
}

func stableValue(current, candidate string) string {
	if current == "" || (candidate != "" && candidate < current) {
		return candidate
	}
	return current
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
