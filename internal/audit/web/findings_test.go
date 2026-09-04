package web

import (
	"crypto/tls"
	"crypto/x509"
	"reflect"
	"testing"
	"time"

	"raxuiscli/internal/crypto/certinfo"
	"raxuiscli/internal/shared/constants"
	"raxuiscli/internal/shared/models"
	"raxuiscli/internal/shared/report"
)

func TestHTTPHeaderFindingsMapsEveryInsecureHeaderState(t *testing.T) {
	const resource = "https://example.test/account"

	tests := []struct {
		name        string
		parameter   string
		severity    constants.Severity
		evidence    string
		ruleID      string
		title       string
		remediation string
	}{
		{"missing HSTS", "Strict-Transport-Security", constants.SeverityMedium, "Header not present", "http.header.hsts.missing", "HSTS header is missing", "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' header."},
		{"missing CSP", "Content-Security-Policy", constants.SeverityMedium, "Header not present", "http.header.content-security-policy.missing", "Content-Security-Policy header is missing", "Implement a Content-Security-Policy header to restrict resource loading."},
		{"missing content type options", "X-Content-Type-Options", constants.SeverityLow, "Header not present", "http.header.x-content-type-options.missing", "X-Content-Type-Options header is missing", "Add 'X-Content-Type-Options: nosniff' header."},
		{"missing frame options", "X-Frame-Options", constants.SeverityMedium, "Header not present", "http.header.x-frame-options.missing", "X-Frame-Options header is missing", "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN' header."},
		{"missing XSS protection", "X-XSS-Protection", constants.SeverityLow, "Header not present", "http.header.x-xss-protection.missing", "X-XSS-Protection header is missing", "Add 'X-XSS-Protection: 1; mode=block' header (note: deprecated in favor of CSP)."},
		{"missing referrer policy", "Referrer-Policy", constants.SeverityLow, "Header not present", "http.header.referrer-policy.missing", "Referrer-Policy header is missing", "Add 'Referrer-Policy: strict-origin-when-cross-origin' header."},
		{"missing permissions policy", "Permissions-Policy", constants.SeverityLow, "Header not present", "http.header.permissions-policy.missing", "Permissions-Policy header is missing", "Add Permissions-Policy header to control browser features."},
		{"server version disclosure", "Server", constants.SeverityInfo, "nginx/1.24", "http.header.server.version-disclosure", "Server version is disclosed", "Remove or obfuscate the Server header version information."},
		{"powered by disclosure", "X-Powered-By", constants.SeverityInfo, "PHP/8.3", "http.header.x-powered-by.disclosure", "Technology stack is disclosed", "Remove the X-Powered-By header."},
		{"weak cookie flags", "Cookie: session", constants.SeverityMedium, "missing Secure flag, missing HttpOnly flag, weak SameSite policy", "http.cookie.security-flags", "Cookie security flags are weak", "Set Secure, HttpOnly, and SameSite=Strict flags on sensitive cookies."},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			legacy := models.VulnResult{
				Type:        constants.VulnHeaders,
				Severity:    tt.severity,
				URL:         resource,
				Parameter:   tt.parameter,
				Evidence:    tt.evidence,
				Remediation: tt.remediation,
			}

			findings := HTTPHeaderFindings(resource, []models.VulnResult{legacy})
			if len(findings) != 1 {
				t.Fatalf("findings length = %d, want 1", len(findings))
			}
			got := findings[0]
			if got.RuleID != tt.ruleID || got.Severity != tt.severity || got.Evidence != tt.evidence || got.Remediation != tt.remediation || got.Title != tt.title {
				t.Errorf("finding = %#v, want rule=%q severity=%q evidence=%q remediation=%q title=%q", got, tt.ruleID, tt.severity, tt.evidence, tt.remediation, tt.title)
			}
			if got.Resource != resource || got.Status != "open" {
				t.Errorf("resource/status = %q/%q, want %q/open", got.Resource, got.Status, resource)
			}
		})
	}
}

func TestCertificateFindingsMapValidationStates(t *testing.T) {
	const resource = "https://example.test/"

	tests := []struct {
		name        string
		chain       certinfo.ChainInfo
		validations []certinfo.ValidationResult
		ruleID      string
		severity    constants.Severity
		evidence    string
		remediation string
	}{
		{"expired", certinfo.ChainInfo{}, []certinfo.ValidationResult{{Expired: true, ChainErrors: []string{"Certificate has expired"}}}, "tls.certificate.expired", constants.SeverityHigh, "Certificate has expired", "Replace the certificate with one valid for the current time."},
		{"not yet valid", certinfo.ChainInfo{}, []certinfo.ValidationResult{{NotYetValid: true, ChainErrors: []string{"Certificate is not yet valid"}}}, "tls.certificate.not-yet-valid", constants.SeverityHigh, "Certificate is not yet valid", "Deploy a certificate whose validity period has begun."},
		{"self signed", certinfo.ChainInfo{}, []certinfo.ValidationResult{{SelfSigned: true, Warnings: []string{"Certificate is self-signed"}}}, "tls.certificate.self-signed", constants.SeverityHigh, "Certificate is self-signed", "Use a certificate issued by a trusted certificate authority."},
		{"weak signature", certinfo.ChainInfo{}, []certinfo.ValidationResult{{Warnings: []string{"Weak signature algorithm: SHA1-RSA"}}}, "tls.certificate.weak-signature", constants.SeverityHigh, "Weak signature algorithm: SHA1-RSA", "Replace the certificate with one using a modern SHA-256-or-stronger signature."},
		{"chain failure", certinfo.ChainInfo{Valid: false, Error: "x509: certificate signed by unknown authority"}, nil, "tls.certificate.chain-validation", constants.SeverityHigh, "x509: certificate signed by unknown authority", "Install the complete chain issued by a trusted certificate authority."},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := CertificateFindings(resource, tt.chain, tt.validations)
			if len(findings) != 1 {
				t.Fatalf("findings length = %d, want 1: %#v", len(findings), findings)
			}
			got := findings[0]
			if got.RuleID != tt.ruleID || got.Severity != tt.severity || got.Evidence != tt.evidence || got.Remediation != tt.remediation {
				t.Errorf("finding = %#v, want rule=%q severity=%q evidence=%q remediation=%q", got, tt.ruleID, tt.severity, tt.evidence, tt.remediation)
			}
			if got.Resource != resource || got.Status != "open" {
				t.Errorf("resource/status = %q/%q, want %q/open", got.Resource, got.Status, resource)
			}
		})
	}
}

func TestTLSObservationsExposeConnectionFacts(t *testing.T) {
	observations := TLSObservations(certinfo.ChainInfo{
		Host:        "example.test",
		Port:        443,
		Valid:       true,
		TLSVersion:  tls.VersionTLS13,
		CipherSuite: tls.TLS_AES_128_GCM_SHA256,
	})

	want := map[string]string{
		"tls.cipher_suite": tls.CipherSuiteName(tls.TLS_AES_128_GCM_SHA256),
		"tls.chain_valid":  "true",
		"tls.version":      "TLS 1.3",
	}
	if len(observations) != len(want) {
		t.Fatalf("observations length = %d, want %d", len(observations), len(want))
	}
	for _, observation := range observations {
		if want[observation.Key] != observation.Value {
			t.Errorf("observation %q = %q, want %q", observation.Key, observation.Value, want[observation.Key])
		}
	}
}

func TestCertificateFindingsDoesNotMutateInputs(t *testing.T) {
	chain := certinfo.ChainInfo{Error: "chain error"}
	validation := certinfo.ValidationResult{Warnings: []string{"Weak signature algorithm: SHA1-RSA"}}
	beforeError := chain.Error

	_ = CertificateFindings("https://example.test/", chain, []certinfo.ValidationResult{validation})

	if chain.Error != beforeError || validation.Warnings[0] != "Weak signature algorithm: SHA1-RSA" {
		t.Error("CertificateFindings mutated its analysis inputs")
	}
}

func TestCertificateFindingTitlesAreStable(t *testing.T) {
	findings := CertificateFindings("https://example.test/", certinfo.ChainInfo{}, []certinfo.ValidationResult{{Expired: true, ChainErrors: []string{"Certificate has expired"}}})
	if got, want := findings[0].Title, "Certificate has expired"; got != want {
		t.Errorf("title = %q, want %q", got, want)
	}
	if findings[0].Description == "" || findings[0].Resource == "" || findings[0].Evidence == "" {
		t.Errorf("finding must include report fields: %#v", findings[0])
	}
}

func TestCertificateFindingsDeduplicatesRepeatedValidationMessages(t *testing.T) {
	validation := certinfo.ValidationResult{
		Expired:     true,
		ChainErrors: []string{"Certificate has expired", "Certificate has expired"},
	}
	findings := CertificateFindings("https://example.test/", certinfo.ChainInfo{}, []certinfo.ValidationResult{validation})
	if len(findings) != 1 {
		t.Errorf("findings length = %d, want 1", len(findings))
	}
}

func TestCertificateFindingsAcceptsMultipleCertificates(t *testing.T) {
	validations := []certinfo.ValidationResult{
		{Expired: true, ChainErrors: []string{"Certificate has expired"}},
		{NotYetValid: true, ChainErrors: []string{"Certificate is not yet valid"}},
	}
	findings := CertificateFindings("https://example.test/", certinfo.ChainInfo{}, validations)
	if len(findings) != 2 {
		t.Errorf("findings length = %d, want 2", len(findings))
	}
}

func TestCertificateFindingsAllowsFutureCertificateValidationAtCallersChoice(t *testing.T) {
	validation := certinfo.ValidationResult{Warnings: []string{"Certificate expires in 7 days"}}
	findings := CertificateFindings("https://example.test/", certinfo.ChainInfo{}, []certinfo.ValidationResult{validation})
	if len(findings) != 0 {
		t.Errorf("findings = %#v, want no finding for the informational expiry warning", findings)
	}
}

func TestHTTPHeaderFindingsIgnoresUnrelatedLegacyFindings(t *testing.T) {
	findings := HTTPHeaderFindings("https://example.test/", []models.VulnResult{{Type: constants.VulnXSS, Severity: constants.SeverityHigh}})
	if len(findings) != 0 {
		t.Errorf("findings = %#v, want none", findings)
	}
}

func TestHTTPHeaderFindingsAggregateCookiesIntoOneStableReportIdentity(t *testing.T) {
	const resource = "https://example.test/"
	cookies := []models.VulnResult{
		{Type: constants.VulnHeaders, Severity: constants.SeverityMedium, Parameter: "Cookie: session", Evidence: "missing Secure flag", Remediation: "Set Secure, HttpOnly, and SameSite=Strict flags on sensitive cookies."},
		{Type: constants.VulnHeaders, Severity: constants.SeverityMedium, Parameter: "Cookie: preferences", Evidence: "missing Secure flag", Remediation: "Set Secure, HttpOnly, and SameSite=Strict flags on sensitive cookies."},
		{Type: constants.VulnHeaders, Severity: constants.SeverityMedium, Parameter: "Cookie: cart", Evidence: "missing HttpOnly flag", Remediation: "Set Secure, HttpOnly, and SameSite=Strict flags on sensitive cookies."},
	}

	rawForward := HTTPHeaderFindings(resource, cookies)
	if len(rawForward) != 1 {
		t.Fatalf("raw findings length = %d, want 1", len(rawForward))
	}
	if got, want := rawForward[0].Parameter, "Cookie: cart; Cookie: preferences; Cookie: session"; got != want {
		t.Errorf("raw parameter = %q, want %q", got, want)
	}
	forward := report.NewReport(report.ToolInfo{}, report.AuditInfo{}, rawForward, nil, nil)
	reversed := report.NewReport(report.ToolInfo{}, report.AuditInfo{}, HTTPHeaderFindings(resource, []models.VulnResult{cookies[2], cookies[1], cookies[0]}), nil, nil)
	if len(forward.Findings) != 1 {
		t.Fatalf("normalized findings length = %d, want 1", len(forward.Findings))
	}
	if forward.Findings[0].ID == "" || forward.Findings[0].RuleID != "http.cookie.security-flags" {
		t.Errorf("aggregated finding = %#v, want one identified cookie finding", forward.Findings[0])
	}
	if got, want := forward.Findings[0].Parameter, "Cookie: <redacted>"; got != want {
		t.Errorf("normalized parameter = %q, want %q", got, want)
	}
	if got, want := forward.Findings[0].Evidence, "missing HttpOnly flag; missing Secure flag"; got != want {
		t.Errorf("evidence = %q, want %q", got, want)
	}
	if !reflect.DeepEqual(forward.Findings, reversed.Findings) {
		t.Errorf("normalized findings depend on input order:\nforward=%#v\nreversed=%#v", forward.Findings, reversed.Findings)
	}
}

func TestCertificateFindingsFindsWeakSignatureByExistingWarning(t *testing.T) {
	validation := certinfo.ValidationResult{Warnings: []string{"Certificate expires in 10 days", "Weak signature algorithm: MD5-RSA"}}
	findings := CertificateFindings("https://example.test/", certinfo.ChainInfo{}, []certinfo.ValidationResult{validation})
	if len(findings) != 1 || findings[0].RuleID != "tls.certificate.weak-signature" {
		t.Errorf("findings = %#v, want weak signature finding", findings)
	}
}

func TestCertificateFindingsAggregateWeakSignaturesIntoOneStableReportIdentity(t *testing.T) {
	const resource = "https://example.test/"
	validations := []certinfo.ValidationResult{
		{Warnings: []string{"Weak signature algorithm: SHA1-RSA"}},
		{Warnings: []string{"Weak signature algorithm: MD5-RSA"}},
		{Warnings: []string{"Weak signature algorithm: SHA1-RSA"}},
	}

	forward := report.NewReport(report.ToolInfo{}, report.AuditInfo{}, CertificateFindings(resource, certinfo.ChainInfo{}, validations), nil, nil)
	reversed := report.NewReport(report.ToolInfo{}, report.AuditInfo{}, CertificateFindings(resource, certinfo.ChainInfo{}, []certinfo.ValidationResult{validations[2], validations[1], validations[0]}), nil, nil)
	if len(forward.Findings) != 1 {
		t.Fatalf("normalized findings length = %d, want 1", len(forward.Findings))
	}
	if got, want := forward.Findings[0].Evidence, "Weak signature algorithm: MD5-RSA; Weak signature algorithm: SHA1-RSA"; got != want {
		t.Errorf("evidence = %q, want %q", got, want)
	}
	if forward.Findings[0].ID == "" || !reflect.DeepEqual(forward.Findings, reversed.Findings) {
		t.Errorf("weak signature finding identity/output is not stable: forward=%#v reversed=%#v", forward.Findings, reversed.Findings)
	}
}

func TestCertificateFindingsClassifyVerifyFailuresWithoutMisleadingChainDuplicates(t *testing.T) {
	const resource = "https://example.test/"

	tests := []struct {
		name        string
		chain       certinfo.ChainInfo
		validation  certinfo.ValidationResult
		wantRule    string
		wantRemedy  string
		wantFinding int
	}{
		{
			name:       "expired",
			chain:      certinfo.ChainInfo{Valid: false, Error: "x509: certificate has expired", VerificationError: x509.CertificateInvalidError{Reason: x509.Expired}},
			validation: certinfo.ValidationResult{Expired: true, ChainErrors: []string{"Certificate has expired"}},
			wantRule:   "tls.certificate.expired", wantRemedy: "Replace the certificate with one valid for the current time.", wantFinding: 1,
		},
		{
			name:       "not yet valid",
			chain:      certinfo.ChainInfo{Valid: false, Error: "x509: certificate is not yet valid", VerificationError: x509.CertificateInvalidError{Reason: x509.Expired}},
			validation: certinfo.ValidationResult{NotYetValid: true, ChainErrors: []string{"Certificate is not yet valid"}},
			wantRule:   "tls.certificate.not-yet-valid", wantRemedy: "Deploy a certificate whose validity period has begun.", wantFinding: 1,
		},
		{
			name:     "hostname mismatch",
			chain:    certinfo.ChainInfo{Valid: false, Error: "x509: certificate is not valid for example.test", VerificationError: x509.HostnameError{Certificate: &x509.Certificate{}, Host: "example.test"}},
			wantRule: "tls.certificate.hostname-mismatch", wantRemedy: "Use a certificate whose DNS names or IP addresses cover the audited host.", wantFinding: 1,
		},
		{
			name:     "incompatible key usage",
			chain:    certinfo.ChainInfo{Valid: false, Error: "x509: certificate specifies an incompatible key usage", VerificationError: x509.CertificateInvalidError{Reason: x509.IncompatibleUsage}},
			wantRule: "tls.certificate.incompatible-usage", wantRemedy: "Use a certificate authorized for TLS server authentication.", wantFinding: 1,
		},
		{
			name:     "unknown authority chain failure",
			chain:    certinfo.ChainInfo{Valid: false, Error: "x509: certificate signed by unknown authority", VerificationError: x509.UnknownAuthorityError{Cert: &x509.Certificate{}}},
			wantRule: "tls.certificate.chain-validation", wantRemedy: "Install the complete chain issued by a trusted certificate authority.", wantFinding: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := CertificateFindings(resource, tt.chain, []certinfo.ValidationResult{tt.validation})
			if len(findings) != tt.wantFinding {
				t.Fatalf("findings length = %d, want %d: %#v", len(findings), tt.wantFinding, findings)
			}
			if got := findings[0]; got.RuleID != tt.wantRule || got.Remediation != tt.wantRemedy {
				t.Errorf("finding = %#v, want rule=%q remediation=%q", got, tt.wantRule, tt.wantRemedy)
			}
			for _, finding := range findings {
				if finding.RuleID == "tls.certificate.chain-validation" && tt.wantRule != finding.RuleID {
					t.Errorf("unexpected generic chain finding for %s: %#v", tt.name, finding)
				}
			}
		})
	}
}

func TestTLSObservationsOmitUnavailableHandshakeValues(t *testing.T) {
	observations := TLSObservations(certinfo.ChainInfo{Valid: false})
	for _, observation := range observations {
		if observation.Key == "tls.version" || observation.Key == "tls.cipher_suite" {
			t.Errorf("unexpected unavailable handshake observation: %#v", observation)
		}
	}
}

func TestCertificateFindingsOrderIsStable(t *testing.T) {
	validations := []certinfo.ValidationResult{{SelfSigned: true, Warnings: []string{"Certificate is self-signed"}}, {Expired: true, ChainErrors: []string{"Certificate has expired"}}}
	findings := CertificateFindings("https://example.test/", certinfo.ChainInfo{}, validations)
	if len(findings) != 2 || findings[0].RuleID != "tls.certificate.expired" || findings[1].RuleID != "tls.certificate.self-signed" {
		t.Errorf("finding order = %#v, want lexical rule order", findings)
	}
}

func TestCertificateFindingsUsesSuppliedAnalysisNotWallClock(t *testing.T) {
	validation := certinfo.ValidationResult{Expired: true, ChainErrors: []string{"Certificate has expired"}}
	start := time.Now()
	findings := CertificateFindings("https://example.test/", certinfo.ChainInfo{}, []certinfo.ValidationResult{validation})
	if time.Since(start) > time.Second || len(findings) != 1 {
		t.Errorf("CertificateFindings should be a fast pure conversion, findings=%#v", findings)
	}
}
