// Package dns audits a domain's DNS/email posture (SPF, DMARC, zone transfer)
// and returns a versioned, comparable report.
package dns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	netdns "github.com/Raxuis/RaxuisCLI/internal/network/dns"
	"github.com/Raxuis/RaxuisCLI/internal/shared/constants"
	"github.com/Raxuis/RaxuisCLI/internal/shared/models"
	"github.com/Raxuis/RaxuisCLI/internal/shared/report"

	"golang.org/x/net/idna"
)

// Options configures a DNS audit.
type Options struct {
	Nameserver string
	Timeout    int // seconds
	SkipAXFR   bool
}

type lookupFunc func(context.Context, string, netdns.RecordType, string, int) ([]string, error)

func Audit(ctx context.Context, target string, opts Options) (report.Report, error) {
	return auditWithLookup(ctx, target, opts, lookup)
}

func auditWithLookup(ctx context.Context, target string, opts Options, query lookupFunc) (report.Report, error) {
	if ctx == nil {
		return report.Report{}, fmt.Errorf("audit context must not be nil")
	}
	if err := ctx.Err(); err != nil {
		return report.Report{}, err
	}
	domain, err := idna.Lookup.ToASCII(strings.TrimSuffix(strings.ToLower(strings.TrimSpace(target)), "."))
	if err != nil || domain == "" || len(domain) > 253 || net.ParseIP(domain) != nil {
		return report.Report{}, fmt.Errorf("audit target must be a DNS domain")
	}
	for _, label := range strings.Split(domain, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return report.Report{}, fmt.Errorf("invalid DNS domain")
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return report.Report{}, fmt.Errorf("invalid DNS domain")
			}
		}
	}
	if opts.Timeout < 0 {
		return report.Report{}, fmt.Errorf("timeout must be positive")
	}
	timeout := opts.Timeout
	if timeout == 0 {
		timeout = 10
	}
	started := time.Now()
	var reportErrors []report.ReportError
	collect := func(name string, kind netdns.RecordType) ([]string, bool) {
		records, err := query(ctx, name, kind, opts.Nameserver, timeout)
		if err != nil {
			reportErrors = append(reportErrors, report.ReportError{Code: "dns.lookup_failed", Message: fmt.Sprintf("%s %s: %v", name, kind, err)})
			return nil, false
		}
		return records, true
	}
	txt, txtOK := collect(domain, netdns.TypeTXT)
	dmarc, dmarcOK := collect("_dmarc."+domain, netdns.TypeTXT)
	mx, _ := collect(domain, netdns.TypeMX)
	ns, _ := collect(domain, netdns.TypeNS)
	aRecords, _ := collect(domain, netdns.TypeA)

	spfRecords := recordsWithPrefix(txt, "v=spf1")
	spf := firstWithPrefix(txt, "v=spf1")
	dmarcRecords := recordsWithPrefix(dmarc, "v=dmarc1")
	dmarcRecord := firstWithPrefix(dmarc, "v=dmarc1")
	var findings []models.VulnResult
	if txtOK {
		if len(spfRecords) > 1 {
			findings = append(findings, finding("dns.spf-multiple", "Multiple SPF records", constants.SeverityMedium, domain, strings.Join(spfRecords, " | "), "Publish a single SPF record for the domain."))
		} else {
			findings = append(findings, spfFindings(domain, spf)...)
		}
	}
	if dmarcOK {
		if len(dmarcRecords) > 1 {
			findings = append(findings, finding("dns.dmarc-multiple", "Multiple DMARC records", constants.SeverityMedium, domain, strings.Join(dmarcRecords, " | "), "Publish a single DMARC record at _dmarc."))
		} else {
			findings = append(findings, dmarcFindings(domain, dmarcRecord)...)
		}
	}
	if !opts.SkipAXFR && ctx.Err() == nil {
		axfrResults, axfrErrors := axfrFindings(ctx, domain, ns, timeout)
		findings = append(findings, axfrResults...)
		reportErrors = append(reportErrors, axfrErrors...)
	}
	status := "complete"
	if len(reportErrors) > 0 {
		status = "partial"
	}
	obs := observations(ns, mx, aRecords, spf, dmarcRecord)
	for i := range obs {
		if obs[i].Key == "dns.spf" && !txtOK || obs[i].Key == "dns.dmarc" && !dmarcOK {
			obs[i].Value = "unknown"
		}
	}
	return report.NewReport(report.ToolInfo{}, report.AuditInfo{
		Kind: "dns", Target: domain, StartedAt: started, Duration: time.Since(started), Status: status,
	}, findings, obs, reportErrors), nil
}

func spfFindings(domain, spf string) []models.VulnResult {
	spf = strings.TrimSpace(spf)
	if spf == "" {
		return []models.VulnResult{finding(
			"dns.spf-missing", "No SPF record", constants.SeverityMedium, domain,
			"No v=spf1 TXT record was found.",
			"Publish an SPF record ending in -all (or ~all) to limit who can send mail as this domain.",
		)}
	}
	policy := ""
	redirect := false
	for _, term := range strings.Fields(strings.ToLower(spf))[1:] {
		if strings.HasPrefix(term, "redirect=") && len(term) > len("redirect=") {
			redirect = true
		}
		if term == "all" || term == "+all" || term == "?all" || term == "-all" || term == "~all" {
			policy = term
			break
		}
	}
	switch policy {
	case "all", "+all":
		return []models.VulnResult{finding("dns.spf-permissive", "SPF allows any sender (all)", constants.SeverityHigh, domain, "SPF record allows all senders: "+spf, "Replace all with -all (hard fail) or ~all (soft fail).")}
	case "?all":
		return []models.VulnResult{finding("dns.spf-neutral", "SPF policy is neutral (?all)", constants.SeverityLow, domain, "SPF record contains ?all: "+spf, "Use -all or ~all so receivers can act on SPF failures.")}
	case "":
		if redirect {
			return nil
		}
		return []models.VulnResult{finding("dns.spf-no-all", "SPF has no 'all' mechanism", constants.SeverityLow, domain, "SPF record has no all mechanism: "+spf, "Review the default policy and any redirect modifier; use -all or ~all when appropriate.")}
	}

	return nil
}

func dmarcFindings(domain, dmarc string) []models.VulnResult {
	if dmarc == "" {
		return []models.VulnResult{finding(
			"dns.dmarc-missing", "No DMARC record", constants.SeverityMedium, domain,
			"No v=DMARC1 TXT record was found at _dmarc."+domain+".",
			"Publish a DMARC record with p=quarantine or p=reject.",
		)}
	}
	policy := ""
	for _, tag := range strings.Split(dmarc, ";") {
		name, value, ok := strings.Cut(tag, "=")
		if ok && strings.EqualFold(strings.TrimSpace(name), "p") {
			policy = strings.ToLower(strings.TrimSpace(value))
			break
		}
	}
	if policy != "none" && policy != "reject" && policy != "quarantine" {
		return []models.VulnResult{finding("dns.dmarc-invalid-policy", "DMARC policy is missing or invalid", constants.SeverityMedium, domain, "Invalid DMARC policy: "+dmarc, "Publish one p=none, p=quarantine, or p=reject policy tag.")}
	}
	if policy == "none" {
		return []models.VulnResult{finding(
			"dns.dmarc-none", "DMARC policy is p=none", constants.SeverityLow, domain,
			"DMARC is monitor-only: "+dmarc,
			"Move to p=quarantine, then p=reject, once reports look clean.",
		)}
	}
	return nil
}

func axfrFindings(ctx context.Context, domain string, nameservers []string, timeout int) ([]models.VulnResult, []report.ReportError) {
	var reportErrors []report.ReportError
	var findings []models.VulnResult
	for _, server := range nameservers {
		server = strings.TrimSuffix(server, ".")
		if server == "" {
			continue
		}
		res := netdns.AttemptAXFRContext(ctx, domain, server, timeout)
		if res.Error != nil && !errors.Is(res.Error, netdns.ErrAXFRDenied) {
			reportErrors = append(reportErrors, report.ReportError{Code: "dns.axfr_failed", Message: fmt.Sprintf("%s: %v", server, res.Error)})
		}
		if res.Success && len(res.Records) > 0 {
			findings = append(findings, finding(
				"dns.axfr-"+slug(server), "Zone transfer allowed by "+server, constants.SeverityCritical, domain,
				fmt.Sprintf("AXFR from %s returned %d records.", server, len(res.Records)),
				"Restrict zone transfers (AXFR) to authorized secondary nameservers only.",
			))
		}
	}
	return findings, reportErrors
}

func observations(ns, mx, aRecords []string, spf, dmarc string) []report.Observation {
	obs := []report.Observation{
		{Key: "dns.spf", Value: valueOrNone(spf)},
		{Key: "dns.dmarc", Value: valueOrNone(dmarc)},
	}
	for _, n := range ns {
		obs = append(obs, report.Observation{Key: "dns.nameserver", Value: strings.TrimSuffix(n, ".")})
	}
	for _, m := range mx {
		obs = append(obs, report.Observation{Key: "dns.mx", Value: m})
	}
	for _, a := range aRecords {
		obs = append(obs, report.Observation{Key: "dns.a", Value: a})
	}
	return obs
}

func finding(ruleID, title string, severity constants.Severity, resource, evidence, remediation string) models.VulnResult {
	return models.VulnResult{
		RuleID:      ruleID,
		Title:       title,
		Type:        constants.VulnType("DNS"),
		Severity:    severity,
		Resource:    resource,
		Evidence:    evidence,
		Remediation: remediation,
		Status:      "open",
	}
}

func lookup(ctx context.Context, name string, recordType netdns.RecordType, nameserver string, timeout int) ([]string, error) {
	results := netdns.LookupContext(ctx, netdns.LookupOptions{Domain: name, RecordType: recordType, Nameserver: nameserver, Timeout: timeout})
	var records []string
	for _, r := range results {
		if r.Error != nil {
			var dnsErr *net.DNSError
			if errors.As(r.Error, &dnsErr) && dnsErr.IsNotFound {
				continue
			}
			return nil, r.Error
		}
		records = append(records, r.Records...)
	}
	return records, nil
}

func firstWithPrefix(records []string, prefix string) string {
	for _, r := range records {
		value := strings.ToLower(strings.TrimSpace(r))
		if value == prefix || strings.HasPrefix(value, prefix+" ") || strings.HasPrefix(value, prefix+";") {
			return strings.TrimSpace(r)
		}
	}
	return ""
}

func valueOrNone(v string) string {
	if v == "" {
		return "none"
	}
	return v
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

func recordsWithPrefix(records []string, prefix string) []string {
	var matches []string
	for _, record := range records {
		if value := firstWithPrefix([]string{record}, prefix); value != "" {
			matches = append(matches, value)
		}
	}
	return matches
}
