// Package dns audits a domain's DNS/email posture (SPF, DMARC, zone transfer)
// and returns a versioned, comparable report.
package dns

import (
	"context"
	"fmt"
	"strings"
	"time"

	netdns "github.com/Raxuis/RaxuisCLI/internal/network/dns"
	"github.com/Raxuis/RaxuisCLI/internal/shared/constants"
	"github.com/Raxuis/RaxuisCLI/internal/shared/models"
	"github.com/Raxuis/RaxuisCLI/internal/shared/report"
)

// Options configures a DNS audit.
type Options struct {
	Nameserver string
	Timeout    int // seconds
	SkipAXFR   bool
}

// Audit inspects target's DNS records and returns a schema-v1 report. The Tool
// field is left for the command layer to populate.
func Audit(_ context.Context, target string, opts Options) (report.Report, error) {
	domain := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(target)), ".")
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 10
	}

	started := time.Now()

	txt := lookup(domain, netdns.TypeTXT, opts.Nameserver, timeout)
	dmarc := lookup("_dmarc."+domain, netdns.TypeTXT, opts.Nameserver, timeout)
	mx := lookup(domain, netdns.TypeMX, opts.Nameserver, timeout)
	ns := lookup(domain, netdns.TypeNS, opts.Nameserver, timeout)
	aRecords := lookup(domain, netdns.TypeA, opts.Nameserver, timeout)

	spf := firstWithPrefix(txt, "v=spf1")
	dmarcRecord := firstWithPrefix(dmarc, "v=dmarc1")

	var findings []models.VulnResult
	findings = append(findings, spfFindings(domain, spf)...)
	findings = append(findings, dmarcFindings(domain, dmarcRecord)...)
	if !opts.SkipAXFR {
		findings = append(findings, axfrFindings(domain, ns, timeout)...)
	}

	audit := report.AuditInfo{
		Kind:      "dns",
		Target:    domain,
		StartedAt: started,
		Duration:  time.Since(started),
		Status:    "complete",
	}
	return report.NewReport(
		report.ToolInfo{},
		audit,
		findings,
		observations(ns, mx, aRecords, spf, dmarcRecord),
		nil,
	), nil
}

func spfFindings(domain, spf string) []models.VulnResult {
	if spf == "" {
		return []models.VulnResult{finding(
			"dns.spf-missing", "No SPF record", constants.SeverityMedium, domain,
			"No v=spf1 TXT record was found.",
			"Publish an SPF record ending in -all (or ~all) to limit who can send mail as this domain.",
		)}
	}
	low := strings.ToLower(spf)
	switch {
	case strings.Contains(low, "+all"):
		return []models.VulnResult{finding(
			"dns.spf-permissive", "SPF allows any sender (+all)", constants.SeverityHigh, domain,
			"SPF record contains +all: "+spf,
			"Replace +all with -all (hard fail) or ~all (soft fail).",
		)}
	case strings.Contains(low, "?all"):
		return []models.VulnResult{finding(
			"dns.spf-neutral", "SPF policy is neutral (?all)", constants.SeverityLow, domain,
			"SPF record ends in ?all: "+spf,
			"Use -all or ~all so receivers can act on SPF failures.",
		)}
	case !strings.Contains(low, "-all") && !strings.Contains(low, "~all"):
		return []models.VulnResult{finding(
			"dns.spf-no-all", "SPF has no 'all' mechanism", constants.SeverityLow, domain,
			"SPF record has no terminating all mechanism: "+spf,
			"Append -all or ~all to define the default policy.",
		)}
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
	if strings.Contains(strings.ToLower(dmarc), "p=none") {
		return []models.VulnResult{finding(
			"dns.dmarc-none", "DMARC policy is p=none", constants.SeverityLow, domain,
			"DMARC is monitor-only: "+dmarc,
			"Move to p=quarantine, then p=reject, once reports look clean.",
		)}
	}
	return nil
}

func axfrFindings(domain string, nameservers []string, timeout int) []models.VulnResult {
	var findings []models.VulnResult
	for _, server := range nameservers {
		server = strings.TrimSuffix(server, ".")
		if server == "" {
			continue
		}
		res := netdns.AttemptAXFR(domain, server, timeout)
		if res.Success && len(res.Records) > 0 {
			findings = append(findings, finding(
				"dns.axfr-"+slug(server), "Zone transfer allowed by "+server, constants.SeverityCritical, domain,
				fmt.Sprintf("AXFR from %s returned %d records.", server, len(res.Records)),
				"Restrict zone transfers (AXFR) to authorized secondary nameservers only.",
			))
		}
	}
	return findings
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

func lookup(name string, recordType netdns.RecordType, nameserver string, timeout int) []string {
	results := netdns.Lookup(netdns.LookupOptions{
		Domain:     name,
		RecordType: recordType,
		Nameserver: nameserver,
		Timeout:    timeout,
	})
	var records []string
	for _, r := range results {
		if r.Error == nil {
			records = append(records, r.Records...)
		}
	}
	return records
}

func firstWithPrefix(records []string, prefix string) string {
	for _, r := range records {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(r)), prefix) {
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
