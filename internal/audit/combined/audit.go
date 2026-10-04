package combined

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	dnsaudit "github.com/Raxuis/RaxuisCLI/internal/audit/dns"
	tlsaudit "github.com/Raxuis/RaxuisCLI/internal/audit/tls"
	webaudit "github.com/Raxuis/RaxuisCLI/internal/audit/web"
	"github.com/Raxuis/RaxuisCLI/internal/shared/models"
	"github.com/Raxuis/RaxuisCLI/internal/shared/report"
)

type Options struct {
	Timeout    time.Duration
	Web        webaudit.Options
	Nameserver string
	AXFR       bool
	WebRunner  func(context.Context, string, webaudit.Options) (report.Report, error)
	DNSRunner  func(context.Context, string, dnsaudit.Options) (report.Report, error)
	TLSRunner  func(context.Context, string, tlsaudit.Options) (report.Report, error)
}

func Audit(ctx context.Context, rawTarget string, options Options) (report.Report, error) {
	if ctx == nil {
		return report.Report{}, fmt.Errorf("audit context must not be nil")
	}
	target, err := webaudit.ParseTarget(rawTarget)
	if err != nil {
		return report.Report{}, err
	}
	if options.Timeout < 0 {
		return report.Report{}, fmt.Errorf("timeout must be positive")
	}
	timeout := options.Timeout
	if timeout == 0 {
		timeout = 60 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	started := time.Now()
	webRunner, dnsRunner, tlsRunner := options.WebRunner, options.DNSRunner, options.TLSRunner
	if webRunner == nil {
		webRunner = webaudit.Audit
	}
	if dnsRunner == nil {
		dnsRunner = dnsaudit.Audit
	}
	if tlsRunner == nil {
		tlsRunner = tlsaudit.Audit
	}
	options.Web.Timeout = timeout
	host := target.Hostname()
	port := 443
	if target.Port() != "" {
		port, _ = strconv.Atoi(target.Port())
	}
	type stage struct {
		name       string
		skipReason string
		run        func(context.Context) (report.Report, error)
	}
	stages := []stage{
		{name: "web", run: func(ctx context.Context) (report.Report, error) { return webRunner(ctx, target.String(), options.Web) }},
		{name: "dns", run: func(ctx context.Context) (report.Report, error) {
			return dnsRunner(ctx, host, dnsaudit.Options{Nameserver: options.Nameserver, Timeout: 10, SkipAXFR: !options.AXFR})
		}},
		{name: "tls", run: func(ctx context.Context) (report.Report, error) {
			return tlsRunner(ctx, net.JoinHostPort(host, strconv.Itoa(port)), tlsaudit.Options{Port: port, Timeout: 10 * time.Second})
		}},
	}
	if net.ParseIP(host) != nil {
		stages[1].skipReason = "target hostname is an IP address"
	}
	if target.Scheme == "http" {
		stages[2].skipReason = "target scheme is http"
	}
	var findings []models.VulnResult
	var observations []report.Observation
	var reportErrors []report.ReportError
	status := "complete"
	for _, item := range stages {
		key := "combined." + item.name
		if item.skipReason != "" {
			observations = append(observations, report.Observation{Key: key + ".status", Value: "skipped"}, report.Observation{Key: key + ".reason", Value: item.skipReason})
			continue
		}
		stageStatus := "complete"
		var value report.Report
		stageErr := ctx.Err()
		if stageErr == nil {
			value, stageErr = item.run(ctx)
		}
		findings = append(findings, value.Findings...)
		observations = append(observations, value.Observations...)
		reportErrors = append(reportErrors, value.Errors...)
		if stageErr == nil {
			stageErr = ctx.Err()
		}
		if stageErr != nil {
			reportErrors = append(reportErrors, report.ReportError{Code: key + ".failed", Message: stageErr.Error()})
		}
		if stageErr != nil || value.Audit.Status == "partial" || len(value.Errors) > 0 {
			stageStatus, status = "partial", "partial"
		}
		observations = append(observations, report.Observation{Key: key + ".status", Value: stageStatus})
	}
	return report.NewReport(report.ToolInfo{}, report.AuditInfo{Kind: "all", Target: target.String(), StartedAt: started, Duration: time.Since(started), Status: status}, findings, observations, reportErrors), nil
}
