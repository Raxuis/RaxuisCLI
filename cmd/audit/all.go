package audit

import (
	"context"
	"fmt"
	"time"

	"github.com/Raxuis/RaxuisCLI/cmd"
	"github.com/Raxuis/RaxuisCLI/internal/audit/combined"
	sharedcommand "github.com/Raxuis/RaxuisCLI/internal/shared/command"
	"github.com/Raxuis/RaxuisCLI/internal/shared/render"
	"github.com/Raxuis/RaxuisCLI/internal/shared/report"
	"github.com/spf13/cobra"
)

type combinedAuditRunner func(context.Context, string, combined.Options) (report.Report, error)

func newAllCommand(runner combinedAuditRunner) *cobra.Command {
	command := &cobra.Command{Args: exactlyOneAuditTarget}
	command.Use = "all <http-or-https-url>"
	command.Short = "Combine web, DNS, and TLS posture audits in one versioned report"
	command.Long = `Audit a URL's web, DNS/email, and TLS posture in one comparable report.
DNS is skipped for IP targets; TLS is skipped for HTTP URLs. AXFR is disabled
unless --axfr is supplied. Collection failures preserve available results and
produce a partial report (exit 1); --fail-on applies to complete reports (exit 2).

Examples:
  raxuiscli audit all https://example.com
  raxuiscli --output=json --output-file report.json audit all https://example.com
  raxuiscli --fail-on=high audit all https://example.com --timeout=60s
  raxuiscli audit all https://example.com --axfr`
	addWebAuditFlags(command, 60*time.Second)
	command.Flags().String("nameserver", "", "Custom DNS nameserver (host or host:port)")
	command.Flags().Bool("axfr", false, "Attempt DNS zone transfers against authoritative nameservers")
	command.RunE = func(command *cobra.Command, args []string) error { return runCombinedAudit(command, args[0], runner) }
	return command
}

func runCombinedAudit(command *cobra.Command, target string, runner combinedAuditRunner) error {
	options, err := cmd.OptionsFromCommand(command)
	if err != nil {
		return err
	}
	webOptions, err := auditOptionsFromCommand(command)
	if err != nil {
		return sharedcommand.NewOperationalError(err)
	}
	nameserver, err := command.Flags().GetString("nameserver")
	if err != nil {
		return sharedcommand.NewOperationalError(err)
	}
	axfr, err := command.Flags().GetBool("axfr")
	if err != nil {
		return sharedcommand.NewOperationalError(err)
	}
	if webOptions.Timeout <= 0 {
		return sharedcommand.NewOperationalError(fmt.Errorf("timeout must be positive"))
	}
	value, err := runner(command.Context(), target, combined.Options{Timeout: webOptions.Timeout, Web: webOptions, Nameserver: nameserver, AXFR: axfr})
	if err != nil {
		return sharedcommand.NewOperationalError(err)
	}
	value.Tool = buildToolInfo()
	renderer, err := render.RendererFor(options.Output)
	if err != nil {
		return sharedcommand.NewOperationalError(err)
	}
	if options.OutputFile != "" {
		err = report.WriteFile(options.OutputFile, value, renderer, options.Force)
	} else {
		err = renderer.Render(command.OutOrStdout(), value)
	}
	if err != nil {
		return sharedcommand.NewOperationalError(err)
	}
	if value.Audit.Status == "partial" {
		return sharedcommand.NewOperationalError(fmt.Errorf("combined audit completed partially"))
	}
	if severity, matched := highestSeverityAt(options.FailOn, value); matched {
		return sharedcommand.NewPolicyError(severity, options.FailOn)
	}
	return nil
}
