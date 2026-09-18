package audit

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/Raxuis/RaxuisCLI/cmd"
	dnsaudit "github.com/Raxuis/RaxuisCLI/internal/audit/dns"
	sharedcommand "github.com/Raxuis/RaxuisCLI/internal/shared/command"
	"github.com/Raxuis/RaxuisCLI/internal/shared/render"
	"github.com/Raxuis/RaxuisCLI/internal/shared/report"
)

// dnsAuditRunner keeps the Cobra layer testable while production uses the real
// DNS audit service.
type dnsAuditRunner func(context.Context, string, dnsaudit.Options) (report.Report, error)

func newDNSCommand(runner dnsAuditRunner) *cobra.Command {
	command := &cobra.Command{
		Use:   "dns <domain>",
		Short: "Audit a domain's DNS/email posture and produce a versioned report",
		Long: `Assess a domain's DNS and email-authentication posture, then emit a
schema-v1 report that can be diffed with 'compare' and gated with --fail-on.

Checks SPF and DMARC records, and whether nameservers allow zone transfers
(AXFR). Records observed (NS, MX, A) are attached as observations. Run it only
against domains you are authorized to test.

Examples:
  raxuiscli audit dns example.com
  raxuiscli --output=json --output-file before.json audit dns example.com
  raxuiscli --fail-on=high audit dns example.com
  raxuiscli audit dns example.com --skip-axfr`,
		Args: exactlyOneAuditTarget,
		RunE: func(command *cobra.Command, args []string) error {
			return runDNSAudit(command, args[0], runner)
		},
	}

	command.Flags().String("nameserver", "", "Custom nameserver (host or host:port)")
	command.Flags().Int("timeout", 10, "Per-query timeout in seconds")
	command.Flags().Bool("skip-axfr", false, "Skip zone-transfer (AXFR) checks")
	return command
}

func runDNSAudit(command *cobra.Command, target string, runner dnsAuditRunner) error {
	options, err := cmd.OptionsFromCommand(command)
	if err != nil {
		return err
	}
	nameserver, err := command.Flags().GetString("nameserver")
	if err != nil {
		return sharedcommand.NewOperationalError(err)
	}
	timeout, err := command.Flags().GetInt("timeout")
	if err != nil {
		return sharedcommand.NewOperationalError(err)
	}
	skipAXFR, err := command.Flags().GetBool("skip-axfr")
	if err != nil {
		return sharedcommand.NewOperationalError(err)
	}

	auditContext := command.Context()
	if auditContext == nil {
		auditContext = context.Background()
	}
	value, err := runner(auditContext, target, dnsaudit.Options{
		Nameserver: nameserver,
		Timeout:    timeout,
		SkipAXFR:   skipAXFR,
	})
	if err != nil {
		return sharedcommand.NewOperationalError(err)
	}
	value.Tool = buildToolInfo()

	renderer, err := render.RendererFor(options.Output)
	if err != nil {
		return sharedcommand.NewOperationalError(err)
	}
	if options.OutputFile != "" {
		if err := report.WriteFile(options.OutputFile, value, renderer, options.Force); err != nil {
			return sharedcommand.NewOperationalError(err)
		}
	} else if err := renderer.Render(command.OutOrStdout(), value); err != nil {
		return sharedcommand.NewOperationalError(err)
	}

	if value.Audit.Status == "partial" {
		return sharedcommand.NewOperationalError(fmt.Errorf("dns audit completed partially"))
	}
	if severity, matched := highestSeverityAt(options.FailOn, value); matched {
		return sharedcommand.NewPolicyError(severity, options.FailOn)
	}
	return nil
}
