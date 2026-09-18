package audit

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/Raxuis/RaxuisCLI/cmd"
	tlsaudit "github.com/Raxuis/RaxuisCLI/internal/audit/tls"
	sharedcommand "github.com/Raxuis/RaxuisCLI/internal/shared/command"
	"github.com/Raxuis/RaxuisCLI/internal/shared/render"
	"github.com/Raxuis/RaxuisCLI/internal/shared/report"
)

// tlsAuditRunner keeps the Cobra layer testable while production uses the real
// TLS audit service.
type tlsAuditRunner func(context.Context, string, tlsaudit.Options) (report.Report, error)

func newTLSCommand(runner tlsAuditRunner) *cobra.Command {
	command := &cobra.Command{
		Use:   "tls <host[:port]>",
		Short: "Audit TLS/SSL posture and produce a versioned report",
		Long: `Assess a server's TLS/SSL posture and emit a schema-v1 report.

Reuses the tlsscan engine (protocol versions, cipher suites, certificate) and
records each weakness as a severity-rated finding, so snapshots can be diffed
with 'raxuiscli compare' and gated with --fail-on. Passive: handshakes only.

Examples:
  raxuiscli audit tls example.com
  raxuiscli --output=json audit tls example.com
  raxuiscli --output=json --output-file before.json audit tls example.com
  raxuiscli --fail-on=high audit tls example.com`,
		Args: exactlyOneAuditTarget,
		RunE: func(command *cobra.Command, args []string) error {
			return runTLSAudit(command, args[0], runner)
		},
	}

	command.Flags().Int("port", 443, "Default port when the target omits one")
	command.Flags().Duration("timeout", 10*time.Second, "Per-connection timeout")
	return command
}

func runTLSAudit(command *cobra.Command, target string, runner tlsAuditRunner) error {
	options, err := cmd.OptionsFromCommand(command)
	if err != nil {
		return err
	}
	port, err := command.Flags().GetInt("port")
	if err != nil {
		return sharedcommand.NewOperationalError(err)
	}
	timeout, err := command.Flags().GetDuration("timeout")
	if err != nil {
		return sharedcommand.NewOperationalError(err)
	}

	auditContext := command.Context()
	if auditContext == nil {
		auditContext = context.Background()
	}
	value, err := runner(auditContext, target, tlsaudit.Options{Port: port, Timeout: timeout})
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
		return sharedcommand.NewOperationalError(fmt.Errorf("tls audit completed partially"))
	}
	if severity, matched := highestSeverityAt(options.FailOn, value); matched {
		return sharedcommand.NewPolicyError(severity, options.FailOn)
	}
	return nil
}
