// Package audit exposes passive, report-producing audit commands.
package audit

import (
	"context"

	"github.com/spf13/cobra"

	"github.com/Raxuis/RaxuisCLI/cmd"
	tlsaudit "github.com/Raxuis/RaxuisCLI/internal/audit/tls"
	webaudit "github.com/Raxuis/RaxuisCLI/internal/audit/web"
	"github.com/Raxuis/RaxuisCLI/internal/shared/report"
)

// auditRunner keeps the Cobra layer testable while the production command uses
// the passive web service directly.
type auditRunner func(context.Context, string, webaudit.Options) (report.Report, error)

var auditCmd = newAuditCommand(webaudit.Audit)

func newAuditCommand(runner auditRunner) *cobra.Command {
	command := &cobra.Command{
		Use:   "audit",
		Short: "Passive security audits with versioned reports",
		RunE: func(command *cobra.Command, args []string) error {
			return command.Help()
		},
	}
	command.AddCommand(newWebCommand(runner))
	command.AddCommand(newTLSCommand(tlsaudit.Audit))
	return command
}

func init() {
	cmd.RootCmd.AddCommand(auditCmd)
}
