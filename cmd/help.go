package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"raxuiscli/internal/shared/catalog"
)

// Cobra's default templates, extended to show catalog maturity/safety data.
const helpTemplate = `{{with (or .Long .Short)}}{{. | trimTrailingWhitespaces}}

{{end}}{{with catalogMeta .}}{{.}}

{{end}}{{if or .Runnable .HasSubCommands}}{{.UsageString}}{{end}}`

const usageTemplate = `Usage:{{if .Runnable}}
  {{.UseLine}}{{end}}{{if .HasAvailableSubCommands}}
  {{.CommandPath}} [command]{{end}}{{if gt (len .Aliases) 0}}

Aliases:
  {{.NameAndAliases}}{{end}}{{if .HasExample}}

Examples:
{{.Example}}{{end}}{{if .HasAvailableSubCommands}}{{$cmds := .Commands}}{{if eq (len .Groups) 0}}

Available Commands:{{range $cmds}}{{if (or .IsAvailableCommand (eq .Name "help"))}}
  {{rpad .Name .NamePadding }} {{.Short}}{{catalogBadge .}}{{end}}{{end}}{{else}}{{range $group := .Groups}}

{{.Title}}{{range $cmds}}{{if (and (eq .GroupID $group.ID) (or .IsAvailableCommand (eq .Name "help")))}}
  {{rpad .Name .NamePadding }} {{.Short}}{{catalogBadge .}}{{end}}{{end}}{{end}}{{if not .AllChildCommandsHaveGroup}}

Additional Commands:{{range $cmds}}{{if (and (eq .GroupID "") (or .IsAvailableCommand (eq .Name "help")))}}
  {{rpad .Name .NamePadding }} {{.Short}}{{catalogBadge .}}{{end}}{{end}}{{end}}{{end}}{{end}}{{if .HasAvailableLocalFlags}}

Flags:
{{.LocalFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{if .HasAvailableInheritedFlags}}

Global Flags:
{{.InheritedFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{if .HasHelpSubCommands}}

Additional help topics:{{range .Commands}}{{if .IsAdditionalHelpTopicCommand}}
  {{rpad .CommandPath .CommandPathPadding}} {{.Short}}{{end}}{{end}}{{end}}{{if .HasAvailableSubCommands}}

Use "{{.CommandPath}} [command] --help" for more information about a command.{{end}}
`

func init() {
	cobra.AddTemplateFunc("catalogBadge", catalogBadge)
	cobra.AddTemplateFunc("catalogMeta", catalogMeta)
}

// catalogBadge returns " [maturity]" for command, or "" if uncataloged.
func catalogBadge(command *cobra.Command) string {
	entry, ok := catalog.Lookup(command.CommandPath())
	if !ok {
		return ""
	}
	return fmt.Sprintf(" [%s]", entry.Maturity)
}

// catalogMeta returns "Maturity: ... Safety: ..." for command, or "" if uncataloged.
func catalogMeta(command *cobra.Command) string {
	entry, ok := catalog.Lookup(command.CommandPath())
	if !ok {
		return ""
	}
	return fmt.Sprintf("Maturity: %s   Safety: %s", entry.Maturity, entry.Safety)
}
