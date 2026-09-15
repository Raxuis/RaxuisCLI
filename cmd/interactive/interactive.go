// Package interactive exposes the guided terminal interface as a Cobra command.
package interactive

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/Raxuis/RaxuisCLI/cmd"
	sharedcommand "github.com/Raxuis/RaxuisCLI/internal/shared/command"
	"github.com/Raxuis/RaxuisCLI/internal/tui"
)

// deps are injected so the launch decision and the run itself are testable
// without a real terminal.
type deps struct {
	interactive func() bool
	run         func(tui.Config) error
}

func defaultDeps() deps {
	return deps{
		interactive: standardStreamsInteractive,
		run:         tui.Run,
	}
}

var interactiveCmd = newInteractiveCommand(defaultDeps())

func init() {
	cmd.RootCmd.AddCommand(interactiveCmd)
}

func newInteractiveCommand(d deps) *cobra.Command {
	return &cobra.Command{
		Use:   "interactive",
		Short: "Launch the guided terminal interface",
		Long: "Launch the guided terminal interface for passive web audits, the local demo, " +
			"and report comparison. It never starts implicitly, so scripts and pipelines keep " +
			"the stable non-interactive command behavior.",
		Args: func(command *cobra.Command, args []string) error {
			if err := cobra.NoArgs(command, args); err != nil {
				return sharedcommand.NewOperationalError(err)
			}
			return nil
		},
		RunE: func(command *cobra.Command, _ []string) error {
			return run(command, d)
		},
	}
}

func run(command *cobra.Command, d deps) error {
	options, err := cmd.OptionsFromCommand(command)
	if err != nil {
		return err
	}
	if !d.interactive() {
		return sharedcommand.NewOperationalError(fmt.Errorf(
			"interactive mode needs a terminal; run it in a shell, not a pipe, redirect, or CI. " +
				"For scripted use run the equivalent commands: raxuiscli audit web <url>, " +
				"raxuiscli demo web, or raxuiscli compare <before> <after>"))
	}
	return d.run(tui.Config{
		Color:    tui.ColorEnabled(options.NoColor, os.LookupEnv, true),
		Force:    options.Force,
		SavePath: options.OutputFile,
	})
}

func standardStreamsInteractive() bool {
	return isCharDevice(os.Stdin) && isCharDevice(os.Stdout)
}

func isCharDevice(f *os.File) bool {
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}
