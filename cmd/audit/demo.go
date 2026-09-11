package audit

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"raxuiscli/cmd"
	localdemo "raxuiscli/internal/demo"
	sharedcommand "raxuiscli/internal/shared/command"
	"raxuiscli/internal/shared/render"
	"raxuiscli/internal/shared/report"
)

type demoRunner func(context.Context) (report.Report, error)
type reportRendererFactory func(string) (render.Renderer, error)

var demoCmd = newDemoCommand(localdemo.Web)

func init() {
	cmd.RootCmd.AddCommand(demoCmd)
}

func newDemoCommand(runner demoRunner) *cobra.Command {
	return newDemoCommandWithRenderer(runner, render.RendererFor)
}

func newDemoCommandWithRenderer(runner demoRunner, rendererFor reportRendererFactory) *cobra.Command {
	command := &cobra.Command{
		Use:   "demo",
		Short: "Run safe local demonstrations without public network access",
		RunE: func(command *cobra.Command, _ []string) error {
			return command.Help()
		},
	}
	command.AddCommand(newDemoWebCommand(runner, rendererFor))
	return command
}

func newDemoWebCommand(runner demoRunner, rendererFor reportRendererFactory) *cobra.Command {
	return &cobra.Command{
		Use:   "web",
		Short: "Audit an intentionally weak local HTTPS fixture",
		Args: func(command *cobra.Command, args []string) error {
			if err := cobra.NoArgs(command, args); err != nil {
				return sharedcommand.NewOperationalError(err)
			}
			return nil
		},
		RunE: func(command *cobra.Command, _ []string) error {
			return runDemoWeb(command, runner, rendererFor)
		},
	}
}

func runDemoWeb(command *cobra.Command, runner demoRunner, rendererFor reportRendererFactory) error {
	options, err := cmd.OptionsFromCommand(command)
	if err != nil {
		return err
	}
	if runner == nil {
		return sharedcommand.NewOperationalError(fmt.Errorf("demo web runner is nil"))
	}
	if rendererFor == nil {
		return sharedcommand.NewOperationalError(fmt.Errorf("demo web renderer factory is nil"))
	}

	auditContext := command.Context()
	if auditContext == nil {
		auditContext = context.Background()
	}
	value, err := runner(auditContext)
	if err != nil {
		return sharedcommand.NewOperationalError(err)
	}
	value.Tool = buildToolInfo()

	renderer, err := rendererFor(options.Output)
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
		return sharedcommand.NewOperationalError(fmt.Errorf("web demo audit completed partially"))
	}
	if severity, matched := highestSeverityAt(options.FailOn, value); matched {
		return sharedcommand.NewPolicyError(severity, options.FailOn)
	}
	return nil
}
