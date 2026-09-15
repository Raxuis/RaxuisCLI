package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	sharedcommand "raxuiscli/internal/shared/command"
	"raxuiscli/internal/shared/constants"
	"raxuiscli/internal/shared/output"
)

const (
	outputText = "text"
	outputJSON = "json"
	outputHTML = "html"
)

// Options contains the root execution options shared by commands.
type Options struct {
	Output     string
	OutputFile string
	Force      bool
	NoColor    bool
	Quiet      bool
	FailOn     constants.Severity
}

// RootCmd is exported so subpackages can add their commands.
var RootCmd = newRootCommand()

func newRootCommand() *cobra.Command {
	root := &cobra.Command{
		Use:           "raxuiscli",
		Short:         "A powerful CLI toolkit",
		Long:          "RaxuisCLI is a collection of the most used commands by @Raxuis.\n\nAuthor: Raxuis (github.com/raxuis)",
		SilenceErrors: true,
		SilenceUsage:  true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if _, err := OptionsFromCommand(cmd); err != nil {
				return err
			}
			// Route command text output through the command's writer so it is
			// redirectable and capturable instead of hard-wired to os.Stdout.
			output.Set(cmd.OutOrStdout())
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			options, err := OptionsFromCommand(cmd)
			if err != nil {
				return err
			}
			if !options.Quiet && options.Output == outputText {
				fmt.Fprintln(cmd.OutOrStdout(), "Welcome to RaxuisCLI! Use --help to see available commands.")
			}
			return nil
		},
	}

	root.SetHelpTemplate(helpTemplate)
	root.SetUsageTemplate(usageTemplate)

	root.PersistentFlags().BoolP("verbose", "v", false, "Verbose output")
	root.PersistentFlags().String("output", outputText, "Output format: text, json, or html")
	root.PersistentFlags().String("output-file", "", "Write output to file")
	root.PersistentFlags().Bool("force", false, "Allow replacing an existing output file")
	root.PersistentFlags().Bool("no-color", false, "Disable colorized output")
	root.PersistentFlags().Bool("quiet", false, "Suppress progress and informational messages")
	root.PersistentFlags().String("fail-on", "none", "Fail when findings meet severity: none, info, low, medium, high, or critical")

	return root
}

// OptionsFromCommand reads and validates the persistent root options available
// to cmd. It returns operational errors so the root executor can map them to a
// deterministic process exit code.
func OptionsFromCommand(cmd *cobra.Command) (Options, error) {
	rootFlags := cmd.Root().PersistentFlags()

	output, err := rootFlags.GetString("output")
	if err != nil {
		return Options{}, sharedcommand.NewOperationalError(err)
	}
	if output != outputText && output != outputJSON && output != outputHTML {
		return Options{}, sharedcommand.NewOperationalError(
			fmt.Errorf("invalid output %q: must be one of text, json, html", output),
		)
	}

	outputFile, err := rootFlags.GetString("output-file")
	if err != nil {
		return Options{}, sharedcommand.NewOperationalError(err)
	}
	if output == outputHTML && outputFile == "" {
		return Options{}, sharedcommand.NewOperationalError(
			fmt.Errorf("--output-file is required when --output=html"),
		)
	}

	failOn, err := rootFlags.GetString("fail-on")
	if err != nil {
		return Options{}, sharedcommand.NewOperationalError(err)
	}
	severity, err := constants.ParseSeverity(failOn)
	if err != nil {
		return Options{}, sharedcommand.NewOperationalError(err)
	}

	force, err := rootFlags.GetBool("force")
	if err != nil {
		return Options{}, sharedcommand.NewOperationalError(err)
	}
	noColor, err := rootFlags.GetBool("no-color")
	if err != nil {
		return Options{}, sharedcommand.NewOperationalError(err)
	}
	quiet, err := rootFlags.GetBool("quiet")
	if err != nil {
		return Options{}, sharedcommand.NewOperationalError(err)
	}

	return Options{
		Output:     output,
		OutputFile: outputFile,
		Force:      force,
		NoColor:    noColor,
		Quiet:      quiet,
		FailOn:     severity,
	}, nil
}

// Execute runs the root command and returns the process exit code. Cobra is
// silenced so this function is the sole renderer for command errors.
func Execute() int {
	return execute(RootCmd)
}

func execute(root *cobra.Command) int {
	if err := root.Execute(); err != nil {
		fmt.Fprintln(root.ErrOrStderr(), err)
		return sharedcommand.ExitCode(err)
	}
	return 0
}
