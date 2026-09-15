package audit

import (
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/Raxuis/RaxuisCLI/cmd"
	sharedcommand "github.com/Raxuis/RaxuisCLI/internal/shared/command"
	"github.com/Raxuis/RaxuisCLI/internal/shared/constants"
	"github.com/Raxuis/RaxuisCLI/internal/shared/render"
	"github.com/Raxuis/RaxuisCLI/internal/shared/report"
)

// reportReader makes persisted-report input replaceable in command tests.
type reportReader func(string) (report.Report, error)

// comparisonRendererFactory selects a renderer that knows how to render the
// comparison envelope, rather than a single audit report.
type comparisonRendererFactory func(string) (render.ComparisonRenderer, error)

var compareCmd = newCompareCommand(report.ReadFile)

// newCompareCommand constructs the top-level snapshot comparison command.
func newCompareCommand(reader reportReader) *cobra.Command {
	return newCompareCommandWithRenderer(reader, comparisonRendererFor)
}

func newCompareCommandWithRenderer(reader reportReader, rendererFor comparisonRendererFactory) *cobra.Command {
	command := &cobra.Command{
		Use:   "compare <before-report.json> <after-report.json>",
		Short: "Compare two versioned audit reports",
		Args:  compareArgs,
		RunE: func(command *cobra.Command, args []string) error {
			return runCompare(command, args, reader, rendererFor)
		},
	}
	command.Flags().Bool("allow-target-mismatch", false, "Allow comparison of reports for different targets")
	command.Flags().String("fail-on-new", "none", "Fail when added or worsened findings meet severity: none, info, low, medium, high, or critical")
	return command
}

// compareArgs validates every command-local input before either report reader
// runs. This keeps malformed invocations from touching the filesystem.
func compareArgs(command *cobra.Command, args []string) error {
	if err := cobra.ExactArgs(2)(command, args); err != nil {
		return sharedcommand.NewOperationalError(err)
	}
	if _, err := failOnNewFromCommand(command); err != nil {
		return sharedcommand.NewOperationalError(err)
	}
	return nil
}

func runCompare(command *cobra.Command, args []string, reader reportReader, rendererFor comparisonRendererFactory) error {
	options, err := cmd.OptionsFromCommand(command)
	if err != nil {
		return err
	}
	threshold, err := failOnNewFromCommand(command)
	if err != nil {
		return sharedcommand.NewOperationalError(err)
	}
	allowTargetMismatch, err := command.Flags().GetBool("allow-target-mismatch")
	if err != nil {
		return sharedcommand.NewOperationalError(err)
	}

	before, err := reader(args[0])
	if err != nil {
		return sharedcommand.NewOperationalError(err)
	}
	after, err := reader(args[1])
	if err != nil {
		return sharedcommand.NewOperationalError(err)
	}
	comparison, err := report.Compare(before, after, allowTargetMismatch)
	if err != nil {
		return sharedcommand.NewOperationalError(err)
	}

	renderer, err := rendererFor(options.Output)
	if err != nil {
		return sharedcommand.NewOperationalError(err)
	}
	if options.OutputFile != "" {
		if err := report.WriteFile(options.OutputFile, report.Report{}, comparisonFileRenderer{renderer: renderer, comparison: comparison}, options.Force); err != nil {
			return sharedcommand.NewOperationalError(err)
		}
	} else if err := renderer.RenderComparison(command.OutOrStdout(), comparison); err != nil {
		return sharedcommand.NewOperationalError(err)
	}

	if severity, matched := highestRegressionAt(comparison, threshold); matched {
		return sharedcommand.NewPolicyError(severity, threshold)
	}
	return nil
}

func failOnNewFromCommand(command *cobra.Command) (constants.Severity, error) {
	value, err := command.Flags().GetString("fail-on-new")
	if err != nil {
		return constants.SeverityNone, err
	}
	return constants.ParseSeverity(value)
}

func highestRegressionAt(comparison report.Comparison, threshold constants.Severity) (constants.Severity, bool) {
	highest := constants.SeverityNone
	for _, finding := range comparison.Findings.Added {
		if finding.Severity.MeetsThreshold(threshold) && finding.Severity.Rank() > highest.Rank() {
			highest = finding.Severity
		}
	}
	for _, change := range comparison.Findings.Changed {
		if change.SeverityWorsened && change.After.Severity.MeetsThreshold(threshold) && change.After.Severity.Rank() > highest.Rank() {
			highest = change.After.Severity
		}
	}
	return highest, highest != constants.SeverityNone
}

func comparisonRendererFor(format string) (render.ComparisonRenderer, error) {
	renderer, err := render.RendererFor(format)
	if err != nil {
		return nil, err
	}
	comparisonRenderer, ok := renderer.(render.ComparisonRenderer)
	if !ok {
		return nil, fmt.Errorf("report renderer for %q does not support comparisons", format)
	}
	return comparisonRenderer, nil
}

// comparisonFileRenderer adapts a comparison renderer to the atomic report
// file writer without changing that established report persistence contract.
type comparisonFileRenderer struct {
	renderer   render.ComparisonRenderer
	comparison report.Comparison
}

func (renderer comparisonFileRenderer) Render(writer io.Writer, _ report.Report) error {
	if renderer.renderer == nil {
		return fmt.Errorf("comparison renderer is nil")
	}
	return renderer.renderer.RenderComparison(writer, renderer.comparison)
}

func init() {
	cmd.RootCmd.AddCommand(compareCmd)
}
