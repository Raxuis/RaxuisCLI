package cmd

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	sharedcommand "raxuiscli/internal/shared/command"
	"raxuiscli/internal/shared/constants"
)

func TestRootOptionsAcceptPersistentFlags(t *testing.T) {
	root := newRootCommand()
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.SetArgs([]string{
		"--output", "json",
		"--output-file", "report.json",
		"--force",
		"--no-color",
		"--quiet",
		"--fail-on", "high",
	})

	if code := execute(root); code != 0 {
		t.Fatalf("execute() = %d, want 0; stderr: %s", code, stderr.String())
	}

	options, err := OptionsFromCommand(root)
	if err != nil {
		t.Fatalf("OptionsFromCommand() returned error: %v", err)
	}
	if options.Output != "json" || options.OutputFile != "report.json" || !options.Force || !options.NoColor || !options.Quiet {
		t.Errorf("OptionsFromCommand() = %+v, want supplied persistent flags", options)
	}
	if options.FailOn != constants.SeverityHigh {
		t.Errorf("OptionsFromCommand().FailOn = %q, want %q", options.FailOn, constants.SeverityHigh)
	}
}

func TestRootOptionsRejectInvalidValues(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"output", []string{"--output", "yaml"}, "invalid output \"yaml\""},
		{"fail-on", []string{"--fail-on", "urgent"}, "invalid severity: \"urgent\""},
		{"html needs output file", []string{"--output", "html"}, "--output-file is required when --output=html"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := newRootCommand()
			stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
			root.SetOut(stdout)
			root.SetErr(stderr)
			root.SetArgs(tt.args)

			if code := execute(root); code != 1 {
				t.Fatalf("execute() = %d, want 1; stderr: %s", code, stderr.String())
			}
			if !strings.Contains(stderr.String(), tt.want) {
				t.Errorf("stderr = %q, want %q", stderr.String(), tt.want)
			}
		})
	}
}

func TestRootRendersRuntimeErrorOnceWithoutUsage(t *testing.T) {
	root := newRootCommand()
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.SetArgs([]string{"--output", "yaml"})

	if code := execute(root); code != 1 {
		t.Fatalf("execute() = %d, want 1", code)
	}
	if got := stderr.String(); strings.Count(got, "invalid output") != 1 {
		t.Errorf("stderr rendered error %d times, want once: %q", strings.Count(got, "invalid output"), got)
	}
	if strings.Contains(stderr.String(), "Usage:") {
		t.Errorf("stderr included usage for runtime error: %q", stderr.String())
	}
}

func TestRootMapsPolicyErrorToExitCode(t *testing.T) {
	root := newRootCommand()
	root.RunE = func(*cobra.Command, []string) error {
		return sharedcommand.NewPolicyError(constants.SeverityHigh, constants.SeverityMedium)
	}
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	root.SetOut(stdout)
	root.SetErr(stderr)

	if code := execute(root); code != 2 {
		t.Fatalf("execute() = %d, want 2; stderr: %s", code, stderr.String())
	}
	if strings.Contains(stderr.String(), "Usage:") {
		t.Errorf("stderr included usage for runtime error: %q", stderr.String())
	}
}

func TestRootHelpIncludesAuthorCredit(t *testing.T) {
	root := newRootCommand()
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.SetArgs([]string{"--help"})

	if err := root.Execute(); err != nil {
		t.Fatalf("root.Execute() returned error: %v", err)
	}
	if !strings.Contains(stdout.String(), "Author: Raxuis (github.com/raxuis)") {
		t.Errorf("help omitted author credit: %q", stdout.String())
	}
}

func TestRootQuietAndMachineOutputOmitDecorativeCredit(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"quiet", []string{"--quiet"}},
		{"machine", []string{"--output", "json"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := newRootCommand()
			stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
			root.SetOut(stdout)
			root.SetErr(stderr)
			root.SetArgs(tt.args)

			if code := execute(root); code != 0 {
				t.Fatalf("execute() = %d, want 0; stderr: %s", code, stderr.String())
			}
			if strings.Contains(stdout.String(), "Raxuis") || strings.Contains(stderr.String(), "Raxuis") {
				t.Errorf("output included decorative credit: stdout=%q stderr=%q", stdout.String(), stderr.String())
			}
		})
	}
}

func TestRootDefaultWelcomeOutput(t *testing.T) {
	root := newRootCommand()
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	root.SetOut(stdout)
	root.SetErr(stderr)

	if code := execute(root); code != 0 {
		t.Fatalf("execute() = %d, want 0; stderr: %s", code, stderr.String())
	}
	if got, want := stdout.String(), "Welcome to RaxuisCLI! Use --help to see available commands.\n"; got != want {
		t.Errorf("welcome output = %q, want %q", got, want)
	}
}

func TestRootOptionsErrorsAreOperational(t *testing.T) {
	root := newRootCommand()
	if err := root.PersistentFlags().Set("output", "yaml"); err != nil {
		t.Fatalf("set output flag: %v", err)
	}

	_, err := OptionsFromCommand(root)
	if err == nil {
		t.Fatal("OptionsFromCommand() returned nil error")
	}
	if !errors.Is(err, sharedcommand.ErrOperational) {
		t.Errorf("OptionsFromCommand() error = %v, want operational error", err)
	}
}

func TestHelpShowsCatalogMaturityAndSafety(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"root list", []string{"--help"}, "audit       Passive security audits with versioned reports [stable]"},
		{"audit web detail", []string{"audit", "web", "--help"}, "Maturity: stable   Safety: passive"},
		{"compare detail", []string{"compare", "--help"}, "Maturity: stable   Safety: safe"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := newRootCommand()
			auditCmd := &cobra.Command{Use: "audit", Short: "Passive security audits with versioned reports"}
			auditCmd.AddCommand(&cobra.Command{Use: "web", Short: "Passively inspect HTTP security headers and TLS certificates", Run: func(*cobra.Command, []string) {}})
			root.AddCommand(auditCmd)
			root.AddCommand(&cobra.Command{Use: "compare", Short: "Compare two versioned audit reports", Run: func(*cobra.Command, []string) {}})

			stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
			root.SetOut(stdout)
			root.SetErr(stderr)
			root.SetArgs(tt.args)

			if err := root.Execute(); err != nil {
				t.Fatalf("root.Execute() returned error: %v", err)
			}
			if !strings.Contains(stdout.String(), tt.want) {
				t.Errorf("help output missing %q; got:\n%s", tt.want, stdout.String())
			}
		})
	}
}

func TestRootOptionsIgnoreChildOutputFlag(t *testing.T) {
	root := newRootCommand()
	child := &cobra.Command{
		Use: "child",
		RunE: func(cmd *cobra.Command, args []string) error {
			options, err := OptionsFromCommand(cmd)
			if err != nil {
				return err
			}
			if options.Output != outputText {
				t.Errorf("OptionsFromCommand().Output = %q, want %q", options.Output, outputText)
			}
			return nil
		},
	}
	child.Flags().String("output", "", "existing child output file")
	root.AddCommand(child)
	root.SetArgs([]string{"child", "--output", "report.txt"})

	if code := execute(root); code != 0 {
		t.Fatalf("execute() = %d, want 0", code)
	}
}
