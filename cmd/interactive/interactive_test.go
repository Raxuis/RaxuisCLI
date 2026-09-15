package interactive

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/Raxuis/RaxuisCLI/cmd"
	sharedcommand "github.com/Raxuis/RaxuisCLI/internal/shared/command"
	"github.com/Raxuis/RaxuisCLI/internal/tui"
)

func newTestRoot(t *testing.T, d deps) *cobra.Command {
	t.Helper()
	root := &cobra.Command{
		Use:           "raxuiscli",
		SilenceErrors: true,
		SilenceUsage:  true,
		PersistentPreRunE: func(command *cobra.Command, _ []string) error {
			_, err := cmd.OptionsFromCommand(command)
			return err
		},
	}
	root.PersistentFlags().String("output", "text", "")
	root.PersistentFlags().String("output-file", "", "")
	root.PersistentFlags().Bool("force", false, "")
	root.PersistentFlags().Bool("no-color", false, "")
	root.PersistentFlags().Bool("quiet", false, "")
	root.PersistentFlags().String("fail-on", "none", "")
	root.AddCommand(newInteractiveCommand(d))

	var out, errOut bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errOut)
	return root
}

func TestLaunchesWhenInteractive(t *testing.T) {
	called := 0
	root := newTestRoot(t, deps{
		interactive: func() bool { return true },
		run: func(tui.Config) error {
			called++
			return nil
		},
	})
	root.SetArgs([]string{"interactive"})
	if err := root.Execute(); err != nil {
		t.Fatalf("interactive: %v", err)
	}
	if called != 1 {
		t.Fatalf("run called %d times, want 1", called)
	}
}

func TestRefusesNoninteractiveTerminal(t *testing.T) {
	called := false
	root := newTestRoot(t, deps{
		interactive: func() bool { return false },
		run: func(tui.Config) error {
			called = true
			return nil
		},
	})
	root.SetArgs([]string{"interactive"})
	err := root.Execute()
	if err == nil || !errors.Is(err, sharedcommand.ErrOperational) || sharedcommand.ExitCode(err) != 1 {
		t.Fatalf("error = %T %v, want operational exit 1", err, err)
	}
	if called {
		t.Fatal("run was called despite a non-interactive terminal")
	}
	for _, want := range []string{"terminal", "audit web"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("message %q missing actionable hint %q", err.Error(), want)
		}
	}
}

func TestRejectsArguments(t *testing.T) {
	called := false
	root := newTestRoot(t, deps{
		interactive: func() bool { return true },
		run: func(tui.Config) error {
			called = true
			return nil
		},
	})
	root.SetArgs([]string{"interactive", "extra"})
	err := root.Execute()
	if err == nil || !errors.Is(err, sharedcommand.ErrOperational) {
		t.Fatalf("error = %v, want operational error", err)
	}
	if called {
		t.Fatal("run was called for invalid arguments")
	}
}

func TestPassesRootConfiguration(t *testing.T) {
	var got tui.Config
	root := newTestRoot(t, deps{
		interactive: func() bool { return true },
		run: func(cfg tui.Config) error {
			got = cfg
			return nil
		},
	})
	root.SetArgs([]string{"--no-color", "--force", "--output-file", "out.txt", "interactive"})
	if err := root.Execute(); err != nil {
		t.Fatalf("interactive: %v", err)
	}
	if got.Color {
		t.Error("Color should be false when --no-color is set")
	}
	if !got.Force {
		t.Error("Force should be true when --force is set")
	}
	if got.SavePath != "out.txt" {
		t.Errorf("SavePath = %q, want out.txt", got.SavePath)
	}
}
