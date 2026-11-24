package cmd

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/Raxuis/RaxuisCLI/internal/shared/catalog"
	"github.com/Raxuis/RaxuisCLI/internal/shared/constants"
	"github.com/Raxuis/RaxuisCLI/internal/shared/output"
	"github.com/Raxuis/RaxuisCLI/internal/shared/report"
	"github.com/charmbracelet/x/ansi/parser"
	"github.com/charmbracelet/x/term"
	"github.com/spf13/cobra"
)

func validateCapabilities(command *cobra.Command, options Options) error {
	caps := catalog.CapabilitiesFor(command.CommandPath())
	var unsupported string
	switch {
	case options.Output == outputJSON && !caps.JSON:
		unsupported = "--output=json"
	case options.Output == outputHTML && !caps.HTML:
		unsupported = "--output=html"
	case options.OutputFile != "" && !caps.OutputFile:
		unsupported = "--output-file"
	case options.FailOn != constants.SeverityNone && !caps.FailOn:
		unsupported = "--fail-on"
	case options.Verbose && !caps.Verbose:
		unsupported = "--verbose"
	case options.Quiet && options.Verbose:
		return fmt.Errorf("--quiet and --verbose cannot be combined")
	case options.Quiet && !caps.Quiet && options.Output != outputJSON:
		unsupported = "--quiet"
	}
	if unsupported != "" {
		return fmt.Errorf("%s does not support %s; see --help for its capabilities", command.CommandPath(), unsupported)
	}
	return nil
}

func wrapCommandOutput(command *cobra.Command, options Options) {
	runE, run := command.RunE, command.Run
	command.RunE = func(c *cobra.Command, args []string) error {
		c.RunE = runE
		if c.CommandPath() == "raxuiscli interactive" {
			return runE(c, args)
		}
		original := c.OutOrStdout()
		action := func(w io.Writer) error {
			writer := &commandWriter{target: w, strip: plainOutput(c, options)}
			c.SetOut(writer)
			output.Set(writer)
			output.SetFormat(options.Output)
			defer func() { c.SetOut(original); output.Set(original) }()
			var err error
			if runE != nil {
				err = runE(c, args)
			} else if run != nil {
				run(c, args)
			}
			if err != nil {
				return err
			}
			return writer.Error()
		}
		if options.OutputFile != "" && !catalog.CapabilitiesFor(c.CommandPath()).NativeOutput {
			return report.WriteFile(options.OutputFile, report.Report{}, commandRenderer{action}, options.Force)
		}
		return action(original)
	}
}

type commandRenderer struct{ render func(io.Writer) error }

func (r commandRenderer) Render(w io.Writer, _ report.Report) error { return r.render(w) }

type commandWriter struct {
	mu            sync.Mutex
	target        io.Writer
	strip         bool
	err           error
	ansiState     byte
	utf8Remaining int
}

func (w *commandWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.err != nil {
		return 0, w.err
	}
	data := p
	if w.strip {
		data = w.stripANSI(p)
	}
	n, err := w.target.Write(data)
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	if err != nil {
		w.err = err
		return 0, err
	}
	return len(p), nil
}
func (w *commandWriter) Error() error { w.mu.Lock(); defer w.mu.Unlock(); return w.err }

func plainOutput(command *cobra.Command, options Options) bool {
	if options.Output != outputText {
		return false
	}
	if options.NoColor || options.OutputFile != "" || os.Getenv("TERM") == "dumb" {
		return true
	}
	if _, ok := os.LookupEnv("NO_COLOR"); ok {
		return true
	}
	out, ok := command.OutOrStdout().(*os.File)
	return !ok || !term.IsTerminal(out.Fd())
}

func capabilityDescription(c catalog.Capabilities) string {
	formats := []string{"text"}
	if c.JSON {
		formats = append(formats, "json")
	}
	if c.HTML {
		formats = append(formats, "html")
	}
	return fmt.Sprintf("Output: %s | file: %t | quiet (text): %t | fail-on: %t | verbose: %t", strings.Join(formats, ", "), c.OutputFile, c.Quiet, c.FailOn, c.Verbose)
}

func (w *commandWriter) stripANSI(p []byte) []byte {
	data := make([]byte, 0, len(p))
	for _, b := range p {
		if w.utf8Remaining > 0 {
			data = append(data, b)
			w.utf8Remaining--
			continue
		}
		state, action := parser.Table.Transition(w.ansiState, b)
		if state == parser.Utf8State {
			data = append(data, b)
			switch {
			case b >= 0xf0:
				w.utf8Remaining = 3
			case b >= 0xe0:
				w.utf8Remaining = 2
			default:
				w.utf8Remaining = 1
			}
			w.ansiState = parser.GroundState
			continue
		}
		if action == parser.PrintAction || action == parser.ExecuteAction {
			data = append(data, b)
		}
		w.ansiState = state
	}
	return data
}
