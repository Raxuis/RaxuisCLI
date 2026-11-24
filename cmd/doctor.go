package cmd

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/Raxuis/RaxuisCLI/internal/shared/output"
	"github.com/charmbracelet/x/term"
	"github.com/spf13/cobra"
)

type doctorTool struct {
	Name      string `json:"name"`
	Installed bool   `json:"installed"`
	Purpose   string `json:"purpose"`
}

type doctorResult struct {
	OS        string `json:"os"`
	Arch      string `json:"arch"`
	GoVersion string `json:"go_version"`
	Terminal  struct {
		Stdin  bool `json:"stdin"`
		Stdout bool `json:"stdout"`
		Stderr bool `json:"stderr"`
	} `json:"terminal"`
	Tools        []doctorTool `json:"tools"`
	DockerDaemon string       `json:"docker_daemon"`
	Notes        []string     `json:"notes"`
}

func newDoctorCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Check local runtime and optional tools without changing the environment",
		Long:  "Report the local OS, architecture, Go runtime, process terminals and optional tools on PATH. No tools are executed, no services are contacted and no configuration is changed. Missing optional tools do not fail the check.",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			result := collectDoctorResult()
			var textError error
			err := output.Emit(result, func(w io.Writer) {
				// Render once so both output modes propagate their writer's error.
				var text strings.Builder
				fmt.Fprintf(&text, "Runtime: %s/%s, %s\n", result.OS, result.Arch, result.GoVersion)
				fmt.Fprintf(&text, "Terminal (process): stdin=%t stdout=%t stderr=%t\n", result.Terminal.Stdin, result.Terminal.Stdout, result.Terminal.Stderr)
				fmt.Fprintln(&text, "Optional tools:")
				for _, tool := range result.Tools {
					state := "missing"
					if tool.Installed {
						state = "installed"
					}
					fmt.Fprintf(&text, "  %-10s %-9s %s\n", tool.Name, state, tool.Purpose)
				}
				fmt.Fprintln(&text, "Docker daemon: not checked (executable availability does not establish service status)")
				for _, note := range result.Notes {
					fmt.Fprintln(&text, note)
				}
				_, textError = io.WriteString(w, text.String())
			})
			if err != nil {
				return err
			}
			return textError
		},
	}
}

func collectDoctorResult() doctorResult {
	result := doctorResult{
		OS: runtime.GOOS, Arch: runtime.GOARCH, GoVersion: runtime.Version(),
		DockerDaemon: "not_checked",
		Tools: []doctorTool{
			{Name: "tar", Purpose: "Optional external archive utility; built-in archive commands remain available"},
			{Name: "docker", Purpose: "Optional container labs; daemon status requires a separate check"},
			{Name: "kubectl", Purpose: "Optional Kubernetes administration; cluster access is not checked"},
			{Name: "openssl", Purpose: "Optional external TLS utility; built-in TLS commands remain available"},
		},
		Notes: []string{
			"Built-in commands and the local fixture lab do not require these optional tools.",
			"For a local verification path, run raxuiscli demo web or ./scripts/lab/run.sh from the source checkout.",
			"Clipboard availability is a PATH check; display/session access is not checked.",
		},
	}
	result.Terminal.Stdin = term.IsTerminal(os.Stdin.Fd())
	result.Terminal.Stdout = term.IsTerminal(os.Stdout.Fd())
	result.Terminal.Stderr = term.IsTerminal(os.Stderr.Fd())
	switch runtime.GOOS {
	case "darwin":
		result.Tools = append(result.Tools, doctorTool{Name: "pbcopy", Purpose: "Optional clipboard writes"}, doctorTool{Name: "pbpaste", Purpose: "Optional clipboard reads"})
	case "windows":
		result.Tools = append(result.Tools, doctorTool{Name: "clip", Purpose: "Optional clipboard writes"})
	default:
		result.Tools = append(result.Tools, doctorTool{Name: "xclip", Purpose: "Optional X11 clipboard"}, doctorTool{Name: "xsel", Purpose: "Optional X11 clipboard"}, doctorTool{Name: "wl-copy", Purpose: "Optional Wayland clipboard writes"}, doctorTool{Name: "wl-paste", Purpose: "Optional Wayland clipboard reads"})
	}
	for i := range result.Tools {
		_, err := exec.LookPath(result.Tools[i].Name)
		result.Tools[i].Installed = err == nil
	}
	return result
}

func init() { RootCmd.AddCommand(newDoctorCommand()) }
