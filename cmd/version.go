package cmd

import (
	"fmt"
	"io"
	"runtime"
	"runtime/debug"

	"github.com/Raxuis/RaxuisCLI/internal/shared/output"
	"github.com/spf13/cobra"
)

// Build information. Populated at build time via -ldflags:
//
//	-X github.com/Raxuis/RaxuisCLI/cmd.version=... -X github.com/Raxuis/RaxuisCLI/cmd.commit=... -X github.com/Raxuis/RaxuisCLI/cmd.date=...
//
// When built with `go install` (no ldflags) the values are recovered from the
// embedded build info instead.
var (
	version = "dev"
	commit  = ""
	date    = ""
)

func buildVersionInfo() map[string]string {
	v, c, d := version, commit, date

	if info, ok := debug.ReadBuildInfo(); ok {
		if v == "dev" && info.Main.Version != "" && info.Main.Version != "(devel)" {
			v = info.Main.Version
		}
		for _, s := range info.Settings {
			switch s.Key {
			case "vcs.revision":
				if c == "" {
					c = s.Value
				}
			case "vcs.time":
				if d == "" {
					d = s.Value
				}
			}
		}
	}

	if len(c) > 12 {
		c = c[:12]
	}

	return map[string]string{"version": v, "commit": c, "built_at": d, "os": runtime.GOOS, "arch": runtime.GOARCH, "go_version": runtime.Version()}
}

func versionString() string {
	info := buildVersionInfo()
	v, c, d := info["version"], info["commit"], info["built_at"]
	out := fmt.Sprintf("raxuiscli %s", v)
	if c != "" {
		out += fmt.Sprintf(" (%s)", c)
	}
	if d != "" {
		out += fmt.Sprintf(" built %s", d)
	}
	out += fmt.Sprintf("\n%s/%s, %s", runtime.GOOS, runtime.GOARCH, runtime.Version())
	return out
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version, commit and build information",
	Args:  cobra.NoArgs,
	RunE: func(c *cobra.Command, args []string) error {
		return output.Emit(buildVersionInfo(), func(w io.Writer) { fmt.Fprintln(w, versionString()) })
	},
}

func init() {
	RootCmd.AddCommand(versionCmd)
	RootCmd.Version = versionString()
	RootCmd.SetVersionTemplate("{{.Version}}\n")
}
