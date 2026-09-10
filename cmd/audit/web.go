package audit

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"raxuiscli/cmd"
	webaudit "raxuiscli/internal/audit/web"
	sharedcommand "raxuiscli/internal/shared/command"
	"raxuiscli/internal/shared/constants"
	"raxuiscli/internal/shared/render"
	"raxuiscli/internal/shared/report"
)

func newWebCommand(runner auditRunner) *cobra.Command {
	command := &cobra.Command{
		Use:   "web <http-or-https-url>",
		Short: "Passively inspect HTTP security headers and TLS certificates",
		Args:  exactlyOneAuditTarget,
		RunE: func(command *cobra.Command, args []string) error {
			return runWebAudit(command, args[0], runner)
		},
	}

	command.Flags().Duration("timeout", 10*time.Second, "Overall audit timeout")
	command.Flags().Int64("max-body-bytes", 1<<20, "Maximum response body bytes to read")
	command.Flags().Bool("insecure", false, "Skip TLS verification for the HTTP request")
	command.Flags().Bool("follow-redirects", false, "Allow redirects to another target")
	command.Flags().StringArray("header", nil, "Request header in Name: Value form (repeatable)")
	command.Flags().String("cookie", "", "Cookie header to include with the request")
	command.Flags().String("user-agent", "", "User-Agent header to include with the request")
	return command
}

// exactlyOneAuditTarget preserves Cobra's familiar arity message while making
// malformed command input an OperationalError for deterministic exit handling.
func exactlyOneAuditTarget(command *cobra.Command, args []string) error {
	if err := cobra.ExactArgs(1)(command, args); err != nil {
		return sharedcommand.NewOperationalError(err)
	}
	return nil
}

func runWebAudit(command *cobra.Command, target string, runner auditRunner) error {
	options, err := cmd.OptionsFromCommand(command)
	if err != nil {
		return err
	}
	auditOptions, err := auditOptionsFromCommand(command)
	if err != nil {
		return sharedcommand.NewOperationalError(err)
	}

	auditContext := command.Context()
	if auditContext == nil {
		auditContext = context.Background()
	}
	value, err := runner(auditContext, target, auditOptions)
	if err != nil {
		return sharedcommand.NewOperationalError(err)
	}
	value.Tool = buildToolInfo()

	renderer, err := render.RendererFor(options.Output)
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

	// A rendered partial report still denotes an operational failure. It takes
	// precedence over policy because the audit did not complete successfully.
	if value.Audit.Status == "partial" {
		return sharedcommand.NewOperationalError(fmt.Errorf("web audit completed partially"))
	}
	if severity, matched := highestSeverityAt(options.FailOn, value); matched {
		return sharedcommand.NewPolicyError(severity, options.FailOn)
	}
	return nil
}

func auditOptionsFromCommand(command *cobra.Command) (webaudit.Options, error) {
	timeout, err := command.Flags().GetDuration("timeout")
	if err != nil {
		return webaudit.Options{}, err
	}
	maxBodyBytes, err := command.Flags().GetInt64("max-body-bytes")
	if err != nil {
		return webaudit.Options{}, err
	}
	insecureTLS, err := command.Flags().GetBool("insecure")
	if err != nil {
		return webaudit.Options{}, err
	}
	allowRedirects, err := command.Flags().GetBool("follow-redirects")
	if err != nil {
		return webaudit.Options{}, err
	}
	rawHeaders, err := command.Flags().GetStringArray("header")
	if err != nil {
		return webaudit.Options{}, err
	}
	headers, err := parseHeaders(rawHeaders)
	if err != nil {
		return webaudit.Options{}, err
	}
	cookie, err := command.Flags().GetString("cookie")
	if err != nil {
		return webaudit.Options{}, err
	}
	userAgent, err := command.Flags().GetString("user-agent")
	if err != nil {
		return webaudit.Options{}, err
	}
	return webaudit.Options{
		Timeout:        timeout,
		MaxBodyBytes:   maxBodyBytes,
		AllowRedirects: allowRedirects,
		InsecureTLS:    insecureTLS,
		Headers:        headers,
		Cookie:         cookie,
		UserAgent:      userAgent,
	}, nil
}

func parseHeaders(values []string) (map[string]string, error) {
	if len(values) == 0 {
		return nil, nil
	}
	headers := make(map[string]string, len(values))
	for _, value := range values {
		name, headerValue, found := strings.Cut(value, ":")
		name = strings.TrimSpace(name)
		if !found || name == "" {
			return nil, fmt.Errorf("invalid header %q: use Name: Value", value)
		}
		headers[name] = strings.TrimSpace(headerValue)
	}
	return headers, nil
}

func highestSeverityAt(threshold constants.Severity, value report.Report) (constants.Severity, bool) {
	highest := constants.SeverityNone
	for _, finding := range value.Findings {
		if finding.Severity.Rank() > highest.Rank() {
			highest = finding.Severity
		}
	}
	return highest, constants.MeetsThreshold(highest, threshold)
}

// buildToolInfo adapts cmd/version.go's user-facing build banner to the report
// envelope. The banner is produced from ldflags and Go's embedded build info,
// so reports retain the same provenance shown by `raxuiscli version`.
func buildToolInfo() report.ToolInfo {
	tool := report.ToolInfo{
		Name:      "raxuiscli",
		Version:   "dev",
		GoVersion: runtime.Version(),
		Platform:  runtime.GOOS + "/" + runtime.GOARCH,
	}
	lines := strings.Split(cmd.RootCmd.Version, "\n")
	if len(lines) == 0 {
		return tool
	}
	first := strings.TrimSpace(lines[0])
	fields := strings.Fields(first)
	if len(fields) >= 2 && fields[0] == tool.Name {
		tool.Version = fields[1]
	}
	if start := strings.Index(first, "("); start >= 0 {
		if end := strings.Index(first[start:], ")"); end > 1 {
			tool.Commit = first[start+1 : start+end]
		}
	}
	if len(lines) >= 2 {
		parts := strings.Split(strings.TrimSpace(lines[1]), ",")
		if len(parts) >= 1 && strings.TrimSpace(parts[0]) != "" {
			tool.Platform = strings.TrimSpace(parts[0])
		}
		if len(parts) >= 2 && strings.TrimSpace(parts[1]) != "" {
			tool.GoVersion = strings.TrimSpace(parts[1])
		}
	}
	return tool
}
