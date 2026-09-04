# Audit, Reporting, and Guided Interface Design

**Date:** 2026-09-04  
**Status:** Approved direction; implementation pending specification review

## Objective

Make RaxuisCLI useful to newcomers and experienced operators through one shared
execution model. Newcomers receive a guided terminal interface and readable HTML
reports. Experienced users receive deterministic exit codes, stable JSON, and
commands suitable for scripts and CI.

The first supported vertical slice is passive HTTP and TLS inspection. Existing
offensive commands remain available, but are outside this feature's orchestration
scope.

## Delivery Sequence

1. Establish reliable command, error, and rendering contracts.
2. Add a passive `audit web` command and JSON/HTML reports.
3. Add snapshots and comparisons.
4. Add a guided terminal interface and local demonstration mode.

Each delivery must pass lint, vet, race-enabled tests, and cross-platform builds
before the next begins.

## Shared Execution Model

Business packages return typed data and errors. They do not print directly.
Cobra commands translate flags into request types, call business services, and
pass results to a renderer. This project migrates the root executor, `certinfo`,
and the HTTP header analysis used by `audit web`. Other existing commands retain
their current output and are migrated in separate projects.

The new packages are:

- `internal/shared/command`: operational error categories and exit-code mapping.
- `internal/shared/report`: versioned report models, redaction, JSON persistence,
  and comparison.
- `internal/shared/render`: text, JSON, and HTML renderers that accept report
  models rather than command-specific values.
- `internal/audit/web`: orchestration of existing HTTP-header and TLS-certificate
  analysis.
- `internal/tui`: terminal states and views. It calls the same audit service as
  Cobra and never shells out to the `raxuiscli` binary.

The existing `internal/shared/models.VulnResult` is adapted into the common
finding type rather than duplicated.

## CLI Contract

The root command gains these persistent flags:

- `--output text|json|html`, defaulting to `text`.
- `--output-file <path>`, required for HTML and optional for JSON.
- `--no-color`, disabling ANSI styling.
- `--quiet`, suppressing progress and informational messages, never errors.

`--output-file` is written atomically by creating a sibling temporary file and
renaming it after successful rendering. Existing files are not replaced unless
`--force` is supplied. JSON written to stdout contains no progress text.

Commands use `RunE`; errors are returned to the root executor and written once to
stderr. The process exit codes are:

- `0`: operation completed and no configured policy threshold was reached.
- `1`: invalid input or operational failure such as DNS, TLS, HTTP, parsing, or
  filesystem failure.
- `2`: operation completed but a finding met `--fail-on`.

`--fail-on none|info|low|medium|high|critical` defaults to `none`, so finding a
security issue does not unexpectedly break an interactive invocation.

## Report Model

Every persisted report uses this envelope:

```text
schema_version  fixed integer, initially 1
tool            name, semantic version, commit, Go version, and platform
audit           stable audit ID, kind, target, start time, duration, and status
findings        stable rule ID, title, severity, status, evidence, remediation
observations    non-finding facts such as TLS protocol and HTTP status
errors          redacted partial-failure messages
```

Finding identity is based on the stable rule ID plus a canonicalized resource,
not display text. This allows descriptions to improve without turning unchanged
findings into false additions.

The JSON schema is treated as a public API: additions are backward-compatible,
field removal or semantic changes require a new `schema_version`. Timestamps use
RFC 3339 UTC. Unordered maps are normalized before serialization and tests use
golden fixtures.

The HTML renderer produces one self-contained file with embedded CSS, a summary,
severity counts, observations, findings, remediation, execution metadata, and a
clear disclaimer. It contains no JavaScript or remote resources.

## Passive Web Audit

The command is:

```text
raxuiscli audit web <https-url>
```

Version one accepts exactly one HTTP or HTTPS URL. For HTTPS it collects the
certificate chain and existing validation results, performs one HTTP request,
and applies the existing security-header analysis. HTTP targets skip TLS and add
an observation explaining why.

The audit has a single overall timeout propagated with `context.Context`.
Individual collectors return partial results. If HTTP succeeds but TLS analysis
fails, the report is still rendered with status `partial`, the error is included,
and the command exits `1`. Response bodies are capped; this audit needs headers,
not an unbounded payload.

Sensitive request headers, cookies, authorization values, query values, and
certificate private material are never persisted. Targets retain scheme, host,
port, and path; query values are replaced with `<redacted>`.

## Snapshots and Comparison

Any JSON audit report is a snapshot. Comparison uses:

```text
raxuiscli compare <before.json> <after.json>
```

Both inputs must use supported schemas and the same audit kind. Target mismatch
is rejected unless `--allow-target-mismatch` is set. Findings are classified as
`added`, `resolved`, `changed`, or `unchanged`; severity and evidence changes are
shown explicitly. Observations with stable keys are also compared.

Text and HTML emphasize regressions and resolutions. JSON exposes the complete
diff. `--fail-on-new <severity>` returns exit code `2` only when an added or
worsened finding reaches the threshold.

## Guided Terminal Interface

`raxuiscli interactive` launches a Bubble Tea terminal application. Bubble Tea
is isolated in `internal/tui`; audit and report packages have no dependency on
terminal UI libraries.

The first release contains four screens:

1. Home: choose Passive Web Audit, Compare Reports, Demo, or Help.
2. Form: enter the target or files, choose output and threshold, and validate
   fields inline.
3. Review: show the exact equivalent CLI command with secret values masked.
4. Results: show summary cards, filterable findings, remediation, and the saved
   report path.

Keyboard navigation works without a mouse. Narrow terminals fall back to a
single-column layout. `NO_COLOR`, `TERM=dumb`, redirected output, and
`--no-color` are respected. The interface never starts implicitly; normal CLI
behavior remains stable for scripts.

## Demonstration Mode

`raxuiscli demo web` runs the audit against an in-process local HTTP/TLS fixture.
The fixture intentionally exposes a documented set of weak headers and an
expired or self-signed test certificate. It binds only to loopback on an
ephemeral port, performs no external request, and shuts down automatically.

The demo uses the production audit path and deterministic fixture data. Its
expected report is asserted in tests, making it both an onboarding experience
and an end-to-end regression test.

## Maturity Labels

Command metadata defines one of `stable`, `experimental`, or `informational`.
Labels appear in help and the interactive interface. Commands with placeholder,
mock, or guidance-only behavior cannot be marked stable. The roadmap and README
derive their status tables from a validation test over this metadata so that a
command cannot silently be documented as complete while remaining a stub.

## Testing and Quality Gates

- Unit tests cover exit mapping, redaction, canonical finding IDs, JSON schema,
  atomic output, and every comparison state.
- Golden tests cover text, JSON, and HTML rendering with deterministic time and
  tool metadata.
- `httptest` integration tests cover HTTP, HTTPS, timeouts, partial failures,
  oversized bodies, and cancellation.
- TUI update functions are tested as state transitions without a real terminal.
- The demo is an end-to-end test and must not access the public network.
- CI runs lint, vet, race-enabled tests, `govulncheck`, and cross-platform builds.

## Compatibility and Non-Goals

Existing command names and default human-readable output remain unchanged during
the first delivery. The JSON contract applies only to new audit and compare
commands. Adding structured output to each older command is a separate project.

This design does not add active exploitation, scanning of multiple targets,
remote report hosting, a browser dashboard, plugins, accounts, or a database. It
does not claim that simplified protocol implementations are complete; maturity
labels make those limitations visible.

## Implementation Completion Criteria

- A beginner can run the demo from the interactive interface and save an HTML
  report without knowing flags.
- An expert can run a passive web audit in CI, parse stable JSON, and configure a
  severity threshold.
- Two reports produce a deterministic, machine-readable comparison.
- Failures never return success, secrets do not appear in persisted artifacts,
  and partial audits are clearly identified.
- The root executor, `certinfo`, `audit web`, and `compare` return nonzero status
  for operational failures; unrelated legacy commands are unchanged.

## Design References

- Bubble Tea architecture and terminal application framework:
  <https://github.com/charmbracelet/bubbletea>
- Bubbles terminal components: <https://github.com/charmbracelet/bubbles>
- Go request contexts: <https://pkg.go.dev/net/http#NewRequestWithContext>
