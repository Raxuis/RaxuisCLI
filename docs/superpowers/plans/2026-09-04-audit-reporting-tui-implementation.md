# Audit, Reporting, and Guided Interface Implementation Plan

**Design:** `docs/superpowers/specs/2026-09-04-audit-reporting-tui-design.md`  
**Scope:** passive HTTP/TLS audit, stable reports and comparisons, guided TUI,
local demo, and visible maturity metadata  
**Method:** small test-first changes; complete each delivery before starting the
next

## Delivery 1 — Reliable CLI and report foundations

### Task 1: Define severity ordering and exit semantics

**Files**

- Modify `internal/shared/constants/severity.go`
- Create `internal/shared/constants/severity_test.go`
- Create `internal/shared/command/errors.go`
- Create `internal/shared/command/errors_test.go`

**Steps**

1. Add failing table tests for case-insensitive severity parsing, rank ordering,
   `none`, invalid values, and threshold matching.
2. Implement `ParseSeverity`, `Severity.Rank`, and `MeetsThreshold` without
   changing existing severity strings.
3. Add failing tests for operational errors mapping to exit `1` and policy
   threshold errors mapping to exit `2`, including `errors.Is`/`errors.As`.
4. Implement typed operational and policy errors plus `ExitCode(error) int`.
5. Run `go test ./internal/shared/constants ./internal/shared/command`.

### Task 2: Make root execution deterministic

**Files**

- Modify `cmd/root.go`
- Create `cmd/root_test.go`
- Modify `main.go`

**Steps**

1. Add tests using isolated output buffers for root flags, error output, silence
   of usage on runtime errors, author credit in help, and no credit in quiet or
   machine output.
2. Add persistent flags `--output`, `--output-file`, `--force`, `--no-color`,
   `--quiet`, and `--fail-on`; validate their values in one options function.
3. Configure Cobra with `SilenceErrors` and `SilenceUsage`; ensure errors are
   rendered once to stderr.
4. Replace `log.Fatal` with an executor that maps typed errors to the documented
   exit codes without timestamps.
5. Preserve the existing default welcome output and existing command names.
6. Run `go test ./cmd ./...` and manually verify `go run . --help`.

### Task 3: Harden HTTP execution without breaking callers

**Files**

- Modify `internal/web/http/http.go`
- Modify `internal/web/http/http_test.go`
- Modify `internal/shared/httpclient/client.go`
- Modify `internal/shared/httpclient/client_test.go`

**Steps**

1. Add failing `httptest` cases for context cancellation, a response larger than
   a configured cap, an interrupted response body, and an invalid proxy URL.
2. Add `DoRequestContext(context.Context, RequestOptions, maxBodyBytes)` to the
   web HTTP package. Keep `DoRequest` as a compatibility wrapper.
3. Build requests with `http.NewRequestWithContext`, reject malformed proxies,
   read through `io.LimitReader`, expose truncation on `Response`, and propagate
   body-read errors.
4. Add a context-aware, bounded equivalent to the shared HTTP client used by the
   vulnerability scanner. Preserve its current wrapper for existing callers.
5. Verify response bodies are closed on all success and failure paths.
6. Run `go test -race ./internal/web/http ./internal/shared/httpclient
   ./internal/web/vuln`.

### Task 4: Introduce the versioned report model and redaction

**Files**

- Modify `internal/shared/models/result.go`
- Create `internal/shared/report/model.go`
- Create `internal/shared/report/model_test.go`
- Create `internal/shared/report/redact.go`
- Create `internal/shared/report/redact_test.go`

**Steps**

1. Add failing tests for deterministic finding IDs, canonical targets, RFC 3339
   UTC timestamps, stable ordering, and schema version `1`.
2. Add the minimal stable fields required for finding identity and status while
   retaining compatibility with existing `VulnResult` literals.
3. Define `Report`, `ToolInfo`, `AuditInfo`, `Observation`, and `ReportError`.
4. Add redaction tests covering query values, cookies, authorization headers,
   embedded URL credentials, and error text containing secrets.
5. Implement centralized redaction and require report constructors to apply it.
6. Run `go test ./internal/shared/models ./internal/shared/report`.

### Task 5: Add JSON, text, HTML, and atomic file output

**Files**

- Create `internal/shared/render/render.go`
- Create `internal/shared/render/text.go`
- Create `internal/shared/render/json.go`
- Create `internal/shared/render/html.go`
- Create `internal/shared/render/templates/report.html`
- Create `internal/shared/render/templates/report.css`
- Create `internal/shared/render/testdata/`
- Create `internal/shared/render/render_test.go`
- Create `internal/shared/report/write.go`
- Create `internal/shared/report/write_test.go`

**Steps**

1. Add golden tests with fixed clock/tool metadata for all three formats.
2. Implement a renderer interface writing to `io.Writer`; JSON must contain only
   the report envelope and deterministic indentation/order.
3. Implement the approved dark HTML report as a self-contained document with no
   JavaScript or external resources and the clickable Raxuis credit.
4. Add failing tests for atomic writes, refusal to overwrite, `--force`, cleanup
   after renderer failure, and Windows-safe replacement behavior.
5. Implement file output via a sibling temporary file, sync/close, and rename.
6. Run `go test ./internal/shared/render ./internal/shared/report` and inspect the
   golden HTML in a browser.

**Delivery 1 gate**

Run:

```bash
golangci-lint run
go vet ./...
go test -race ./...
make build-all
```

Commit as one coherent foundation change after the gate is green.

## Delivery 2 — Passive web audit and reports

### Task 6: Convert HTTP/TLS analyses into typed findings

**Files**

- Create `internal/audit/web/findings.go`
- Create `internal/audit/web/findings_test.go`
- Modify `internal/crypto/certinfo/certinfo.go`
- Modify `internal/crypto/certinfo/certinfo_test.go`

**Steps**

1. Add tests mapping every insecure/missing header state to a stable rule ID,
   severity, evidence, and remediation.
2. Add tests mapping certificate expiry, not-yet-valid, self-signed, weak
   signature, and chain failures to stable findings.
3. Introduce `GetCertFromHostContext` using a context-aware dialer and TLS
   handshake; retain `GetCertFromHost` as a compatibility wrapper.
4. Implement pure conversion functions from existing analyses to report
   findings and observations.
5. Run `go test ./internal/audit/web ./internal/crypto/certinfo`.

### Task 7: Build the passive audit orchestrator

**Files**

- Create `internal/audit/web/audit.go`
- Create `internal/audit/web/audit_test.go`

**Steps**

1. Add integration tests using `httptest`/local TLS servers for HTTPS success,
   HTTP-with-TLS-skipped, invalid scheme, timeout, oversized body, and one
   collector failing while another returns useful data.
2. Define `Options`, injectable HTTP/TLS collector interfaces, and a clock so
   tests remain deterministic.
3. Implement one overall context deadline, HTTP header collection, TLS chain
   collection for HTTPS, partial status, redacted errors, and stable sorting.
4. Confirm collectors never contact a second target through redirects unless
   explicitly allowed by the audit options.
5. Run `go test -race ./internal/audit/web`.

### Task 8: Expose `audit web` through Cobra

**Files**

- Create `cmd/audit/audit.go`
- Create `cmd/audit/web.go`
- Create `cmd/audit/web_test.go`
- Modify `main.go`

**Steps**

1. Add command tests for exact arguments, URL validation, stdout JSON purity,
   HTML requiring `--output-file`, overwrite refusal, quiet behavior, partial
   failure exit `1`, and `--fail-on` exit `2`.
2. Register the new domain through the existing blank-import convention.
3. Wire flags into the audit service and renderer without printing from business
   packages.
4. Use build metadata from `cmd/version.go` in every report.
5. Run `go test ./cmd/audit ./cmd` and exercise the command only against a local
   `httptest` fixture.

### Task 9: Correct `certinfo` success-on-error behavior

**Files**

- Modify `cmd/crypto/certinfo.go`
- Create `cmd/crypto/certinfo_test.go`

**Steps**

1. Add regression tests proving missing arguments, missing files, malformed
   host/port pairs, connection failures, and empty chains return errors.
2. Extract shared target parsing using `net.SplitHostPort` with IPv6 support.
3. Convert the main command and its subcommands to `Args` validators and `RunE`.
4. Keep current successful text output byte-compatible where practical.
5. Run `go test ./cmd/crypto ./internal/crypto/certinfo`.

### Task 10: Document and demonstrate the web audit

**Files**

- Modify `README.md`
- Modify `ROADMAP.md`
- Modify `CLAUDE.md` only if its separately staged addition has been committed
  by its owner
- Create `docs/examples/audit-report.json`

**Steps**

1. Document text, JSON, HTML, `--fail-on`, exit codes, privacy behavior, and the
   passive-only scope.
2. Generate the example JSON from a deterministic local fixture, not by hand.
3. Add a screenshot only after the TUI delivery; do not promise an interface
   that is not yet shipped.
4. Run every documented command that does not require public network access.

**Delivery 2 gate**

Run the full Delivery 1 gate plus `govulncheck ./...`. Commit only when the new
audit works end to end with a local target.

## Delivery 3 — Snapshot comparison

### Task 11: Parse and validate stored reports

**Files**

- Create `internal/shared/report/read.go`
- Create `internal/shared/report/read_test.go`
- Create `internal/shared/report/testdata/`

**Steps**

1. Add fixtures/tests for schema v1, unsupported schemas, truncated JSON,
   unknown fields, target mismatch inputs, and deterministic normalization.
2. Implement strict required-field validation while permitting unknown additive
   fields for forward compatibility.
3. Run `go test ./internal/shared/report`.

### Task 12: Implement deterministic comparison

**Files**

- Create `internal/shared/report/compare.go`
- Create `internal/shared/report/compare_test.go`
- Extend `internal/shared/render/text.go`
- Extend `internal/shared/render/json.go`
- Extend `internal/shared/render/html.go`
- Extend renderer golden fixtures

**Steps**

1. Add table tests for added, resolved, severity-worsened, evidence-changed, and
   unchanged findings plus changed observations.
2. Match findings by stable ID and canonical resource, sort every category, and
   expose a versioned comparison envelope.
3. Render text and HTML with regressions first and resolutions clearly distinct.
4. Add `HasRegressionAt(threshold)` and cover `none` plus all severities.
5. Run `go test ./internal/shared/report ./internal/shared/render`.

### Task 13: Expose the `compare` command

**Files**

- Create `cmd/audit/compare.go`
- Create `cmd/audit/compare_test.go`
- Modify `README.md`

**Steps**

1. Add tests for two required files, schema errors, target mismatch rejection,
   `--allow-target-mismatch`, all output formats, and `--fail-on-new` exit `2`.
2. Register `compare` as a top-level command while keeping implementation in the
   audit command package.
3. Add local before/after examples and verify their deterministic diff.
4. Run `go test ./cmd/audit ./internal/shared/report ./internal/shared/render`.

**Delivery 3 gate**

Run the full quality gate and compare two generated local audit snapshots.

## Delivery 4 — Demo, maturity, and guided terminal UI

### Task 14: Create the safe local demo fixture

**Files**

- Create `internal/demo/web.go`
- Create `internal/demo/web_test.go`
- Create `cmd/audit/demo.go`
- Create `cmd/audit/demo_test.go`

**Steps**

1. Add an end-to-end test that fails if any connection leaves loopback.
2. Start an in-process HTTP/TLS server on loopback and an ephemeral port with a
   generated self-signed/expired certificate and a fixed weak-header profile.
3. Run the production audit service with certificate verification explicitly
   relaxed for this local fixture, record that choice as an observation,
   normalize nondeterministic certificate details, and assert the documented
   findings.
4. Guarantee shutdown on success, cancellation, renderer failure, and panic.
5. Expose `raxuiscli demo web` with text/JSON/HTML output.
6. Run `go test -race ./internal/demo ./cmd/audit`.

### Task 15: Add the command maturity catalog

**Files**

- Create `internal/shared/catalog/catalog.go`
- Create `internal/shared/catalog/catalog_test.go`
- Create `cmd/catalog_test.go`
- Create `internal/shared/catalog/gen/main.go`
- Modify marked status sections in `README.md` and `ROADMAP.md`

**Steps**

1. Define command path, summary, category, maturity (`stable`, `experimental`,
   `informational`), safety level, and whether the TUI may invoke it.
2. Initially classify placeholder/mock/guidance-only implementations as
   experimental or informational; do not change their behavior.
3. Add a test traversing Cobra's command tree and requiring one catalog entry per
   visible command plus no stale entries.
4. Add deterministic generation for delimited status sections in README and
   ROADMAP; add a CI check that regeneration produces no diff.
5. Run `go generate ./internal/shared/catalog/...` and `go test ./cmd
   ./internal/shared/catalog`.

### Task 16: Add Bubble Tea dependencies and a testable UI shell

**Files**

- Modify `go.mod` and `go.sum`
- Create `internal/tui/app.go`
- Create `internal/tui/model.go`
- Create `internal/tui/styles.go`
- Create `internal/tui/keys.go`
- Create `internal/tui/model_test.go`

**Steps**

1. Add Bubble Tea v2, Bubbles v2, and Lip Gloss v2 from their official module
   paths; pin resolved versions in `go.mod`/`go.sum`.
2. Add pure update-state tests for loading, home, search, form, review, running,
   results, error, and About states.
3. Implement the approved dark palette, muted mint accent, soft selected-row
   background with no side border, narrow-terminal fallback, and centralized
   English strings.
4. Respect `NO_COLOR`, `TERM=dumb`, redirected output, and `--no-color`.
5. Render `Created by Raxuis · github.com/raxuis` in the footer/About view.
6. Run `go test ./internal/tui` and `go mod tidy`.

### Task 17: Implement palette, guided audit, and results views

**Files**

- Create `internal/tui/palette.go`
- Create `internal/tui/audit_form.go`
- Create `internal/tui/review.go`
- Create `internal/tui/results.go`
- Create `internal/tui/views_test.go`

**Steps**

1. Add golden/state tests for fuzzy command filtering, maturity/safety badges,
   inline URL validation, masked command preview, cancellation, report saving,
   finding filters, keyboard-only operation, and narrow widths.
2. Drive entries from the catalog, with Passive Web Audit, Local Demo, Compare,
   Browse Commands, and Help/About as initial actions.
3. Call audit/report services directly; never execute a shell command or invoke
   the compiled CLI.
4. Ensure the review screen shows scope, duration, output path, safety level, and
   exact equivalent command with secrets masked.
5. Run `go test ./internal/tui`.

### Task 18: Expose `interactive` and finish product documentation

**Files**

- Create `cmd/interactive/interactive.go`
- Create `cmd/interactive/interactive_test.go`
- Modify `main.go`
- Modify `README.md`
- Modify `ROADMAP.md`
- Add a final screenshot under `docs/assets/`

**Steps**

1. Add command tests proving the TUI launches only when explicitly requested and
   refuses noninteractive terminals with an actionable message.
2. Register the command through a blank import and pass root configuration into
   the TUI.
3. Capture a screenshot from the deterministic demo, verify the visible Raxuis
   credit, and document keyboard controls plus CLI equivalents.
4. Regenerate maturity tables and verify the docs match the catalog.
5. Run all documented demo flows on Linux/macOS-compatible terminals; rely on
   state tests and cross-compilation for Windows behavior.

**Delivery 4 and final gate**

```bash
go mod tidy
git diff --check
golangci-lint run
go vet ./...
go test -race -covermode=atomic -coverprofile=coverage.txt ./...
go run golang.org/x/vuln/cmd/govulncheck@latest ./...
make build-all
```

Then verify manually:

```bash
go run . demo web --output json
go run . demo web --output html --output-file /tmp/raxuis-demo.html
go run . compare /tmp/raxuis-before.json /tmp/raxuis-after.json --fail-on-new medium
go run . interactive
```

The final handoff must list intentional compatibility changes, published schema
version, exit codes, demo behavior, and any commands still labeled experimental
or informational.
