# Task 8 — `audit web` Cobra integration

## Outcome

Implemented the passive `raxuiscli audit web <http-or-https-url>` command and
registered it through the application's blank-import convention. The command
uses the existing audit service and report renderers; the command layer alone
selects output, writes files, and maps returned conditions to typed CLI errors.

## RED

The initial command-test run was intentionally red because the command factory
did not yet exist:

```text
# raxuiscli/cmd/audit [raxuiscli/cmd/audit.test]
cmd/audit/web_test.go:197:18: undefined: newAuditCommand
FAIL    raxuiscli/cmd/audit [build failed]
```

The test suite added before implementation covers:

- `TestWebRequiresExactlyOneTarget`
- `TestWebRejectsInvalidURLAsOperationalError`
- `TestWebJSONOnStdoutIsOnlyTheReportEnvelope`
- `TestWebHTMLRequiresOutputFile`
- `TestWebRefusesToOverwriteOutputFileWithoutForce`
- `TestWebQuietDoesNotAddOutputAroundReport`
- `TestWebPartialAuditReturnsOperationalErrorAfterRendering`
- `TestWebFailOnReturnsPolicyError`
- `TestWebAttachesBuildMetadata`

All successful network-path coverage uses only a local `httptest.Server`.

## GREEN

```text
$ go test ./cmd/audit ./cmd
ok      raxuiscli/cmd/audit
ok      raxuiscli/cmd

$ go test -race ./cmd/audit ./cmd
ok      raxuiscli/cmd/audit
ok      raxuiscli/cmd

$ go vet ./...
(success)

$ go build .
(success)

$ go test ./...
(success)
```

`golangci-lint` was not installed or discoverable on this host, so no lint
binary was run. `gofmt` and `git diff --check` passed.

## Self-review

- The new `audit` command does not define a child-local `--output`; modern
  format and destination behavior continues to come from the root
  `--output` and `--output-file` flags. Existing child-local flags elsewhere
  were not changed.
- JSON is rendered directly to stdout with no command banners or progress
  output. Text remains the default renderer. HTML relies on the root's
  required-output-file validation.
- Output files use the existing atomic writer and refuse replacement without
  `--force`.
- A partial audit is rendered before returning `OperationalError` (exit 1).
  A completed audit meeting `--fail-on` returns `PolicyError` (exit 2).
  Partial failure intentionally takes precedence over policy failure.
- Report tool provenance is populated from the build banner assembled in
  `cmd/version.go`, with runtime fallbacks for version, platform, and Go
  version.

## Plan conflict

None found; no `NEEDS_CONTEXT` escalation is required.
