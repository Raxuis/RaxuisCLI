# Contributing to RaxuisCLI

Thanks for your interest in improving RaxuisCLI. This guide covers the build,
the conventions, and the checklist for adding a command.

## Prerequisites

- Go **1.25+** (see `go.mod`).
- `make` (optional, but the targets below are the easiest path).

## Build, test, lint

```bash
make build        # build ./bin/raxuiscli
make build-all    # cross-compile linux/darwin/windows
make test         # go test ./...
make test-race    # go test -race ./...
make cover        # coverage profile
make lint         # golangci-lint (see note below)
make tidy         # go mod tidy
```

Before opening a pull request, make sure the following pass:

```bash
gofmt -l .        # must print nothing
go vet ./...
go test -race ./...
go build ./...
```

**Linters.** The project uses `golangci-lint` (config in `.golangci.yml`).
If your toolchain is newer than the pinned `golangci-lint` and it fails to load
packages, you can still run the core analyzer directly:

```bash
go run honnef.co/go/tools/cmd/staticcheck@latest ./...
```

## Code style

- **Comments are minimal.** Comment *why*, not *what*; do not add a doc comment
  to every exported symbol just because it is exported (`revive`'s `exported`
  rule is disabled on purpose). Prefer clear names and short functions.
- Match the style of the surrounding code (naming, error handling, structure).
- New audit/report/UI code writes to an `io.Writer` and keeps user-facing
  strings centralized (see `internal/tui/strings.go`); it does not print from
  business logic.

## Adding a command

The command tree, the docs, and a validation test must stay in sync. When you
add a visible command you **must**:

1. Create the Cobra command in `cmd/<domain>/<command>.go` and register it on
   `cmd.RootCmd` via `init()`.
2. Create the logic in `internal/<domain>/<command>/`.
3. If it is a new domain package, add a blank import in `main.go`
   (`_ "raxuiscli/cmd/<domain>"`).
4. Add a matching entry in `internal/shared/catalog/catalog.go` with a
   `Summary` equal to the command's Cobra `Short`, and classify its maturity and
   safety. `stable` is only for complete implementations; a placeholder, mock,
   or guidance-only command must be `experimental` or `informational`. A command
   at `active`/`dangerous` safety cannot be TUI-enabled.
5. Regenerate the docs tables and confirm no diff:
   ```bash
   go generate ./internal/shared/catalog/...
   ```
6. Document the command in `README.md` (and `ROADMAP.md` if relevant).

`go test ./cmd ./internal/shared/catalog` enforces that every visible command
has exactly one catalog entry with a matching summary, and that the generated
README/ROADMAP tables are current — so these steps are checked in CI, not just
by convention.

## Guided interface

Only safe, passive, report-producing flows are exposed in the terminal UI
(`raxuiscli interactive`). If you want a command reachable there, it must be a
`safe`/`passive` command marked `TUIAllowed` in the catalog, and wired through
`internal/tui` calling the service directly — never by shelling out to the CLI.

## Pull requests

- Keep PRs focused; describe the change and how you tested it.
- Include tests for new behavior. Business logic lives under `internal/`, which
  is where most tests belong.
- Do not commit built binaries (`bin/`) or generated artifacts by hand; let the
  generator produce the doc tables.
