# RaxuisCLI — continuation handoff

Last updated: 2026-09-14  
Branch: `develop`  
Current implementation commit: `e55747e feat(catalog): track command maturity`

This file is the durable handoff for a new session. It complements the detailed
SDD ledger at
`.superpowers/sdd/2026-09-04-audit-reporting-tui-implementation/progress.md`.

## Non-negotiable workspace rules

- `CLAUDE.md` is user-owned work and is deliberately staged (`A  CLAUDE.md`).
  Never edit, unstage, reset, or commit it. Use path-scoped commits such as
  `git commit --only -- <task paths>`.
- Preserve unrelated work in a dirty worktree. Never use destructive Git reset
  or checkout commands to make the tree appear clean.
- Use `apply_patch` for source and documentation edits.
- Keep SDD reports under
  `.superpowers/sdd/2026-09-04-audit-reporting-tui-implementation/`; that
  directory is local/ignored and is not committed.
- Run the independent review loop for every task: implementation, focused
  verification, review package, independent review, fix Important/Critical
  findings, then re-review.

## Plan and source of truth

- Implementation plan:
  `docs/superpowers/plans/2026-09-04-audit-reporting-tui-implementation.md`
- Product/design contract:
  `docs/superpowers/specs/2026-09-04-audit-reporting-tui-design.md`
- Detailed task ledger:
  `.superpowers/sdd/2026-09-04-audit-reporting-tui-implementation/progress.md`

Use the plan task brief helper before each task:

```bash
bash /Users/raphael/.codex/skills/subagent-driven-development/scripts/task-brief \
  docs/superpowers/plans/2026-09-04-audit-reporting-tui-implementation.md <task-number>
```

Generate a reviewer bundle with:

```bash
bash /Users/raphael/.codex/skills/subagent-driven-development/scripts/review-package \
  docs/superpowers/plans/2026-09-04-audit-reporting-tui-implementation.md <base> <head>
```

## Completed work

Tasks 1–14 are implemented, independently reviewed, and recorded in the SDD
ledger.

| Delivery | Result | Key commits |
|---|---|---|
| 1 — command/report foundations | Passed full gate | `a087f11..df01385` |
| 2 — passive web audit | Passed full gate and `govulncheck` | `04a99a2`, `19d7f3b` |
| 3 — stored reports and comparison | Passed full gate; real loopback snapshots compare successfully | `c574330..b2fe662` |
| 4 — safe demo (Task 14 portion) | Approved after socket-level loopback enforcement | `afd285d`, `3f26464` |

Delivered highlights:

- Deterministic severity/exit contracts, report v1, redaction, text/JSON/HTML
  renderers, atomic output files, and safe cross-platform replacement.
- Passive `audit web`, certificate/header findings, strict stored-report reader,
  and top-level `compare` with regression exit status `2`.
- Local `demo web`: an in-process expired self-signed HTTPS fixture on
  `127.0.0.1:0`; the real HTTP and TLS collectors use a guard that rejects every
  non-loopback socket destination before dialing.
- Reports produced by `go run` are self-readable (`tool.commit` falls back to
  `unknown` only when build provenance is unavailable).

## Current task: Task 15 — command maturity catalog

Implementation commit: `e55747e feat(catalog): track command maturity`.

It added a 200-command catalog, metadata validation, generated README/ROADMAP
blocks, and a CI stale-documentation check. The initial review is **not
approved**. Address these Important findings before marking Task 15 complete:

1. **Expose maturity labels in Cobra help.** The design requires labels in both
   help and the future interactive interface. Help for `audit web` and `compare`
   currently has no catalog-derived maturity/safety badge.
2. **Cover every command visible in Cobra help.** The parity test currently
   excludes Cobra-generated `help` and `completion` commands. Either catalog
   those visible framework commands (including shell completion children) with
   honest informational/safe metadata, or make them not visible by an explicit,
   product-approved Cobra configuration. Do not silently exclude them.
3. **Classify safety per invocation, not by family.** Examples currently
   over-classified: `http curl` only formats text; `vuln payloads` only lists
   payloads; `poison protocols` only lists information. Their metadata should
   reflect their actual behavior, and tests should lock the distinctions down.

Reviewer minor, worthwhile while touching the generator:

- Make README/ROADMAP generation recoverable (temporary sibling files plus
  rename, or equivalent) so a failed second write cannot leave one document
  stale or truncated.

Do not treat the Task 15 commit as final until it receives a clean re-review.

## Remaining work after Task 15

| Task | Objective | Main files |
|---|---|---|
| 16 | Bubble Tea v2 shell, dark muted-mint visual system, key handling, no-color fallback, visible Raxuis credit | `go.mod`, `go.sum`, `internal/tui/{app,model,styles,keys}.go` |
| 17 | Guided TUI views: palette, form, review, running/results, filtering and accessible keyboard navigation | `internal/tui/*` |
| 18 | Explicit `interactive` launcher, noninteractive refusal, docs, deterministic screenshot, final validation | `cmd/interactive.go`, `main.go`, `README.md`, `ROADMAP.md`, screenshot asset |

For Tasks 16–18, use the `frontend-design` skill before implementation. The
user explicitly values the visual quality: selected rows must not use the
unwanted left-side border, and the credit must read
`Created by Raxuis · github.com/raxuis` in the human-facing TUI only. Machine
JSON and quiet output must stay free of decorative text.

## Public-documentation standard

The project should be publication-ready, not merely technically documented.
Keep these promises true in `README.md` and `ROADMAP.md`:

- Lead with the safe, beginner-friendly local demo and explain its intentional
  weaknesses, loopback-only scope, automatic shutdown, and no-public-network
  guarantee.
- Keep expert flows concise and reproducible: passive audit, JSON/HTML output,
  report comparison, thresholds, exit codes, privacy/redaction, and the schema
  version.
- Describe maturity labels honestly. Generated catalog blocks are authoritative;
  run `go generate ./internal/shared/catalog/...` and ensure no doc diff remains.
- Do not claim an interface, screenshot, or command until it exists. Add the
  TUI screenshot only in Task 18 after verifying the actual rendered result.
- Preserve the legal/authorized-use language and clearly separate passive,
  active, dangerous, and informational commands.
- Use local deterministic examples in documentation whenever possible. Never
  require a public target for tests or screenshots.

## Verification commands

Run focused tests while implementing, then the delivery/final gate:

```bash
/Users/raphael/go/bin/golangci-lint run
go vet ./...
go test -race ./...
make build-all
go run golang.org/x/vuln/cmd/govulncheck@latest ./...
go generate ./internal/shared/catalog/...
git diff --exit-code -- README.md ROADMAP.md
```

Useful manual local-only checks:

```bash
go run . demo web --output json
go run . demo web --output html --output-file /tmp/raxuis-demo.html
go run . compare /tmp/raxuis-before.json /tmp/raxuis-after.json --fail-on-new medium
```

Task 18 additionally requires a real interactive-terminal check; default CLI
invocation must never launch the TUI implicitly.

## Known deferred notes

- Legacy `GetCertFromHost` with a negative timeout remains unbounded rather
  than immediately expired.
- Scoped IPv6-zone URLs and Unicode terminal-dot equivalence are not normalized
  in the redirect policy.
- One closed-ephemeral-port test has a very small possible port-reuse race.
- Task 13 has two non-blocking coverage notes: test every typed read cause at
  command level, and replay the bundled README JSON fixture directly in a test.

These are not release blockers, but retain them in future review context.

## Session-resume checklist

1. Read this file, the plan, the detailed SDD ledger, and `git status --short`.
2. Confirm `CLAUDE.md` is still staged but untouched.
3. Finish the three Task 15 review findings, run the generator, and re-review.
4. Update both this file and the SDD ledger after each approved task.
5. Complete Tasks 16–18 with the same TDD, review, documentation, and gate
   discipline. Use `finishing-a-development-branch` only after the final gate.
