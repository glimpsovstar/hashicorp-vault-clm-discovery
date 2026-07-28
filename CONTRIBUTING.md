# Contributing — HashiCorp Vault CLM Discovery

This repo demonstrates **Cursor + Superpowers + GitHub SDLC**. Follow the workflow below for features and bugs.

## SDLC workflow

1. **Issue** — [Feature](../.github/ISSUE_TEMPLATE/feature_request.md) or [Bug](../.github/ISSUE_TEMPLATE/bug_report.md) template; acceptance criteria + test plan.
2. **Design** — `docs/superpowers/specs/YYYY-MM-DD-<topic>-design.md` (Superpowers `brainstorming` gate).
3. **Plan** — `docs/superpowers/plans/YYYY-MM-DD-<feature>.md` (Superpowers `writing-plans`).
4. **Branch** — `feature/<issue#>-slug` or `fix/<issue#>-slug` from `main`.
5. **Implement** — tests per [`.cursor/rules/require-tests.mdc`](.cursor/rules/require-tests.mdc).
6. **Docs** — README / architecture / data-model per [`.cursor/rules/require-docs.mdc`](.cursor/rules/require-docs.mdc).
7. **Verify** — `go test ./...`, `go build ./...`, `cd web && npm run build`, Docker Compose smoke test.
8. **Pull request** — [template](../.github/pull_request_template.md), `Fixes #N`.
9. **Merge** — squash to `main`; close issue.

Skip only when explicitly requested ("skip SDLC") or for trivial typos.

## Verification commands

```bash
go test ./...
go test -tags uat ./internal/uat/...            # expiry/validity integration test
sh test/uat/run-uat.sh                          # full self-cleaning docker UAT (up --wait -> driver -> down)
go build ./...
cd web && npm run build
docker compose -f deploy/docker-compose.yml up --build -d
curl -s http://localhost:8080/api/v1/health
curl -s -o /dev/null -w "%{http_code}\n" http://localhost:3000/
```

## Cursor rules

| Layer | Location |
|-------|----------|
| **Organization** | [glimpsovstar/cursor-org-rules](https://github.com/glimpsovstar/cursor-org-rules) — SDLC, Superpowers, commit/PR |
| **Project** | [`.cursor/rules/`](.cursor/rules/) — tests, docs, project context |

Install org rules: copy `org-*.mdc` to `~/.cursor/rules/` or paste `cursor-org-rules/team-rules/` into Cursor **Team Content**.

## Claude Code settings

`.claude/` is **gitignored in full**. Claude Code owns those files and rewrites
them every session — approvals you grant are appended automatically — so
tracking them produces a file that is modified after almost every session,
gets swept into unrelated commits, and conflicts between contributors. Your
allowlist is therefore local; this section is the shared part.

### Never allowlist these

A permission entry is unattended: once granted, the agent runs matching commands
without prompting. Judge an entry by the worst command that matches its pattern,
not the one you happened to be running.

| Entry | Why not |
|-------|---------|
| `Bash(podman machine *)` | `podman machine ssh <cmd>` runs as **passwordless root** in the VM, which bind-mounts your host home read-write. Full read/write on `~/.ssh`, `~/.aws`, every repo. |
| `Bash(docker compose *)` / `Bash(podman compose *)` | `compose run -v /:/host … sh -c '…'` is arbitrary code with arbitrary host mounts; `compose down -v` destroys the `pgdata` volume without a prompt. |
| `Bash(docker exec *)` / `Bash(podman exec *)` | Blanket exec inside containers; reaches the database and the bind-mounted `migrations/` tree. |
| `Bash(python3 -c ' *)`, `Bash(python3 -)` | Arbitrary code execution wearing an innocuous prefix. |
| `Bash(*)`, `Bash(sudo *)` | Unbounded. |

Prefer the narrowest form that still matches routine work — `Bash(docker compose up *)`
and `Bash(docker compose down)` (no wildcard, so `-v` cannot slip in) rather than
`Bash(docker compose *)`.

### Prefer entries that generalize

Allowlist patterns are **prefix** matches, so a trailing `*` covers a whole verb
while a fully-specified command matches only its exact repeat. Both are valid —
the fixed `curl` health checks under [Verification commands](#verification-commands)
recur every cycle and are worth keeping.

Avoid entries that encode one session's incidental history: a `curl` pinned to a
demo hostname you will not scan again, an `awk` carrying a literal output prefix,
a `grep` bound to one file's heading regex. They will not match anyone else's
work and they leak local paths.

## Demo narrative

See [`.prompts-history.md`](.prompts-history.md) for the Cursor-assisted build log used in demos.

## Authorized scanning

Only scan targets you own or have permission to test. API and CLI require explicit consent.
