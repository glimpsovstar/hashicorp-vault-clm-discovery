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

## Demo narrative

See [`.prompts-history.md`](.prompts-history.md) for the Cursor-assisted build log used in demos.

## Authorized scanning

Only scan targets you own or have permission to test. API and CLI require explicit consent.
