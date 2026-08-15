# Connections Settings options UX — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Human-labeled Connections Settings with compact radios and dropdowns for Vault PKI mounts and AAP job/workflow templates, filled from live resolved connections.

**Architecture:** Read-only options endpoints on the Go API use `settings.Resolve` + existing Vault `ListPKIMounts` and new AAP list helpers. Next BFF already proxies `/api/v1/*`. UI selects store the same fields as today (`default_mount`, `renew_template`, `renew_workflow`).

**Tech Stack:** Go chi/httptest, existing vault/aap clients, Next.js Helios CSS, Vitest.

## Global Constraints

- Spec: `docs/superpowers/specs/2026-08-14-connections-settings-options-design.md`
- Approach A only — persist mount path + template name + `renew_workflow` bool; no template ID as SoR.
- Env var names unchanged (`AAP_DEFAULT_MOUNT`, etc.).
- Free-text fallback when options empty or peer fails.
- No secrets in options responses; no AAP job launch.
- Auth: Settings GET roles (`platform_admin` | `remediator`).
- Docs as you code; TDD; commit per task; subagent review per task.
- No Cursor co-author trailers.

## File structure

- `internal/aap/client.go` (+ tests) — list job/workflow templates
- `internal/api/handlers_settings_options.go` (+ tests) — options handlers
- `internal/api/server.go` — routes
- `web/app/globals.css` — radio sizing
- `web/app/settings/connections/connections-form.tsx` (+ tests)
- `web/lib/api.ts` — fetch options helpers
- README, `docs/architecture.md`, Connections design cross-link

---

### Task 1: CSS — compact radios

- [x] Override `input[type="radio"]` like checkboxes (`width: auto; min-height: auto; box-shadow: none`).
- [x] Visual/regression: Connections form still renders radios (Vitest role=radio).
- [x] Commit.

### Task 2: AAP list templates

- [x] TDD: httptest paginated list for job_templates and workflow_job_templates.
- [x] `ListJobTemplates` / `ListWorkflowJobTemplates` returning `{ID, Name}` (cap ~200).
- [x] Must not call launch endpoints.
- [x] Commit.

### Task 3: Options API handlers

- [x] TDD: vault-pki-mounts returns ListPKIMounts via Resolve; aap-templates?kind=; 400 bad kind; empty when unconfigured; 502 when configured but peer fails (or document 200+detail — match spec **502**).
- [x] Wire routes; RBAC via existing Settings read gate.
- [x] Commit.

### Task 4: Connections UI

- [x] TDD: human labels; Job/Workflow radios; selects with free-text fallback; mount help text.
- [x] Fetch options via same-origin BFF; reload after successful save.
- [x] Commit.

### Task 5: Docs + verify

- [x] README / architecture: options endpoints, UI labels, mount meaning.
- [x] Close/link #92 into #91 narrative.
- [x] `go test ./...`, `go build ./...`, `cd web && npm test && npm run build`.
- [x] Commit.
