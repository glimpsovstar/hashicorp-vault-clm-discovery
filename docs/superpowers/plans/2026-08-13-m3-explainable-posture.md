# M3 Explainable Posture — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Persist pack+ops findings, compute explainable `risk_score`, waivers, PQC inventory tags — without changing SC-081/PCI/crypto rule IDs.

**Architecture:** Evaluate → upsert findings → `risk_score = max(non-waived)` + `risk_reasons[]`. Operational rubric ≤7/≤30; SC-081 keeps 14/60.

**Tech Stack:** Existing `internal/compliance`, `internal/report`, pgx, Next dashboard types.

## Global Constraints

- Spec: `docs/superpowers/specs/2026-08-13-m3-explainable-posture-design.md`
- Do not rewrite pack ceilings or UAT expiry matrix.
- Reject &lt;14-high / &lt;30-medium / else-low.
- No PQ issuance.
- `go test ./...`, `go test -tags uat ./internal/uat/...`, web tests.

## File structure

- `migrations/NNNN_posture.{up,down}.sql` — policy_versions, findings, waivers
- `internal/store/findings.go`, `waivers.go`
- `internal/compliance/severity.go` — warning → 5-level
- `internal/policy/` optional operational windows
- `internal/cert/keymeta.go` — PQC tag
- `web/lib/api.ts`, cert detail, inventory; `web/lib/findings.ts` consume API

---

### Task 1: Schema + persist pack output

- [ ] Findings upsert on `cert_id+rule_id`; recompute `risk_score`.
- [ ] Hook scan complete + enrichment PATCH.

### Task 2: Severity adapter + ops pack

- [ ] Map `warning`; emit `ClassifyCertificate` as `pack=ops` findings.
- [ ] Dedup insight vs shadow where spec requires.

### Task 3: Waivers + API

- [ ] CRUD with expiry; honor in counts/score.
- [ ] GET cert includes `risk_score` + `risk_reasons`.

### Task 4: PQC tag + UI + UAT

- [ ] classic/hybrid/pqc/unknown at parse; inventory count.
- [ ] Dashboard filter/sort; report table from persisted findings.
- [ ] UAT matrix still green.
