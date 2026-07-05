# CLM Lifecycle v1.1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** Deliver **Choose** (reconcile-informed) and **Manage** (Vault PKI reconciliation) slices of the CLM lifecycle so discovered certs align with Vault PKI, complementing HCP Certificates Inventory.

**Architecture:** Extend the external CLM service with `internal/vault` read-only client, post-scan or manual reconcile job, and dashboard/API surfacing of `managed_status` and Vault fields. Import and agent/AAP tracks deferred to v1.2 per [lifecycle design spec](../specs/2026-06-14-clm-lifecycle-workflow-design.md).

**Tech Stack:** Go 1.22+, PostgreSQL, Vault HTTP API, Chi REST, Next.js dashboard, table tests with HTTP mocks.

**Design spec:** [docs/superpowers/specs/2026-06-14-clm-lifecycle-workflow-design.md](../specs/2026-06-14-clm-lifecycle-workflow-design.md)  
**HCP / reconcile detail:** [docs/superpowers/specs/2026-06-14-hcp-vault-cert-inventory-integration-design.md](../specs/2026-06-14-hcp-vault-cert-inventory-integration-design.md)

---

## Scope

This plan covers **v1.1 lifecycle slices only**:

| Lifecycle phase | In scope (v1.1) | Deferred |
|-----------------|-----------------|----------|
| Discover | Post-scan reconcile hook (optional) | — |
| Choose | Reconcile informs `managed_status`; scope refinement rules | Choose wizard UI |
| Import | — | `import/bundle` workflow (v1.2) |
| Manage | Reconcile API, dashboard Vault column, docs | vault-agent, AAP, HCP API ingest |

---

## File map (expected touch points)

| Area | Files |
|------|-------|
| Vault client | Create `internal/vault/client.go`, `auth.go`, `pki.go` |
| Reconciler | Create `internal/vault/reconcile.go`, `reconcile_test.go` |
| Config | Modify `internal/config/config.go` (or equivalent env loader) |
| API | Modify `internal/api/handlers.go` — `POST /api/v1/reconcile` |
| Store | Modify `internal/store/certificates.go` — update managed fields |
| Worker | Modify scan worker — optional `RECONCILE_ON_SCAN_COMPLETE` |
| Migrations | Only if new columns needed (prefer existing schema per `data-model.md`) |
| Dashboard | Modify inventory table components under `web/` |
| Docs | `README.md`, `docs/architecture.md`, `docs/data-model.md` |
| Operator guide | Create or extend `docs/operator-lifecycle.md` (optional v1.1 doc slice) |

---

### Task 1: Vault client foundation

**Files:**
- Create: `internal/vault/client.go`
- Create: `internal/vault/client_test.go`
- Test: `internal/vault/client_test.go`

- [x] **Step 1:** Add env vars to config loader: `VAULT_ADDR`, `VAULT_NAMESPACE`, `VAULT_AUTH_METHOD`, AppRole/token/AWS fields per HCP spec
- [x] **Step 2:** Write failing test — client authenticates against httptest Vault stub returning 200 on `sys/mounts`
- [x] **Step 3:** Implement minimal client with namespace header and auth wrapper
- [x] **Step 4:** Run `go test ./internal/vault/... -v` — expect PASS
- [x] **Step 5:** Document env vars in `README.md` § Environment variables

---

### Task 2: PKI mount discovery and cert list/read

**Files:**
- Create: `internal/vault/pki.go`
- Test: `internal/vault/pki_test.go`

- [x] **Step 1:** Write table test — mock `sys/mounts` filters `type=pki`; mock `LIST pki/certs/` and `READ pki/cert/{serial}`
- [x] **Step 2:** Implement `ListPKIMounts`, `ListCertSerials(mount)`, `ReadCert(mount, serial)` returning PEM + metadata
- [x] **Step 3:** Implement fingerprint helper (SHA-256 DER) aligned with `internal/cert`
- [x] **Step 4:** Run `go test ./internal/vault/... -v` — expect PASS

---

### Task 3: Reconciliation engine

**Files:**
- Create: `internal/vault/reconcile.go`
- Modify: `internal/store/certificates.go`
- Test: `internal/vault/reconcile_test.go`

- [x] **Step 1:** Write failing test — two CLM certs in store; mock Vault returns one matching fingerprint → one row `managed_in_vault`, one `unmanaged`
- [x] **Step 2:** Implement reconcile loop: mounts → serials → read → fingerprint → store update
- [x] **Step 3:** Populate `vault_pki_mount`, `vault_issuer_ref`, `serial_number` on match; idempotent re-run
- [x] **Step 4:** Apply optional `cert_scope` rule per open question #8 (document chosen behavior in code comment + data-model)
- [x] **Step 5:** Return summary struct: `{mounts_scanned, certs_read, matched, errors}`
- [x] **Step 6:** Run `go test ./internal/vault/... -v` and `go test ./internal/store/... -v`

---

### Task 4: Reconcile API and scan hook

**Files:**
- Modify: `internal/api/handlers.go` (or routes file)
- Modify: scan worker completion path

- [x] **Step 1:** Write API test — `POST /api/v1/reconcile` returns 200 + summary JSON when Vault configured
- [x] **Step 2:** Implement handler; 503 if Vault not configured
- [x] **Step 3:** If `RECONCILE_ON_SCAN_COMPLETE=true`, invoke reconciler after successful scan (log errors, do not fail scan)
- [x] **Step 4:** Run `go test ./internal/api/... -v`

---

### Task 5: Dashboard Vault column wiring

**Files:**
- Modify: `web/` inventory table component(s)
- Modify: `web/lib/api.ts` if new endpoint client needed

- [x] **Step 1:** Ensure inventory API response includes `managed_status`, `vault_pki_mount`
- [x] **Step 2:** Vault column: Connected when `managed_in_vault`, else Not connected (per `data-model.md`)
- [x] **Step 3:** Optional: Reconcile button or link to docs (manual trigger v1.1)
- [x] **Step 4:** Run `cd web && npm run build`

---

### Task 6: Revocation alignment (v1.1b slice)

**Files:**
- Modify: `internal/vault/reconcile.go` or new `revocation.go`
- Modify: `internal/store/certificates.go` — `status`, `revocation_status`

> **Status: deferred to v1.1b — NOT yet implemented.** This slice is the next task
> (see `docs/superpowers/specs/…-revocation-alignment-design.md`).

- [ ] **Step 1:** Write test — revoked serial in Vault CRL/registry → CLM `status=revoked`
- [ ] **Step 2:** Implement read of revocation metadata from Vault PKI cert response
- [ ] **Step 3:** Run `go test ./...`
- [ ] **Step 4:** Update `docs/data-model.md` revocation fields (v1 → Yes)

---

### Task 7: Documentation and lifecycle operator narrative

**Files:**
- Modify: `README.md` — roadmap, reconcile env vars, link to lifecycle spec
- Modify: `docs/architecture.md` — Vault integration section, lifecycle diagram reference
- Modify: `docs/data-model.md` — reconcile field semantics, Choose matrix pointer
- Optional create: `docs/operator-lifecycle.md` — short operator guide for Discover → Choose → Manage (v1.1)

- [x] **Step 1:** Add lifecycle spec link to README Roadmap
- [x] **Step 2:** Cross-link HCP spec from architecture § Vault integration
- [x] **Step 3:** Document read-only Vault policy (from HCP spec) in README
- [x] **Step 4:** Note HCP complement in demo-flow or CONTRIBUTING if applicable

---

### Task 8: Verification gate

- [x] Run `go test ./...`
- [x] Run `go build ./...`
- [x] Run `docker compose -f deploy/docker-compose.yml build` (if compose unchanged, smoke only)
- [x] Manual: scan demo hostname → reconcile against test Vault → Vault column Connected for matched cert
- [x] Manual: compare one row with HCP Certificates Inventory (human compare — complement narrative)

---

## Post–v1.1 backlog (not in this plan)

| Item | Spec reference | Target version |
|------|----------------|----------------|
| CA `import/bundle` workflow | Lifecycle spec § Import | v1.2 |
| Choose wizard / recommended actions | Lifecycle spec § Choose | v1.2 |
| vault-agent / AAP integration links | Lifecycle spec § Manage | v1.2 |
| HCP Vault Reporting API ingest | HCP spec § v1.2 | v1.2 |
| Vault-only cert list in CLM | Open question #7 | v1.1 or v1.2 |
| Cloud CA sources (ACM) | README v2 | v2 |

---

## Self-review (spec coverage)

| Spec requirement | Task |
|------------------|------|
| Vault PKI reconcile | Tasks 1–4 |
| Field mapping `managed_status`, `vault_pki_mount`, `vault_issuer_ref` | Task 3 |
| Dashboard Vault column | Task 5 |
| Revocation `status` | Task 6 |
| HCP complement docs | Task 7 |
| Import / agent / AAP | Post–v1.1 backlog |
| Choose decision matrix UX | Backlog v1.2 |
