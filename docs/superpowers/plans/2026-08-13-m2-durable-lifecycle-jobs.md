# M2 Durable Lifecycle Jobs — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Persist AAP job ids, poll with existing `WaitForJob` in a worker, and mark success only after expected-vs-observed wire verification.

**Architecture:** HTTP stays 202. New `lifecycle_jobs` + claim loop (same Postgres idea as M4). AAP is the only deployer. Successor cert has a **new fingerprint**.

**Tech Stack:** Go, pgx, existing `internal/aap`, `scanrunner`, outbox `appendEventTx`.

## Global Constraints

- Spec: `docs/superpowers/specs/2026-08-13-m2-durable-lifecycle-jobs-design.md`
- No handler calls `WaitForJob` on `r.Context()` (60s write timeout).
- No SSH/k8s adapter package.
- Approvals may be auto/consent until M1 actors exist; do not claim SoD-complete.
- Verify may use `CreateScan` + `scanrunner.Run` until M4.
- `go test ./...` and `go build ./...` before PR.

## File structure

- `migrations/NNNN_lifecycle_jobs.{up,down}.sql`
- `internal/store/lifecycle_jobs.go` (+ tests)
- `internal/lifecyclejobs/` worker
- `internal/api/server.go` handlers + `GET /lifecycle-jobs`
- `cmd/clm-discovery/main.go` start worker next to eventbus
- README / architecture / data-model / ADR 0001 catalogue note

---

### Task 1: Schema + store (TDD)

- [ ] Tables: jobs, job_events, approvals; indexes on status/lease, unique idempotency.
- [ ] `InsertJob`, `ClaimExpiredLeases`, `SetAAPRef`, `UpdateStatus`, `AppendJobEvent`.

### Task 2: Persist before 202

- [ ] Insert job + `renewal.launched` before 202; persist `SetRenewalConfig` on `/renew`.
- [ ] Batch `/renew-expiring` inserts N jobs; worker launches.
- [ ] Tests: 202 includes `lifecycle_job_id`; kill-after-ack still has row.

### Task 3: Worker + WaitForJob

- [ ] Claim loop; call existing `WaitForJob` / `JobStatus`.
- [ ] Map `aap.Status*` → CLM status; restart does not double-launch if `aap_job_id` set.

### Task 4: Verify

- [ ] After `aap_successful`, targeted scan; same CN, new fingerprint, later `not_after`.
- [ ] `renewal.completed` only on verified; else `renewal.failed` with reason.

### Task 5: Read API + docs

- [ ] `GET /lifecycle-jobs/{id}` and list-by-cert.
- [ ] Thin approvals (auto vs human).
- [ ] Recovery tests (new worker, empty memory, same AAP id).
- [ ] Docs replace “closed-loop = later rescan”.
