# M2 — Durable lifecycle jobs and closed-loop renewal — design

**Status:** Approved  
**Date:** 2026-08-13  
**Parent:** [GCM closed-loop roadmap](2026-08-13-gcm-closed-loop-roadmap-design.md)  
**Plan:** [2026-08-13-m2-durable-lifecycle-jobs.md](../plans/2026-08-13-m2-durable-lifecycle-jobs.md)  
**Depends on:** M1 for real actors/approvals (job persist+verify can ship degraded on consent)

---

## Problem

`POST /certificates/{id}/renew` and `POST /renew-expiring` launch AAP and return **202** with a Controller job id. Nothing in Postgres stores that id. `aap.Client.WaitForJob` is tested and **never called from handlers**. No `renewal.*` outbox events. No auto-rescan. “Closed loop” in the README is an operator procedure, not a state machine. Process restart after 202 loses the job. AAP `successful` is not “new cert on the wire.”

A successful renew **changes fingerprint** (new cert row). Verify must not expect the predecessor fingerprint.

## Goal

Handlers stay 202. A **background worker** owns the AAP job: persist before ack → poll with existing `WaitForJob` → targeted rescan → **verified** only if expected-vs-observed matches. AAP remains the only deployer.

## State machine (map to existing `aap.Status`)

```
create → [pending_approval] → launching → aap_pending/running
      → aap_successful → verifying → verified | verify_failed
      → aap_failed|error|canceled → failed
```

Do not invent AAP-equivalent states. Worker uses `internal/aap` only.

## Data (next unused migration)

- `lifecycle_jobs` — predecessor/successor cert ids, `aap_job_id`, status, idempotency_key, claim lease, expected/observed JSONB
- `job_events` — append-only timeline (distinct from EDA `events`)
- `approvals` — actor + decision; auto-approve short-TTL already-approved `(mount,role)` still writes a row

Also: on-demand `/renew` must `SetRenewalConfig` (today only catalog-import persists it).

## Verify predicate

1. Scan predecessor’s last observation (or `target_hosts`).
2. New leaf, **same CN**, **different** `fingerprint_sha256`.
3. `not_after` later than predecessor.
4. If Vault configured: successor `managed_in_vault` after reconcile.
5. Predecessor no longer served on that endpoint (or not `last_seen` this scan).

AAP success alone must not mark the job completed.

## Stopgap vs M4

M2 verify may call `scanrunner.Run` after `CreateScan` (row in Postgres). Full HA scan claims are **M4**. Document that kill-during-probe is only solid after M4.

## Acceptance criteria

- [ ] After successful Controller launch, `lifecycle_jobs.aap_job_id` exists **before** 202.
- [ ] No handler calls `WaitForJob` on `r.Context()`.
- [ ] Restart reclaims `launching|aap_*|verifying` and does not double-launch when `aap_job_id` is set.
- [ ] Idempotency key prevents a second AAP launch.
- [ ] `renewal.launched` in same txn as persist; `renewal.completed` only after **verified**; `renewal.failed` distinguishes AAP vs verify.
- [ ] `/renew-expiring` inserts N jobs and returns; launches happen in the worker.
- [ ] `GET /lifecycle-jobs/{id}` returns status, AAP id, expected/observed.
- [ ] No new SSH/k8s adapter package.

## Out of scope

NATS, ITSM, cloud collectors, Vault plugin, putting WaitForJob on the HTTP request (60s write timeout).
