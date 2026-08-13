## Problem

`POST /certificates/{id}/renew` and `POST /renew-expiring` launch AAP and return **202** with a Controller job id. Nothing in Postgres stores that id. `WaitForJob` is tested and never called from production handlers. Process restart after 202 loses the job. AAP `successful` is not “new cert on the wire.” A successful renew **changes fingerprint**.

## Proposed solution

Handlers stay 202. Persist a `lifecycle_jobs` row **before** ack. A background worker polls with existing `WaitForJob`, then targeted rescan. Mark **verified** only if expected-vs-observed matches (same CN, new fingerprint, later `not_after`). AAP remains the only deployer. No handler `WaitForJob` on `r.Context()`.

## Acceptance criteria

- [ ] 202 includes `lifecycle_job_id`; kill-after-ack still has a row.
- [ ] Worker maps `aap.Status*` → CLM status; restart does not double-launch if `aap_job_id` is set.
- [ ] `renewal.completed` only after wire verify; AAP success alone is not completed.
- [ ] `GET /lifecycle-jobs/{id}` and list-by-cert.
- [ ] On-demand `/renew` persists `SetRenewalConfig`.
- [ ] Docs replace “closed-loop = later rescan” with the state machine.

## Test plan

- [ ] Store claim/lease tests
- [ ] Handler 202 + persist tests
- [ ] Recovery: new worker, empty memory, same AAP id
- [ ] Verify predicate table tests (same CN / new fingerprint / later not_after)
- [ ] `go test ./...` and `go build ./...`

## Superpowers spec

`docs/superpowers/specs/2026-08-13-m2-durable-lifecycle-jobs-design.md`

Plan: `docs/superpowers/plans/2026-08-13-m2-durable-lifecycle-jobs.md`

Depends on: M1 for real actors/approvals (persist+verify can ship degraded on consent).

## Out of scope

SSH/k8s adapter package, handler-blocking WaitForJob, claiming SoD-complete before M1 actors, Redis/NATS.
