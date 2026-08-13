## Problem

Scan **rows** are durable (`pending|running|completed|failed`). Execution is `ScanWorker.jobs chan` buffer **32**, one goroutine, blocking enqueue. Restart loses queued jobs and orphans `pending`/`running`. 33rd POST blocks the HTTP handler. Two API replicas cannot share work. `execute` uses `context.Background()`. Hostname expansion uses `ip.To4()` only; private-range policy is CIDR-only.

## Proposed solution

`scans` **is** the queue. `POST /scans` inserts `pending` and returns 202 immediately. A poller claims with `FOR UPDATE SKIP LOCKED`. Restart reclaims stale `running`. No Redis. Apply private-range policy to hostname-resolved IPs. Same SKIP LOCKED pattern on outbox claimers.

## Acceptance criteria

- [ ] POST /scans never blocks on an in-memory channel.
- [ ] At most one replica runs a given scan id.
- [ ] Restart resumes pending and reclaims lease-expired running.
- [ ] Heartbeat prevents premature steal; crash allows steal.
- [ ] Over-cap pending → 503.
- [ ] consent + ALLOW_PRIVATE_RANGES unchanged; hostname private IPs obey the same policy.
- [ ] Docs: multi-replica scan execution is safe; Compose stays 1 replica by default.

## Test plan

- [ ] Concurrent claim SQL test
- [ ] Restart smoke: kill API mid-scan, restart, same id completes
- [ ] Two EDA claimers cannot take the same event
- [ ] `go test ./...` and `go build ./...`

## Superpowers spec

`docs/superpowers/specs/2026-08-13-m4-durable-scan-queue-design.md`

Plan: `docs/superpowers/plans/2026-08-13-m4-durable-scan-queue.md`

M2 verify may use direct `scanrunner.Run` until this ships.

## Out of scope

Named scan schedules (M4b), unbounded IPv6 `/64`, Redis, NATS, remote scan agents, `no_store` LIST miss.
