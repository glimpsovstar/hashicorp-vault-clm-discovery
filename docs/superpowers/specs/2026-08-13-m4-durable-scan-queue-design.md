# M4 — Durable scan queue — design

**Status:** Implemented  
**Date:** 2026-08-13  
**Parent:** [GCM closed-loop roadmap](2026-08-13-gcm-closed-loop-roadmap-design.md)  
**Plan:** [2026-08-13-m4-durable-scan-queue.md](../plans/2026-08-13-m4-durable-scan-queue.md)
**Issue:** [#81](https://github.com/glimpsovstar/hashicorp-vault-clm-discovery/issues/81)

---

## Problem

Scan **rows** are durable (`pending|running|completed|failed`). Execution is `ScanWorker.jobs chan` buffer **32**, one goroutine, blocking enqueue. Restart loses queued jobs and orphans `pending`/`running`. 33rd POST blocks the HTTP handler (60s write timeout). Two API replicas cannot share work. `execute` uses `context.Background()` — SIGTERM does not cancel probes. Hostname expansion uses `ip.To4()` only; private-range policy is CIDR-only (hostname→`10.x` still scans).

## Goal

`scans` **is** the queue. `POST /scans` inserts `pending` and returns 202 immediately. A poller claims with `FOR UPDATE SKIP LOCKED`. Restart reclaims stale `running`. No Redis.

## Design

- Columns: `claimed_at`, `claimed_by`, heartbeat while probing.
- Worker pool size via config (jobs, not probe concurrency).
- Backpressure: too many pending → **503**, never a hung POST.
- Shutdown: cancel scan ctx; leave row reclaimable.
- Same SKIP LOCKED pattern on outbox `ListUndeliveredEvents` (two replicas would double-deliver EDA today).
- After DNS, apply private-range policy to resolved IPs (and IPv6 ULA).

## Stretch (separate issues after core)

- Named scan profiles + interval (M4b).
- IPv6 AAAA + tight IPv6 CIDR cap (never unbounded `/64`).
- Cancel-scan API.

## Not this milestone

`no_store` LIST miss (needs audit ingest). Remote scan agents (need M1 + this queue first). Redis/NATS.

## Acceptance criteria

- [ ] POST /scans never blocks on an in-memory channel.
- [ ] At most one replica runs a given scan id.
- [ ] Restart resumes pending and reclaims lease-expired running.
- [ ] Heartbeat prevents premature steal; crash allows steal.
- [ ] Over-cap pending → 503.
- [ ] consent + ALLOW_PRIVATE_RANGES unchanged; hostname private IPs obey the same policy.
- [ ] Docs: multi-replica scan execution is safe; Compose stays 1 replica by default.

## Out of scope

Redis, k8s HPA, vault-agent-as-scanner, no_store reconcile.
