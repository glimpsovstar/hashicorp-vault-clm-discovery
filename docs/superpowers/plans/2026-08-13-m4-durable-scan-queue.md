# M4 Durable Scan Queue — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace in-memory `chan(32)` with Postgres `FOR UPDATE SKIP LOCKED` claims so scans survive restart and multi-replica.

**Architecture:** `scans` is the queue. POST inserts pending; poller claims; heartbeat; stale running reclaim. No Redis.

**Tech Stack:** pgx, existing scanrunner, eventbus-style poller.

## Global Constraints

- Spec: `docs/superpowers/specs/2026-08-13-m4-durable-scan-queue-design.md`
- Core ship = tasks 1–5. IPv6 and schedules are follow-up issues.
- Apply private-range policy to hostname-resolved IPs.
- `go test ./...`, `go build ./...`.

## File structure

- `migrations/NNNN_scan_claims.{up,down}.sql`
- `internal/store` ClaimNextScan / Heartbeat / RequeueStale
- `internal/api/server.go` — remove channel; poller + shutdown ctx
- `internal/scanner/scanner.go` — private IP after DNS
- Optional: outbox SKIP LOCKED
- `docs/architecture.md`, `docs/data-model.md`

---

### Task 1: Migration + claim SQL

- [ ] `claimed_at`, `claimed_by`; SKIP LOCKED claim; concurrent claim test.

### Task 2: Replace ScanWorker channel

- [ ] POST only CreateScan; poller Run; 503 over cap; no blocking enqueue.

### Task 3: Context + shutdown + heartbeat

- [ ] Cancel ctx from main; reclaimable on SIGTERM; no `context.Background()` in execute.

### Task 4: Hostname private-range + outbox SKIP LOCKED

- [ ] Drop/warn RFC1918/ULA unless ALLOW_PRIVATE_RANGES.
- [ ] Two EDA claimers cannot take the same event.

### Task 5: Docs + restart smoke

- [ ] Architecture: DB claim not “worker pool channel”.
- [ ] Optional: kill API mid-scan, restart, same id completes.
