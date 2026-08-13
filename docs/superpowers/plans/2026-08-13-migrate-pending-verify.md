# Migrate to Vault (pending verify) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend M2 `lifecycle_jobs` with Mode C migrate + a CLM-owned `pending_verify` backoff loop so operators can replace ADCS/AKV/TLS leaves with a Vault-issued cert and see **Pending** until the wire matches or the job times out.

**Architecture:** Dual kickoff (on-demand CLM→AAP; policy/batch outbox→EDA webhook→AAP + claim). Same M2 worker owns `WaitForJob` and targeted rescans. User-facing Pending maps to `pending_verify`. Success is the M2 predicate, not AAP `successful`. Timeout default 24h.

**Tech Stack:** Go, pgx, existing `internal/aap`, `scanrunner`, outbox `appendEventTx`, Next.js dashboard.

**Prerequisite:** M2 (`docs/superpowers/plans/2026-08-13-m2-durable-lifecycle-jobs.md`) must land first — or this PR stack sits on top of those commits. Do **not** recreate `lifecycle_jobs` from scratch.

## Global Constraints

- Spec: `docs/superpowers/specs/2026-08-13-migrate-pending-verify-design.md`
- Extends M2; do not re-specify the whole job table.
- No leaf PEM upload; no Vault `pki/issue` from CLM; no private keys in CLM.
- UI/API copy: **Migrate to Vault**, never Upload.
- Dual kickoff: on-demand launches AAP; policy/batch emits `renewal.requested` only.
- CLM owns verify; EDA does not rescan.
- Events: `renewal.requested` / `renewal.launched` / `renewal.verified` / `renewal.timed_out` (keep M2 `renewal.failed` for AAP failure).
- Backoff: 10s, 30s, 60s, 5m, 30m, 60m, 3h, 6h (cap). Timeout default 24h (`LIFECYCLE_VERIFY_TIMEOUT`).
- No handler `WaitForJob` on `r.Context()`. No SSH/k8s adapter. No NATS/Kafka.
- Next unused migration number at implement time (after M2’s).
- `go test ./...` and `go build ./...` before PR. Web: `cd web && npm test && npm run build` for UI tasks.

## File structure

- Create: `migrations/NNNN_lifecycle_job_verify.{up,down}.sql` — `job_kind`, `next_verify_at`, `timeout_at`, `verify_attempt`; allow statuses `pending_verify`, `timed_out`
- Create: `internal/lifecyclejobs/backoff.go` + `backoff_test.go`
- Modify: `internal/store/lifecycle_jobs.go` + tests (M2) — new columns and claim-by-`next_verify_at`
- Modify: `internal/lifecyclejobs/` worker (M2) — pending_verify loop
- Modify: `internal/config/config.go` + `config_test.go` — timeout + poll interval
- Modify: `internal/api/server.go` — `/migrate`, `/migrate-eligible`, `/lifecycle-jobs/claim`; extend GET job JSON
- Create: `internal/api/handlers_migrate_test.go`
- Modify: `internal/lifecycle/choose.go` + `choose_test.go` — leaf CTA **Migrate to Vault**
- Modify: `cmd/clm-discovery/main.go` — worker already started by M2; pass new config
- Create: `web/components/migrate-to-vault-button.tsx` + test
- Create: `web/components/lifecycle-job-pending.tsx` + test
- Modify: `web/lib/api.ts`, `web/app/certificates/[id]/page.tsx`, report explorer if it has cert actions
- Modify: `README.md`, `docs/architecture.md`, `docs/data-model.md`, `docs/adr/0001-source-of-truth-and-event-driven-automation.md` (catalogue)

M2 types this plan consumes (do not redefine):

```go
// internal/store — created by M2
type LifecycleJob struct {
    ID               uuid.UUID
    PredecessorID    uuid.UUID
    SuccessorID      *uuid.UUID
    AAPJobID         *int
    Status           string
    IdempotencyKey   string
    Expected         json.RawMessage
    Observed         json.RawMessage
    ClaimedUntil     *time.Time
    CreatedAt        time.Time
    UpdatedAt        time.Time
}

const (
    JobStatusLaunching    = "launching"
    JobStatusAAPPending   = "aap_pending"
    JobStatusAAPRunning   = "aap_running"
    JobStatusAAPSuccessful = "aap_successful"
    JobStatusVerified     = "verified"
    JobStatusFailed       = "failed"
)
```

This plan **adds** fields and constants below.

---

### Task 1: Schema + store (`pending_verify`, `next_verify_at`)

**Files:**
- Create: `migrations/NNNN_lifecycle_job_verify.up.sql`
- Create: `migrations/NNNN_lifecycle_job_verify.down.sql`
- Modify: `internal/store/lifecycle_jobs.go`
- Test: `internal/store/lifecycle_jobs_test.go` (M2 file; add cases)

**Interfaces:**
- Consumes: M2 `LifecycleJob`, `InsertJob`, `ClaimExpiredLeases`, `SetAAPRef`, `UpdateStatus`
- Produces:

```go
const (
    JobKindMigrate = "migrate"
    JobKindRenew   = "renew"

    JobStatusPendingVerify = "pending_verify"
    JobStatusTimedOut      = "timed_out"
)

type LifecycleJob struct {
    // ... M2 fields ...
    Kind          string     `json:"job_kind"`
    NextVerifyAt  *time.Time `json:"next_verify_at,omitempty"`
    TimeoutAt     time.Time  `json:"timeout_at"`
    VerifyAttempt int        `json:"verify_attempt"`
}

func UserStatus(status string) string // Pending | Verified | Timed out | Failed

func (s *Store) ClaimDueVerifyJobs(ctx context.Context, now time.Time, limit int, lease time.Duration) ([]LifecycleJob, error)
func (s *Store) ScheduleNextVerify(ctx context.Context, id uuid.UUID, attempt int, next time.Time) error
func (s *Store) ClaimByIdempotency(ctx context.Context, key string, aapJobID int) (LifecycleJob, error)
```

- [ ] **Step 1: Write the failing store tests**

```go
func TestUserStatus_PendingIncludesPendingVerify(t *testing.T) {
    t.Parallel()
    for _, st := range []string{"launching", "aap_pending", "aap_running", "aap_successful", "pending_verify"} {
        if got := store.UserStatus(st); got != "Pending" {
            t.Fatalf("UserStatus(%q)=%q want Pending", st, got)
        }
    }
    if store.UserStatus("verified") != "Verified" {
        t.Fatal("verified")
    }
    if store.UserStatus("timed_out") != "Timed out" {
        t.Fatal("timed_out")
    }
    if store.UserStatus("failed") != "Failed" {
        t.Fatal("failed")
    }
}

func TestClaimDueVerifyJobs_OnlyPendingAndDue(t *testing.T) {
    // Insert three jobs: pending_verify due, pending_verify future, verified due.
    // ClaimDueVerifyJobs(now, 10, time.Minute) returns only the first.
}

func TestScheduleNextVerify_PersistsAttemptAndNext(t *testing.T) {
    // After ScheduleNextVerify(id, 2, next), GetJob shows VerifyAttempt=2, NextVerifyAt=next, Status=pending_verify.
}

func TestClaimByIdempotency_SetsAAPRefOnce(t *testing.T) {
    // First claim stores aap_job_id; second same id is OK; different id returns a conflict error.
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/store/ -count=1 -run 'UserStatus|ClaimDueVerify|ScheduleNextVerify|ClaimByIdempotency'`

Expected: FAIL (`UserStatus` undefined and/or missing columns).

- [ ] **Step 3: Write the migration**

`migrations/NNNN_lifecycle_job_verify.up.sql` (NNNN = next unused after M2):

```sql
ALTER TABLE lifecycle_jobs
    ADD COLUMN job_kind TEXT NOT NULL DEFAULT 'renew',
    ADD COLUMN next_verify_at TIMESTAMPTZ,
    ADD COLUMN timeout_at TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '24 hours',
    ADD COLUMN verify_attempt INT NOT NULL DEFAULT 0;

ALTER TABLE lifecycle_jobs DROP CONSTRAINT IF EXISTS lifecycle_jobs_status_check;
ALTER TABLE lifecycle_jobs ADD CONSTRAINT lifecycle_jobs_status_check
    CHECK (status IN (
        'pending_approval','launching','aap_pending','aap_running','aap_successful',
        'pending_verify','verified','timed_out','failed'
    ));

ALTER TABLE lifecycle_jobs ADD CONSTRAINT lifecycle_jobs_kind_check
    CHECK (job_kind IN ('migrate','renew'));

CREATE INDEX lifecycle_jobs_verify_due_idx
    ON lifecycle_jobs (next_verify_at)
    WHERE status = 'pending_verify';
```

Down: drop index, restore M2 status check (without `pending_verify`/`timed_out`), drop the four columns.

- [ ] **Step 4: Implement store methods**

`UserStatus`: map as in the spec table. `ClaimDueVerifyJobs`: `FOR UPDATE SKIP LOCKED` where `status = 'pending_verify' AND next_verify_at <= $now AND timeout_at > $now` (jobs past `timeout_at` are claimed by the timeout path in Task 2, not this query). `ClaimByIdempotency`: update `aap_job_id` if null or equal; error if a different id is stored.

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/store/ -count=1 -run 'UserStatus|ClaimDueVerify|ScheduleNextVerify|ClaimByIdempotency'`

Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add migrations/NNNN_lifecycle_job_verify.*.sql internal/store/lifecycle_jobs.go internal/store/lifecycle_jobs_test.go
git commit -m "$(cat <<'EOF'
Add pending_verify columns and claim helpers on lifecycle_jobs.

Migrate-to-Vault needs a durable next_verify_at/timeout clock on the M2 job row so the worker can rescan without holding HTTP.
EOF
)"
```

---

### Task 2: Backoff helper + verify scheduler

**Files:**
- Create: `internal/lifecyclejobs/backoff.go`
- Create: `internal/lifecyclejobs/backoff_test.go`
- Modify: `internal/lifecyclejobs/worker.go` (M2)
- Test: `internal/lifecyclejobs/worker_verify_test.go`
- Modify: `internal/config/config.go`, `internal/config/config_test.go`

**Interfaces:**
- Consumes: `store.ClaimDueVerifyJobs`, `store.ScheduleNextVerify`, M2 verify predicate (`same CN`, new `fingerprint_sha256`, later `not_after`, predecessor not served), `scanrunner.Runner.Run`
- Produces:

```go
func VerifyDelay(attempt int) time.Duration
// attempt is 1-based (first probe). 1→10s, 2→30s, 3→60s, 4→5m, 5→30m, 6→60m, 7→3h, 8+→6h.

func NextVerifyAt(now time.Time, attempt int, timeoutAt time.Time) (next time.Time, last bool)

type Config struct {
    VerifyTimeout time.Duration // env LIFECYCLE_VERIFY_TIMEOUT default 24h
    VerifyPoll    time.Duration // env LIFECYCLE_VERIFY_POLL_INTERVAL default 5s
}
```

- [ ] **Step 1: Write failing backoff tests**

```go
func TestVerifyDelay(t *testing.T) {
    t.Parallel()
    want := []time.Duration{
        10 * time.Second, 30 * time.Second, 60 * time.Second,
        5 * time.Minute, 30 * time.Minute, 60 * time.Minute,
        3 * time.Hour, 6 * time.Hour, 6 * time.Hour,
    }
    for i, d := range want {
        if got := lifecyclejobs.VerifyDelay(i + 1); got != d {
            t.Fatalf("attempt %d: got %v want %v", i+1, got, d)
        }
    }
}

func TestNextVerifyAt_CapsAtTimeout(t *testing.T) {
    now := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)
    timeout := now.Add(15 * time.Second)
    next, last := lifecyclejobs.NextVerifyAt(now, 1, timeout) // delay 10s < timeout
    if last || !next.Equal(now.Add(10*time.Second)) {
        t.Fatalf("next=%v last=%v", next, last)
    }
    next, last = lifecyclejobs.NextVerifyAt(now, 3, timeout) // delay 60s > remaining
    if !last || !next.Equal(timeout) {
        t.Fatalf("expected last attempt at timeout, got next=%v last=%v", next, last)
    }
}
```

- [ ] **Step 2: Run backoff tests — expect FAIL**

Run: `go test ./internal/lifecyclejobs/ -count=1 -run 'VerifyDelay|NextVerifyAt'`

Expected: FAIL (`VerifyDelay` undefined).

- [ ] **Step 3: Implement `backoff.go`**

```go
func VerifyDelay(attempt int) time.Duration {
    delays := []time.Duration{
        10 * time.Second, 30 * time.Second, 60 * time.Second,
        5 * time.Minute, 30 * time.Minute, 60 * time.Minute,
        3 * time.Hour,
    }
    if attempt <= 0 {
        attempt = 1
    }
    if attempt > len(delays) {
        return 6 * time.Hour
    }
    return delays[attempt-1]
}

func NextVerifyAt(now time.Time, attempt int, timeoutAt time.Time) (time.Time, bool) {
    next := now.Add(VerifyDelay(attempt))
    if !next.Before(timeoutAt) {
        return timeoutAt, true
    }
    return next, false
}
```

- [ ] **Step 4: Write failing worker tests**

```go
func TestWorker_MissStaysPendingVerify(t *testing.T) {
    // Job pending_verify, next_verify_at=now, timeout_at=now+24h.
    // Fake scan returns the same predecessor fingerprint.
    // After one tick: status still pending_verify, verify_attempt=1, next_verify_at ≈ now+30s.
    // Outbox must NOT contain renewal.verified or renewal.timed_out.
}

func TestWorker_PredicatePassEmitsVerified(t *testing.T) {
    // Fake scan returns new fingerprint, same CN, later not_after, predecessor absent.
    // Status=verified; outbox has renewal.verified; no renewal.completed.
}

func TestWorker_TimeoutEmitsTimedOut(t *testing.T) {
    // timeout_at in the past (or now), still pending_verify, predicate miss.
    // Status=timed_out; outbox has renewal.timed_out.
}

func TestWorker_AAPFailedIsFailedNotTimedOut(t *testing.T) {
    // M2 AAP terminal failed while pending_verify → status=failed, renewal.failed, not timed_out.
}

func TestConfig_VerifyTimeoutDefault24h(t *testing.T) {
    // Load() with empty env → LifecycleVerifyTimeout == 24*time.Hour, poll == 5*time.Second.
}
```

- [ ] **Step 5: Run worker tests — expect FAIL**

Run: `go test ./internal/lifecyclejobs/ ./internal/config/ -count=1 -run 'Worker_|VerifyTimeout'`

Expected: FAIL (worker still treats AAP success as done, or no timeout path).

- [ ] **Step 6: Implement scheduler**

On worker tick:

1. `UPDATE … SET status='timed_out' WHERE status='pending_verify' AND timeout_at <= now` (after a final probe if `next_verify_at` is due) then `appendEventTx(..., "renewal.timed_out", ...)`.
2. `jobs := ClaimDueVerifyJobs(...)`.
3. For each job: targeted `CreateScan` + `scanrunner.Run` on last observation host/IP + port (M2 stopgap). Evaluate M2 predicate.
4. Pass → `UpdateStatus(verified)` + `renewal.verified`.
5. Miss → `ScheduleNextVerify(id, attempt+1, next)` staying `pending_verify`.
6. Continue M2 `WaitForJob` for jobs with `aap_job_id` set; AAP failed → `failed` + `renewal.failed`.

Add config fields:

```go
LifecycleVerifyTimeout time.Duration `envconfig:"LIFECYCLE_VERIFY_TIMEOUT" default:"24h"`
LifecycleVerifyPoll    time.Duration `envconfig:"LIFECYCLE_VERIFY_POLL_INTERVAL" default:"5s"`
```

- [ ] **Step 7: Run tests — expect PASS**

Run: `go test ./internal/lifecyclejobs/ ./internal/config/ -count=1`

Expected: PASS

- [ ] **Step 8: Commit**

```bash
git add internal/lifecyclejobs/backoff.go internal/lifecyclejobs/backoff_test.go internal/lifecyclejobs/worker.go internal/lifecyclejobs/worker_verify_test.go internal/config/config.go internal/config/config_test.go
git commit -m "$(cat <<'EOF'
Schedule wire verify with backoff and a 24h timeout.

AAP success is not verified; CLM rescans the target host until the successor fingerprint appears or the job times out.
EOF
)"
```

---

### Task 3: Dual kickoff + events

**Files:**
- Modify: `internal/api/server.go` — routes + handlers
- Create: `internal/api/handlers_migrate_test.go`
- Modify: `internal/api/handlers_resources_test.go` — allowlist new routes
- Modify: `cmd/clm-discovery/main.go` only if worker config plumbing is missing

**Interfaces:**
- Consumes: `store.InsertJob` (M2, now with kind/timeout/next_verify_at), `launchRenewal`, `appendEventTx`, `ClaimByIdempotency`
- Produces:

```go
func (s *Server) handleMigrateCertificate(w http.ResponseWriter, r *http.Request)
func (s *Server) handleMigrateEligible(w http.ResponseWriter, r *http.Request)
func (s *Server) handleClaimLifecycleJob(w http.ResponseWriter, r *http.Request)
```

Routes (under `/api/v1`):

```go
r.Post("/certificates/{id}/migrate", s.handleMigrateCertificate)
r.Post("/migrate-eligible", s.handleMigrateEligible)
r.Post("/lifecycle-jobs/claim", s.handleClaimLifecycleJob)
```

- [ ] **Step 1: Write failing API tests**

```go
func TestMigrate_RejectsCA(t *testing.T) {
    // is_ca cert → 409, body mentions Import CA / Mode B. Fake renewer must not be called.
}

func TestMigrate_RejectsManagedInVault(t *testing.T) {
    // managed_status=managed_in_vault → 409 pointing at /renew.
}

func TestMigrate_ConsentRequired(t *testing.T) {
    // consent false/missing → 400.
}

func TestMigrate_NoAAP_503(t *testing.T) {
    // renewer nil → 503.
}

func TestMigrate_AcceptedPersistsJobAndEvents(t *testing.T) {
    // Eligible leaf + consent + fake Renew returns job 42.
    // 202 JSON has status=pending_verify and lifecycle_job_id.
    // Store has row with aap_job_id=42, job_kind=migrate, timeout_at ≈ now+24h.
    // Outbox contains renewal.requested then renewal.launched.
    // Handler must not call WaitForJob.
}

func TestMigrate_IdempotentOpenJob(t *testing.T) {
    // Second POST while pending_verify → 409 or 202 with the SAME lifecycle_job_id; Renew called once.
}

func TestMigrateEligible_DoesNotLaunchAAP(t *testing.T) {
    // Two eligible leaves; fake Renew must not be called.
    // 202 enqueued=2; each job pending_verify, aap_job_id NULL; outbox renewal.requested only.
}

func TestClaim_SetsAAPJobAndLaunched(t *testing.T) {
    // Job without aap_job_id; POST claim {idempotency_key, aap_job_id:99} → 200; launched event.
    // Repeat same id → 200; different id → 409.
}

func TestMigrate_NoPEMFieldAndNoVaultIssue(t *testing.T) {
    // Decode body into struct that includes optional PEM; leftover unknown field is ignored.
    // Assert fake vault client Issue/ImportLeaf call count is 0 (no such client method wired).
}
```

- [ ] **Step 2: Run API tests — expect FAIL**

Run: `go test ./internal/api/ -count=1 -run 'Migrate_|Claim_'`

Expected: FAIL (404 / unknown handler).

- [ ] **Step 3: Implement handlers**

`handleMigrateCertificate`:

1. Parse id + body (same fields as `handleRenewCertificate`; **no PEM**).
2. Load cert. 409 if `IsCA` or `ManagedStatus == "managed_in_vault"`. 400 if no CN / no observation target / no consent. 503 if `s.renewer == nil`.
3. `SetRenewalConfig` (M2). Insert job `kind=migrate`, `status=pending_verify`, `timeout_at=now+cfg.LifecycleVerifyTimeout`, `next_verify_at=now+10s`, expected JSON = predecessor CN + fingerprint + not_after.
4. `appendEventTx(..., "renewal.requested", ...)`.
5. `launchRenewal` → `SetAAPRef` → `appendEventTx(..., "renewal.launched", ...)`.
6. 202. Never `WaitForJob`.

`handleMigrateEligible`: list eligible leaves (not CA, not managed_in_vault, has CN + observation, no open migrate job). Insert jobs + `renewal.requested` only. 202. 503 if both AAP and EDA webhook are unset.

`handleClaimLifecycleJob`: `ClaimByIdempotency`; emit `renewal.launched` only on first set.

Eligibility helper (pure, testable):

```go
func migrateEligible(c store.Certificate, hasObservation bool, openMigrate bool) error
```

- [ ] **Step 4: Run API tests — expect PASS**

Run: `go test ./internal/api/ -count=1 -run 'Migrate_|Claim_'`

Expected: PASS

- [ ] **Step 5: Update Choose**

Modify `internal/lifecycle/choose.go`: unmanaged or imported **leaf** with a complete/self_signed chain recommends migrate:

```go
case !in.IsCA && (in.ManagedStatus == "unmanaged" || in.ManagedStatus == "imported") &&
    in.ChainStatus != "incomplete" && in.ChainStatus != "untrusted_root":
    return ChooseResult{
        Code:      "migrate_vault",
        Title:     "Migrate to Vault",
        Rationale: "This leaf is not Vault-issued. Vault will issue a new certificate via AAP; CLM cannot upload the scanned PEM (no private key). Status stays Pending until the new fingerprint is on the wire.",
        CTA:       "Migrate to Vault",
    }
```

Keep CA → Import CA; incomplete chain → fix chain; `managed_in_vault` → already_managed.

Update `internal/lifecycle/choose_test.go`: `"internal leaf"` and `"imported"` expect `migrate_vault`; `"external leaf"` also `migrate_vault` (external unmanaged leaf can still migrate if the operator has a PKI role).

- [ ] **Step 6: Run choose + full API tests**

Run: `go test ./internal/lifecycle/ ./internal/api/ -count=1`

Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add internal/api/server.go internal/api/handlers_migrate_test.go internal/api/handlers_resources_test.go internal/lifecycle/choose.go internal/lifecycle/choose_test.go
git commit -m "$(cat <<'EOF'
Add Migrate to Vault kickoff and EDA job claim.

On-demand launches AAP; policy/batch only emits renewal.requested so EDA can launch without CLM double-firing.
EOF
)"
```

---

### Task 4: UI — Migrate to Vault + Pending backoff

**Files:**
- Create: `web/components/migrate-to-vault-button.tsx`
- Create: `web/components/migrate-to-vault-button.test.tsx`
- Create: `web/components/lifecycle-job-pending.tsx`
- Create: `web/components/lifecycle-job-pending.test.tsx`
- Modify: `web/lib/api.ts`
- Modify: `web/app/certificates/[id]/page.tsx`
- Modify: `web/components/report-explorer.tsx` (inline action next to Track in CLM)

**Interfaces:**
- Consumes: `POST /api/v1/certificates/{id}/migrate`, `GET /api/v1/lifecycle-jobs/{id}` (M2 + new fields)
- Produces: button label **Migrate to Vault**; Pending panel with next check / attempt / timeout

```ts
export type LifecycleJob = {
  id: string;
  job_kind: "migrate" | "renew";
  status: string;
  user_status: "Pending" | "Verified" | "Timed out" | "Failed";
  aap_job_id?: number | null;
  next_verify_at?: string | null;
  timeout_at: string;
  verify_attempt: number;
};

export function migrateToVault(id: string, body: {
  consent: true;
  mount: string;
  role: string;
  service?: string;
  target_hosts?: string;
  ttl?: string;
  alt_names?: string;
}) {
  return fetchJSON<{ status: string; lifecycle_job_id: string; timeout_at: string; next_verify_at?: string }>(
    `/api/v1/certificates/${id}/migrate`,
    { method: "POST", body: JSON.stringify(body) },
  );
}

export function getLifecycleJob(id: string) {
  return fetchJSON<LifecycleJob>(`/api/v1/lifecycle-jobs/${id}`);
}
```

- [ ] **Step 1: Write failing UI tests**

`migrate-to-vault-button.test.tsx`: render for an unmanaged leaf → visible text **Migrate to Vault**; must **not** include `Upload`. Hidden when `managed_status === "managed_in_vault"` or `is_ca`. After click, consent modal body includes “new certificate” and “no private key”.

`lifecycle-job-pending.test.tsx`: job `{ user_status: "Pending", verify_attempt: 3, next_verify_at, timeout_at }` → badge **Pending**, text includes `Attempt 3` and a next-check / times-out phrase.

Follow existing `web/components/reconcile-button.test.tsx` patterns (React Testing Library).

- [ ] **Step 2: Run UI tests — expect FAIL**

Run: `cd web && npx vitest run components/migrate-to-vault-button.test.tsx components/lifecycle-job-pending.test.tsx`

Expected: FAIL (files missing).

- [ ] **Step 3: Implement components**

Consent modal copy (verbatim intent from spec): Vault will **issue a new certificate**; CLM **cannot upload** the scanned certificate — no private key; old leaf is **replaced**; status stays **Pending** until the new fingerprint is on the wire or the job times out (default 24 hours).

Wire `MigrateToVaultButton` + `LifecycleJobPending` onto cert detail (and report explorer for eligible rows). Poll `getLifecycleJob` every 10s while `user_status === "Pending"`.

- [ ] **Step 4: Run UI tests — expect PASS**

Run: `cd web && npx vitest run components/migrate-to-vault-button.test.tsx components/lifecycle-job-pending.test.tsx`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add web/components/migrate-to-vault-button.tsx web/components/migrate-to-vault-button.test.tsx web/components/lifecycle-job-pending.tsx web/components/lifecycle-job-pending.test.tsx web/lib/api.ts web/app/certificates/\[id\]/page.tsx web/components/report-explorer.tsx
git commit -m "$(cat <<'EOF'
Show Migrate to Vault and Pending backoff on certificate detail.

Operators need copy that this replaces the leaf via AAP, plus next-check/timeout so Pending is not a black box.
EOF
)"
```

---

### Task 5: Docs + verification

**Files:**
- Modify: `README.md` — API table + env vars + authorized scanning / Mode C note
- Modify: `docs/architecture.md` — migrate + CLM-owned verify loop; EDA does not rescan
- Modify: `docs/data-model.md` — `lifecycle_jobs` delta columns + statuses
- Modify: `docs/adr/0001-source-of-truth-and-event-driven-automation.md` — catalogue: add `renewal.requested`, `renewal.verified`, `renewal.timed_out`; note `renewal.completed` is not emitted for migrate
- Modify: `docs/superpowers/specs/2026-07-06-vault-import-workflow-design.md` — Mode C is no longer “docs only”; link this spec

- [ ] **Step 1: Update docs to match the spec** (no Upload copy; 24h default; dual kickoff; event names).

- [ ] **Step 2: Run verification**

```bash
go test ./...
go build ./...
cd web && npm test && npm run build
```

Expected: all PASS / build OK.

- [ ] **Step 3: Commit**

```bash
git add README.md docs/architecture.md docs/data-model.md docs/adr/0001-source-of-truth-and-event-driven-automation.md docs/superpowers/specs/2026-07-06-vault-import-workflow-design.md
git commit -m "$(cat <<'EOF'
Document Mode C migrate, Pending verify, and renewal event names.

Operators and M5 must not treat leaf upload or renewal.completed as the closed loop.
EOF
)"
```

---

## Spec coverage (self-review)

| Spec requirement | Task |
|------------------|------|
| Reject PEM / `pki/issue` upload | 3 (tests + no endpoint) |
| Mode C migrate = new Vault cert via AAP | 3 |
| Dual kickoff on-demand + policy/EDA claim | 3 |
| CLM-owned verify loop, EDA does not rescan | 2 |
| `pending_verify` + user-facing Pending | 1, 4 |
| Backoff 10s…6h | 2 |
| Timeout default 24h configurable | 2 |
| M2 success predicate | 2 (reuse, do not fork) |
| Events requested/launched/verified/timed_out | 2, 3, 5 |
| UI Migrate to Vault + Pending display | 4 |
| Extends M2 table only | 1 |
| `go test ./...` | 5 |

No placeholders. No SSH/k8s/NATS work.
