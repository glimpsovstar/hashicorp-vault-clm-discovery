# ADCS + Azure Key Vault Collectors — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Discover-only ingest from Microsoft ADCS (via AAP job `CLM - Collect ADCS`) then Azure Key Vault public certificates into the existing fingerprint inventory and environment report.

**Architecture:** Collectors parse public PEM/DER with `cert.ParseCertificate` and call `store.UpsertCertificate`. ADCS collection runs on AAP (Windows plane); CLM never speaks WinRM/SSH. AKV uses Azure SDK or REST for list + public cert get. Same `scans` row + report as network scans; `source` is `adcs` or `akv`.

**Tech Stack:** Go, existing `internal/aap`, `internal/cert`, `internal/store`; httptest + PEM fixtures for unit tests; optional `azcertificates`/`azidentity` behind an interface.

## Global Constraints

- Spec: `docs/superpowers/specs/2026-08-13-adcs-akv-collectors-design.md`
- **Do not start before M1** (collect APIs are privileged).
- Discovery only — no Mode C, no Vault import, no private keys.
- No WinRM/SSH/`certutil` in the Go binary. No Vault plugin. No NATS.
- Do not implement ACM or GCP in this plan.
- Unit tests: local PEM fixtures + httptest; **no live Azure or ADCS**.
- `go test ./...` and `go build ./...` before PR. Docs: README, `docs/data-model.md`, `docs/architecture.md`.

## File structure

- `internal/store/store.go` — `CreateScan` accepts `source` (`network` default; `adcs` / `akv`)
- `internal/collectors/` — shared ingest (`InventoryJSON` → parse PEM → upsert; reject private keys)
- `internal/collectors/adcs/` — AAP launch + stdout ingest
- `internal/collectors/akv/` — list + get public cert (HTTP client interface)
- `internal/aap/client.go` — `JobStdout` (or artifact fetch)
- `internal/api` — consent-gated collect endpoints (M1 RBAC)
- `internal/config/config.go` — `AAP_ADCS_TEMPLATE`, `AZURE_KEY_VAULT_URI`, Azure SP env
- `testdata/collectors/` — leaf PEM, CA PEM, private-key PEM (reject)
- docs: README env table, data-model `scan_source`, architecture collectors note
- AAP playbook is **not** in this repo unless a `deploy/aap/` example is added as docs-only JSON contract

---

### Task 1: Scan source + ingest helper (TDD)

**Files:**
- Modify: `internal/store/store.go` (`CreateScan`)
- Create: `internal/collectors/ingest.go`, `internal/collectors/ingest_test.go`
- Create: `testdata/collectors/leaf.pem`, `testdata/collectors/with-key.pem`

**Interfaces:**
- Produces: `CreateScan(ctx, source string, …)` with `source` in `adcs` \| `akv` \| `network`
- Produces: `IngestPublicPEMs(ctx, scanID, items []Item) (ingested int, skipped int, err error)` calling `UpsertCertificate`

- [ ] Extend `CreateScan` to set `scans.source`; default remains `network` for existing `POST /scans`.
- [ ] Write failing tests: ingest leaf PEM → fingerprint matches `cert.ParseCertificate`; second ingest same PEM → same cert id, new observation; PEM with `BEGIN PRIVATE KEY` → skip/error, no upsert; PFX-like binary rejected.
- [ ] Fixture generation: reuse `internal/cert/parse_test.go` self-signed helper or committed PEM under `testdata/collectors/` (public cert only in `leaf.pem`).
- [ ] Implement ingest: decode PEM blocks of type `CERTIFICATE` only; build sentinel `cert.Observation` (`ip`=`adcs`|`akv`, `port`=0, `sni` prefixed).
- [ ] Run: `go test ./internal/collectors/ ./internal/store/ -count=1`
- [ ] Commit when implementing (not in this docs PR).

Example ingest reject test:

```go
func TestIngestRejectsPrivateKey(t *testing.T) {
    raw, err := os.ReadFile("testdata/collectors/with-key.pem")
    if err != nil {
        t.Fatal(err)
    }
    _, _, err = IngestPublicPEMs(context.Background(), scanID, []Item{{PEM: string(raw)}})
    if err == nil {
        t.Fatal("expected reject")
    }
}
```

### Task 2: AAP stdout + ADCS collect

**Files:**
- Modify: `internal/aap/client.go`, `internal/aap/client_test.go`
- Create: `internal/collectors/adcs/collect.go`, `internal/collectors/adcs/collect_test.go`
- Modify: `internal/config/config.go` — `AAP_ADCS_TEMPLATE` default `CLM - Collect ADCS`

**Interfaces:**
- Consumes: `aap.Client.FindJobTemplate`, `LaunchJobTemplate`, `WaitForJob`
- Produces: `JobStdout(ctx, jobID int) ([]byte, error)`; `adcs.Collect(ctx, scanID, caHost string) error`

- [ ] Add `JobStdout` (Controller `/api/v2/jobs/{id}/stdout/?format=json` or plain); httptest existing AAP fixtures; still cap body (4 MiB).
- [ ] extra_vars: `ca_host`, `clm_scan_id` only — assert payload has no token/password keys.
- [ ] Parse inventory JSON `{ "certificates": [ { "pem": "..." } ] }`; feed Task 1 ingest; `scans.source=adcs`.
- [ ] Tests: httptest Controller launch + successful job + stdout JSON with `testdata/collectors/leaf.pem`; missing AAP → error the API will map to 503; private-key in JSON → not stored.
- [ ] Run: `go test ./internal/aap/ ./internal/collectors/adcs/ -count=1`

### Task 3: ADCS API (after M1)

**Files:**
- Modify: `internal/api/server.go` (+ tests)
- Modify: README — job template name, env, authorized scanning note

- [ ] `POST /api/v1/scans/adcs` (or equivalent) with `{ "consent": true, "ca_host": "…" }`.
- [ ] Persist scan `source=adcs` **before** AAP launch (same persist-before-202 idea as M2 if the job is long).
- [ ] 400 without consent; 401/403 per M1; 503 if AAP unconfigured and fallback off.
- [ ] No new WinRM package; `go list` / grep guard in test optional: fail if `github.com/masterzen/winrm` (or similar) appears.
- [ ] Run: `go test ./internal/api/ -count=1`

### Task 4: AKV collector (TDD, no live Azure)

**Files:**
- Create: `internal/collectors/akv/client.go`, `collect.go`, `collect_test.go`
- Modify: `internal/config/config.go` — `AZURE_KEY_VAULT_URI` (and SP env documented, not logged)

**Interfaces:**
- Produces: `VaultCerts` interface `{ List(ctx) ([]string, error); GetPublicPEM(ctx, name string) (string, error) }`
- Produces: `akv.Collect(ctx, scanID) error` → ingest with `ip=akv`

- [ ] Write failing httptest: list names + get `cer`/PEM from fixture DER/PEM; Get that would return a key blob is never called (interface has no `GetKey`).
- [ ] Implement list + public get (Azure REST `api-version` or SDK behind the interface).
- [ ] Skip entries with empty public cert; continue on per-name 403; do not retry with export.
- [ ] `POST /api/v1/scans/akv` + consent; `source=akv`; 503 if URI unset.
- [ ] Run: `go test ./internal/collectors/akv/ ./internal/api/ -count=1`

Example httptest assertion:

```go
func TestCollectAKVUpsertsFingerprint(t *testing.T) {
    pem := mustRead(t, "testdata/collectors/leaf.pem")
    parsed := parsePEM(t, pem)
    // fakeVault returns pem for "app-cert"
    // Collect → store fake → fingerprint == parsed.FingerprintSHA256
}
```

### Task 5: Report + docs + verify

- [ ] `BuildForScan` on an `adcs`/`akv` scan with one upserted fixture cert returns existing report (no new report type). Table test in `internal/report` if scan source is displayed; otherwise confirm `GetScan` JSON includes `source`.
- [ ] README: env vars, AAP template `CLM - Collect ADCS`, ADCS first then AKV, no keys, no live-cloud required for unit tests.
- [ ] `docs/data-model.md`: `scan_source` values `network` (default), `adcs`, `akv`.
- [ ] `docs/architecture.md`: collectors + AAP as Windows collection plane; ACM/GCP not in this slice.
- [ ] `go test ./...` && `go build ./...`

---

## Spec coverage (self-check)

| Spec section | Task |
|--------------|------|
| ADCS AAP `CLM - Collect ADCS` | 2–3 |
| ADCS fallback documented, no WinRM in binary | 3 + docs |
| AKV public list/get | 4 |
| Upsert by fingerprint; `adcs`/`akv` | 1, 2, 4 |
| Existing report | 5 |
| No private keys | 1, 2, 4 |
| M1 before privileged APIs | Global + Task 3 |
| ACM/GCP / Mode C / plugin / NATS | Out of scope — no task |
