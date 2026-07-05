# Design: v1.1b Revocation alignment (Vault PKI → CLM `status=revoked`)

- **Issue:** #32 (follows #23 reconcile; v1.1 plan Task 6 "v1.1b slice")
- **Status:** Design gate — awaiting approval before implementation
- **Scope:** Read-only. Vault-managed certs only. No OCSP/CRL network calls.

## Problem

The Phase 1 reconcile matches deployed certs to Vault PKI serials and sets
`managed_status='managed_in_vault'`, but it ignores whether Vault has **revoked**
that serial. A revoked cert still shows a lifecycle status of `valid` /
`expiring_soon` / `expired` in the CLM inventory, so operators cannot see
"deployed but revoked" drift — a real security signal (a revoked cert still
served on the wire).

## Goal

During reconcile, mark any CLM cert whose matched Vault serial is revoked as
`status='revoked'`, and record when revocation was last checked.

## Non-goals (later)

- OCSP responder / CRL fetch for **non-Vault (shadow)** certs.
- Revocation *actions* (revoke / renew) — Phase 2 operate loop.
- Un-revoking / status resurrection beyond what a fresh reconcile computes.

## Key insight — no new I/O, no migration

- `Client.ReadCert` already returns the full Vault response `meta` map for each
  serial ([internal/vault/pki.go](../../../internal/vault/pki.go)). Vault's
  `pki/cert/{serial}` response includes `revocation_time` (unix seconds, `0`
  when not revoked) and `revocation_time_rfc3339`. **No extra Vault request.**
- The `certificates` table already has `status cert_status` (enum includes
  `revoked`), `revocation_status TEXT`, and `revocation_checked_at TIMESTAMPTZ`
  ([migrations/000001_init.up.sql](../../../migrations/000001_init.up.sql)).
  **No migration.**

## Design

### 1. Extract revocation from meta (`internal/vault`)

Add a pure helper:

```go
// revocationFromMeta reports whether Vault marks the serial revoked.
// Vault encodes revocation_time as unix seconds (JSON number => float64), 0 = not revoked.
func revocationFromMeta(meta map[string]interface{}) bool
```

Handle the JSON-number-as-`float64` case (and be tolerant of `json.Number` /
string). `revocation_time > 0` ⇒ revoked.

### 2. Carry it on the store update (`internal/store/certificates.go`)

Extend `ManagedStatusUpdate` with revocation intent:

```go
type ManagedStatusUpdate struct {
    ManagedStatus  string
    VaultPKIMount  string
    VaultIssuerRef *string
    Revoked        bool // set status=revoked + revocation_status when true
}
```

`UpdateManagedStatusByFingerprint` always stamps `revocation_checked_at = NOW()`
(we did check), and:

- **revoked:** `status = 'revoked'`, `revocation_status = 'revoked_in_vault'`.
- **not revoked:** leave `status` untouched (preserve the lifecycle
  `valid`/`expiring_soon`/`expired` computed at scan time); set
  `revocation_status = NULL`.

Rationale: reconcile owns the *revoked* signal but must not clobber the
scan-derived lifecycle status when a cert is simply still valid.

### 3. Wire into the reconcile loop (`internal/vault/reconcile.go`)

In the existing per-serial loop, after fingerprinting, compute
`revoked := revocationFromMeta(meta)` and pass `Revoked: revoked` in the
`ManagedStatusUpdate`. Add `Revoked int` to `Summary` for observability.

### 4. Dashboard (`web/`)

`status` already flows through `web/lib/api.ts`; ensure the status badge renders
`revoked` (add the mapping/label if missing). No new endpoint.

### 5. Docs

`docs/data-model.md`: mark `revocation_status` / revocation available in v1.1b
(no longer "OCSP/CRL only"), and note the source is Vault PKI `revocation_time`
via reconcile.

## Behavior matrix

| Vault serial state | Matched CLM cert result |
|---|---|
| `revocation_time == 0` | `status` unchanged; `revocation_status = NULL`; `revocation_checked_at = NOW()` |
| `revocation_time > 0` | `status = revoked`; `revocation_status = revoked_in_vault`; `revocation_checked_at = NOW()` |
| serial not matched in CLM | no-op (as today) |

Idempotent: re-running yields the same result.

## Testing (TDD)

- `internal/vault/reconcile_test.go` — table rows: (a) matched + revoked ⇒
  update carries `Revoked=true`; (b) matched + not revoked ⇒ `Revoked=false`,
  status preserved; assert `Summary.Revoked` count. Uses the existing httptest
  Vault stub + `mockCertStore`.
- `internal/vault/pki_test.go` (or a small unit test) — `revocationFromMeta`
  across `float64`, `json.Number`, string, missing key, `0`.
- No DB test change required (mock store); the SQL change is covered by the
  existing store test pattern if present.

## Verification gate

`go test ./...`, `go build ./...`, `cd web && npm run build`, then PR + sub-agent
review before squash-merge.
