# Design: Vault import workflow (catalog / CA bundle / mirror) — #25

- **Issue:** #25 (parent lifecycle #20 Import phase)
- **Status:** **PR 1 (A+D) and PR 2 (B) implemented.** Mode B is the first Vault write path; Terraform integration validation (local Docker Vault + HCP) is the follow-up.
- **Design source:** `docs/superpowers/specs/2026-06-14-scan-report-and-vault-import-design.md` (Feature 2)
- **Builds on:** reconcile (#23/#32) — read-only Vault client, `managed_status`, `vault_issuer_ref`/`vault_pki_mount`

## Problem

"Import into Vault" is ambiguous. #25 makes the four interpretations explicit and
maps each to a lifecycle phase and `managed_status` semantics.

| ID | Mode | Vault write | Version | Delivery |
|----|------|-------------|---------|----------|
| **A** | Catalog — track in CLM (`managed_status=imported`) | No | v1.2 | **PR 1** |
| **D** | Mirror — wire observation vs Vault row, side-by-side (read-only) | No | v1.2 | **PR 1** |
| **B** | CA/material import — `pki/issuers/import/bundle` | **Yes** | v1.2 | **PR 2** |
| **C** | Reissue + deploy — Vault issue + agent/AAP + rescan | Yes | v1.3+ | Docs only |

## Goals

| ID | Goal | Success criteria |
|----|------|------------------|
| G1 | Catalog import (A) | `POST /certificates/{id}/catalog-import` with consent sets `managed_status=imported`; no Vault call |
| G2 | CA import (B) | `POST /issuers/{id}/import` with consent calls Vault `pki/issuers/import/bundle`, stores `vault_issuer_ref`/`vault_pki_mount`; 409 if not a CA; 503 if Vault unconfigured |
| G3 | Mirror (D) | Cert detail shows wire vs Vault (managed_status, mount, issuer ref) side-by-side, read-only |
| G4 | Disambiguation | Decision-tree doc + UI copy: "Track in CLM" (A) vs "Import CA to Vault" (B) |

## Non-goals (enforced)

CLM issuing certs, bulk reissue/deploy (C is v1.3+ docs), HCP inventory backfill.

## Data model — no migration

- `managed_status` enum already has `imported` (mode A target).
- `issuers` already has `vault_issuer_ref`, `vault_pki_mount`, `pem`, `ca_chain`
  (mode B targets). Certificates carry the reconcile fields for mode D.

## Design

### Mode A — Catalog import (read-only to Vault)

- **Store:** `SetManagedStatus(ctx, certID, status string) (Certificate, error)`
  in `internal/store/certificates.go` — sets `managed_status`, `updated_at`.
  Guard to the `imported`/`unmanaged` transition (not `managed_in_vault`, which
  reconcile owns).
- **API:** `POST /api/v1/certificates/{id}/catalog-import`, body
  `{"consent": true}`. Missing consent → 400. Sets `imported`; returns the cert.
  Structured audit log line (actor unknown in demo; log id + action).
- **UI:** "Track in CLM" button on cert detail; optimistic refresh.

### Mode B — CA import to Vault (Vault write)

- **Vault client:** new `ImportIssuerBundle(ctx, mount, pemBundle string)
  (IssuerImportResult, error)` — `POST /v1/{mount}/issuers/import/bundle` with
  `{"pem_bundle": …}`; parse `imported_issuers`/`mapping`. Reuses namespace/token
  headers. This is the first **write** path; requires a read-write PKI policy
  (documented). Read-only token → Vault 403 surfaced as 502/error.
- **Store:** `SetIssuerVaultRef(ctx, issuerID uuid.UUID, ref, mount string)
  (Issuer, error)`.
- **API:** `POST /api/v1/issuers/{id}/import`, body
  `{"consent": true, "mount": "pki"}`. Flow: load issuer → require `is_ca`
  (else 409) → require Vault configured (else 503) → build bundle from issuer
  `pem` (+ `ca_chain`) → `ImportIssuerBundle` → persist `vault_issuer_ref` +
  `vault_pki_mount` → return issuer. Consent required (400 otherwise).
- **UI:** "Import CA to Vault" button on issuer row/detail with a **consent
  modal** naming the mount and warning it writes to Vault.

### Mode D — Dashboard mirror (read-only)

- No new endpoint. Cert detail page renders a **Wire vs Vault** panel:
  wire (subject, fingerprint, observations) beside Vault
  (`managed_status`, `vault_pki_mount`, `vault_issuer_ref`, last reconcile).
  Uses fields already on the cert. Copy explains reconcile drives it.

### Mode C — deferred

Decision-tree doc links to a vault-agent/AAP reference architecture section; no
code.

## Required Vault policy (mode B)

Mode B needs a **read-write** PKI policy on the configured Vault token; reconcile
(read-only) works with a subset. Example:

```hcl
# mode B (write):
path "pki/issuers/import/bundle" { capabilities = ["create", "update"] }
path "pki/issuer/*"              { capabilities = ["read"] }
# reconcile (read-only):
path "sys/mounts"                { capabilities = ["read"] }
path "pki/certs"                 { capabilities = ["list"] }
path "pki/cert/*"                { capabilities = ["read"] }
```

## Consent & audit

All state-changing endpoints require an explicit `consent: true` body flag
(mirrors the scan consent policy) and emit a structured log line
(`action`, `target_id`, `mount` where relevant). No secrets logged.

## Security

- Mode A/D never call Vault. Mode B is the only write; gated on consent +
  `is_ca` + Vault configured; token scope is the operator's responsibility
  (documented read-write policy). No PEM beyond the issuer's own material is
  sent; response issuer refs only.
- Input validation: cert/issuer id parse; body decode errors → 400.

## Testing (TDD)

- `store`: `SetManagedStatus` transition guard; `SetIssuerVaultRef` (mock/pure
  where possible; DB paths noted).
- `vault`: `ImportIssuerBundle` against httptest Vault stub — success mapping +
  403/500 error paths.
- `api`: catalog-import (consent required 400, success sets imported),
  issuer import (503 unconfigured, 409 non-CA, consent 400, success persists
  ref via a fake vault importer + fake store).
- UI: build passes; button/modal wiring.

## Verification gate

`go build/vet/test ./...`, `cd web && npm run build`, PR + sub-agent review
before squash-merge.

## Open scoping question (for approval)

**Resolved:** split delivery. **PR 1** ships A (catalog) + D (mirror) — both
read-only to Vault, low risk. **PR 2** ships B (CA import) — the first Vault
write path — with its own read-write PKI policy docs and consent modal.
