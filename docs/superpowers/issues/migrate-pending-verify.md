## Problem

Scanned ADCS / Azure Key Vault / TLS **leaves** cannot be uploaded into Vault as issuable certs — CLM has no private key, and `pki/issue` does not ingest a foreign leaf PEM. Mode A only catalogs; Mode B is CA-only. Operators still need a closed-loop “get this onto Vault PKI” action. After AAP launches, there is no durable **Pending** state while CLM independently proves the **new** fingerprint is on the wire, and EDA must not own that rescan.

This **extends** M2 ([#80](https://github.com/glimpsovstar/hashicorp-vault-clm-discovery/issues/80)); it does not replace persist-before-202, `WaitForJob`, or the verify predicate. Parent umbrella: [#78](https://github.com/glimpsovstar/hashicorp-vault-clm-discovery/issues/78).

## Proposed solution

**Migrate to Vault** = Mode C: Vault issues a **new** cert (CSR-on-target / AAP); old leaf is replaced, not uploaded. Dual kickoff: (1) UI/API launches AAP via the existing renew client; (2) policy/batch emits `renewal.requested` → EDA webhook → AAP, then CLM claims `aap_job_id`. CLM owns the verify loop (backoff rescans of the target host). User-facing **Pending** (`pending_verify`) until M2 predicate or **timeout** (default 24h). Copy is **Migrate to Vault**, never Upload.

## Acceptance criteria

- [ ] No endpoint accepts a leaf PEM for Vault `pki/issue` / leaf import.
- [ ] Eligible leaf: **Migrate to Vault** → 202 + `lifecycle_job_id`; row exists before ack; badge **Pending**.
- [ ] CA → 409 (Mode B); `managed_in_vault` → 409 (`/renew`).
- [ ] On-demand: existing AAP renew client; `renewal.requested` then `renewal.launched`; no `WaitForJob` on the request.
- [ ] Policy/batch: jobs + `renewal.requested` without calling Controller; claim sets `aap_job_id` + `renewal.launched`.
- [ ] AAP success alone is not `verified`. Predicate: same CN, new `fingerprint_sha256`, later `not_after`, predecessor not served.
- [ ] Backoff 10s, 30s, 60s, 5m, 30m, 60m, 3h, 6h… ; UI shows next check / attempt / timeout.
- [ ] Default timeout 24h (configurable) → `timed_out` + `renewal.timed_out`.
- [ ] Restart resumes `pending_verify` from `next_verify_at` / `aap_job_id`; no double launch.
- [ ] EDA does not rescan. No NATS. No SSH/k8s deployers. No private keys in CLM.

## Test plan

- [ ] Store: `UserStatus`, `ClaimDueVerifyJobs`, claim-by-idempotency
- [ ] Backoff table + timeout cap
- [ ] Worker: miss stays Pending; predicate → `renewal.verified`; clock → `renewal.timed_out`; AAP fail → `failed`
- [ ] API: migrate 202 persist-before-ack; 409 CA/managed; 400 consent; 503 no AAP; eligible batch does not call `Renew`
- [ ] Choose CTA **Migrate to Vault** for unmanaged/imported leaves
- [ ] UI: button label; no “Upload”; Pending + attempt/next-check
- [ ] `go test ./...` and `go build ./...`

## Superpowers spec

`docs/superpowers/specs/2026-08-13-migrate-pending-verify-design.md`

Plan: `docs/superpowers/plans/2026-08-13-migrate-pending-verify.md`

Depends on: M2 [#80](https://github.com/glimpsovstar/hashicorp-vault-clm-discovery/issues/80) (`lifecycle_jobs`). Ship on top of M2; do not re-specify the job table.

Parent: [#80](https://github.com/glimpsovstar/hashicorp-vault-clm-discovery/issues/80), umbrella [#78](https://github.com/glimpsovstar/hashicorp-vault-clm-discovery/issues/78).

## Out of scope

Replacing M2, Mode A/B changes, ADCS/AKV collectors (M5), CLM `pki/issue` or key storage, SSH/k8s deployers, NATS/Kafka, ITSM/revoke/LLM, EDA-owned verify.
