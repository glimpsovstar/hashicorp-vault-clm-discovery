## Problem

Network TLS scan only sees certificates presented on the wire. Issued-but-not-served inventory in **Microsoft ADCS** (on-prem Windows CA / certsrv) and **Azure Key Vault certificates** stays invisible. M5 #83 lists cloud collectors as a later slice but does not specify ADCS-first or the AKV contract.

## Proposed solution

**Do not start before M1** (collect APIs are privileged). Discovery only: ADCS first via AAP job template **`CLM - Collect ADCS`** (Windows collection plane — no WinRM/SSH in CLM), then AKV as the cloud-vendor example (list + public PEM/CER only). Upsert the existing inventory by `fingerprint_sha256`; `scans.source` = `adcs` or `akv`. Feed the existing environment/scan report. Env vars until Connections Settings. ACM/GCP stay on M5. Import/migrate/Mode C is a separate spec.

## Acceptance criteria

- [ ] ADCS collect (AAP path) creates `scans.source=adcs` and upserts by `fingerprint_sha256`; no private key stored.
- [ ] Template resolved by name `CLM - Collect ADCS`; extra_vars contain no secrets; 503 if AAP unset and fallback disabled.
- [ ] Ingest rejects private-key PEM / PFX (unit test with fixture).
- [ ] AKV collect creates `scans.source=akv` from public cert only; httptest/fixtures — no live Azure in unit tests.
- [ ] Same fingerprint from network + ADCS/AKV remains one inventory row.
- [ ] Existing `GET /scans/{id}/report` works for collector scans (no new report product).
- [ ] No WinRM/SSH/`certutil` client in the Go binary.
- [ ] Collect endpoints follow M1 RBAC (401/403); not shipped before M1.

## Test plan

- [ ] PEM fixture ingest: upsert by fingerprint; private-key fixture rejected
- [ ] AAP httptest: find-by-name, extra_vars names only, stdout JSON ingest
- [ ] AKV httptest: list + public get; no key-export API
- [ ] Report builds for an `adcs`/`akv` scan
- [ ] `go test ./...` (no live Azure/ADCS required)

## Superpowers spec

`docs/superpowers/specs/2026-08-13-adcs-akv-collectors-design.md`

Plan: `docs/superpowers/plans/2026-08-13-adcs-akv-collectors.md`

Parent: M5 broader integrations (#83). Import/Mode C: `docs/superpowers/specs/2026-07-06-vault-import-workflow-design.md` — do not implement here.

## Out of scope

ACM/GCP collectors, Mode C / migrate-to-Vault, Connections Settings UI, WinRM/SSH in CLM, private-key dump/export, Vault plugin, NATS, new report product, revoke-via-AAP / ITSM (remain on M5).
