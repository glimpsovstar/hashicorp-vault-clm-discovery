# ADCS + Azure Key Vault collectors — design

**Status:** Approved for implementation (#86)  
**Date:** 2026-08-13 (updated 2026-08-15)  
**Parent:** [M5 broader integrations](2026-08-13-m5-broader-integrations-design.md) ([#83](https://github.com/glimpsovstar/hashicorp-vault-clm-discovery/issues/83))  
**Plan:** [2026-08-13-adcs-akv-collectors.md](../plans/2026-08-13-adcs-akv-collectors.md)  
**Issue:** [#86](https://github.com/glimpsovstar/hashicorp-vault-clm-discovery/issues/86)  
**Depends on:** M1 for RBAC on collect endpoints; Connections Settings (env vars until that spec exists)

### Alignment with #99 `cloud_*`

M5 remainder (#99) shipped shared ingest + `POST /scans/collect` with sources `cloud_akv` | `cloud_acm` | `cloud_gcp`. This slice **reuses** that pipeline:

| Source | `scans.source` | How collected |
|--------|----------------|---------------|
| ADCS (AAP) | `adcs` | New AAP job path (this issue) |
| Azure Key Vault | `cloud_akv` | Live list+get via `internal/collectors/cloud` + AKV REST (not a second `akv` token) |

Do **not** invent bare `akv` as a scan source.

---

## Problem

Network TLS scan (`internal/scanner`, `scan_source=network`) only sees certificates **presented on the wire**. Enterprise estates also hold issued-but-not-served inventory:

1. **Microsoft ADCS** (on-prem Windows CA / certsrv) — issued request database, templates, requester — often the largest unmanaged CA.
2. **Azure Key Vault certificates** — cloud-vendor store of public certs (and, in Azure, key material CLM must never take).

M5 #83 lists read-only ACM / AKV / GCP collectors as a later slice with `scan_source=cloud_*`. That is the parent milestone; it does not specify the first two sources or the ADCS (non-cloud) path. Without collectors, ADCS-issued and AKV-held certs stay invisible until they appear on a probed endpoint.

## Goal

Add **discovery-only** collectors for **ADCS first**, then **AKV** as the cloud-vendor example. Both upsert the **same** `certificates` inventory by `fingerprint_sha256`. ADCS sets `scans.source=adcs`; AKV reuses M5 `cloud_akv` (see Alignment with #99). Feed the **existing** environment/scan report. No new report product. No import/migrate/Mode C in this spec.

## Locked decisions

- **Order:** Microsoft ADCS (on-prem Windows CA / certsrv) first; Azure Key Vault certificates second. ACM and GCP Certificate Manager are **not** designed or implemented here — they remain M5 follow-ons using the AKV pattern.
- **Inventory:** reuse `store.UpsertCertificate` / `UpsertIssuer`; dedup key remains `fingerprint_sha256`. Scan sources: `adcs` (new) and `cloud_akv` (existing from #99). Do not add bare `akv`.
- **Report:** `GET /scans/{id}/report` (`internal/report.BuildForScan`) unchanged as a product; collector scans are just another completed scan.
- **Discovery only.** Catalog track / CA import / reissue-and-deploy are [Vault import workflow](2026-07-06-vault-import-workflow-design.md) and [Mode C](2026-07-06-mode-c-renewal-kit-design.md). Cutover is [migrate + pending verify](2026-08-13-migrate-pending-verify-design.md) — do not design Mode C here.
- **No private keys in CLM.** Collectors are read-only. No `certutil` PFX/key dump. No AKV key export / `azkeys` / policy that returns key material. Store public cert PEM only (same as network scan).
- **ADCS access plane:** prefer **AAP** as the Windows actuation/collection plane. Do **not** put WinRM, SSH, or `certutil` in the Go binary.
- **Credentials:** AAP/Azure secrets live in Connections Settings later; **env vars first** (same pattern as `AAP_TOKEN` / `VAULT_TOKEN`). Collectors must not block on the Settings spec.
- **No Vault plugin. No NATS.**
- **Do not start before M1** if collect endpoints are privileged mutations (they are: they create scans and write inventory).

## ADCS collector

### Recommended: AAP job template `CLM - Collect ADCS`

A dedicated collector identity already exists on the Windows side (LDAP bind, CA database read, or certsvc query). CLM does not speak those protocols.

1. Operator (role `scanner_operator` after M1) consents to `POST` collect-ADCS.
2. CLM uses existing `internal/aap`: find-by-name template **`CLM - Collect ADCS`**, launch with extra_vars that contain **no secrets** (CA hostname / config name only; AAP credentials store holds the Windows identity).
3. The job queries the CA issued-certificate store (or equivalent) and prints **public cert inventory JSON** on stdout (or a Controller artifact CLM then fetches).
4. CLM waits with existing `WaitForJob`, reads stdout/artifact, **rejects any object with private-key PEM**, parses each public PEM via `cert.ParseCertificate`, upserts.

**extra_vars (names only, no secrets):**

| Key | Meaning |
|-----|---------|
| `ca_host` | CA hostname / config name known to the playbook |
| `clm_scan_id` | UUID of the `scans` row already persisted |
| `issued_since` (optional) | ISO date for incremental collect |

Playbook contract (AAP-owned, not a CLM deployer): dump **public** metadata + PEM. Never `certutil -exportpfx`, never private-key files in the JSON.

**Stdout / artifact JSON (minimum):**

```json
{
  "ca_host": "ca01.corp.example",
  "certificates": [
    {
      "pem": "-----BEGIN CERTIFICATE-----\n…\n-----END CERTIFICATE-----",
      "request_id": "12345",
      "template": "WebServer",
      "requester": "CORP\\svc-web"
    }
  ]
}
```

`pem` is required for upsert. `request_id` / `template` / `requester` may be copied to observation hostname/SNI or tags later; they are not a second identity key.

If inventory exceeds the AAP client `maxBody` (4 MiB), the job paginates (`issued_since` / `after_request_id`); CLM launches follow-up jobs or passes a page cursor in extra_vars. Do not raise the body cap as the primary design.

CLM must add a small AAP helper (e.g. `JobStdout`) — the client today launches and polls status only.

### Fallback (optional): read-only listing without WinRM

If AAP is unset, an optional **read-only** path may list public certs via LDAP (published certificates in AD) or CA web enrollment **listing** of issued certs — HTTP GET of public CER/PEM only.

- Still no SSH/WinRM/certutil in CLM.
- 503 if neither AAP nor the documented fallback is configured.
- Fallback is best-effort and may see a subset of the CA database; AAP remains the supported enterprise path.

### Observation mapping (no TLS probe)

`certificate_observations.ip` / `port` are NOT NULL. Use sentinels, not invented wire state:

| Field | ADCS value |
|-------|------------|
| `ip` | `adcs` (literal) |
| `port` | `0` |
| `hostname` | subject CN (or first SAN) |
| `sni` | `adcs:<ca_host>` |
| `tls_version` / `cipher_suite` | empty |

`hostname_matches_san` uses CN as hostname so the flag is not a false SAN mismatch from a missing probe.

## AKV collector

Read-only Azure Key Vault **Certificates** API (SDK or REST). Pattern for later ACM/GCP — those vendors are out of scope here.

1. List certificate names in the configured vault.
2. Get each certificate’s **public** material (`cer` / PEM). Skip versions that have no public cert yet.
3. Parse with `cert.ParseCertificate`; upsert; `scans.source = akv`.
4. Never call key-export APIs, never persist `-----BEGIN … PRIVATE KEY-----`, never download PKCS#12 with key.

**Auth (env first):** `AZURE_KEY_VAULT_URI` (or name + `https://{name}.vault.azure.net/`) plus DefaultAzureCredential / `AZURE_TENANT_ID` + `AZURE_CLIENT_ID` + `AZURE_CLIENT_SECRET`. Tokens never logged.

If Key Vault policy denies public-cert get, record a scan failure sample and continue other names; do not retry with key-export permissions.

| Field | AKV value |
|-------|-----------|
| `ip` | `akv` |
| `port` | `0` |
| `hostname` | Key Vault certificate name (or CN) |
| `sni` | `akv:<vault-name>` |

## Inventory mapping

Same tables as network scan. `CreateScan` today defaults `scans.source` to `network`; collectors must persist `source` explicitly (`adcs` | `akv`).

| Source field | `store.Certificate` / parse |
|--------------|------------------------------|
| Public PEM / DER | `cert.ParseCertificate` → `pem`, `fingerprint_sha256`, serial, subject, SAN, issuer, dates, key type/bits, usages, AIA |
| First seen / last seen | `UpsertCertificate` `ON CONFLICT (fingerprint_sha256)` |
| `managed_status` | leave default `unmanaged` (reconcile still owns `managed_in_vault`) |
| `cert_scope` | existing `governance.ClassifyScope` |
| Issuers | `UpsertIssuer` when a CA PEM is present in the dump/chain |
| Wire fields | sentinels above; do not fake TLS version |

A cert already found on the network **and** in ADCS/AKV is **one row** (same fingerprint). New observation rows record the additional source via the collect `scan_id` + sentinel ip/sni.

Do not add a second unique key (AKV name, ADCS request id). Those are metadata only.

## Report

Completed collector scans use the existing environment report ([environment scan report](2026-07-06-environment-scan-report-design.md), `BuildForScan`). Insights (expiry, chain, shadow, weak key) run on the same `store.Certificate` fields.

- No new report type, PDF, or vendor-specific section required in this spec.
- Header already exposes `scan.source`; document `adcs` / `akv` in README / data-model when implementing.
- Markdown/CSV still must not include PEM (existing rule).

## Security

- Collect APIs are privileged (`scanner_operator` + consent after M1). Unauthenticated collect → 401; `viewer` → 403. **Do not ship collect routes before M1 auth.**
- AAP extra_vars: names only; Windows bind/CA rights stay in AAP credentials.
- AKV: least-privilege **get/list certificates** (public). No `key` get, no `secrets` get for key-backup blobs.
- Reject ingest payloads containing `BEGIN PRIVATE KEY`, `BEGIN RSA PRIVATE KEY`, `BEGIN EC PRIVATE KEY`, or PFX/PKCS#12.
- Never log tokens, PEM bodies, or AAP/Azure secrets (same as renew).
- Audit collect launch (M1 `audit_events`) like `POST /scans`.
- CLM remains not a Vault plugin and not a WinRM/SSH client.

## Acceptance criteria

- [ ] ADCS collect (AAP path) creates `scans.source=adcs`, upserts by `fingerprint_sha256`, no private key stored.
- [ ] AAP template resolved **by name** `CLM - Collect ADCS`; extra_vars contain no secrets; 503 if AAP unset and fallback disabled.
- [ ] Ingest rejects private-key PEM / PFX; unit test with a fixture that must not be persisted.
- [ ] AKV collect creates `scans.source=akv`, upserts by fingerprint from public `cer`/PEM only; httptest/fixture — no live Azure in unit tests.
- [ ] Same cert from network + ADCS/AKV remains one inventory row; two observations.
- [ ] `GET /scans/{id}/report` works for collector scans (existing report).
- [ ] No WinRM/SSH client package in CLM; no `certutil` invocation from Go.
- [ ] Collect endpoints 401/403 per M1; not implemented before M1.

## Out of scope

- ACM, GCP Certificate Manager, or other cloud CAs (M5 #83 later; copy AKV pattern).
- Import / migrate / Mode C (reissue + deploy) from ADCS or AKV into Vault — [import workflow](2026-07-06-vault-import-workflow-design.md), [Mode C](2026-07-06-mode-c-renewal-kit-design.md); **new migrate spec** when that work starts.
- Connections Settings UI (env vars until that spec).
- Putting WinRM, SSH, or CA write/revoke in the Go binary.
- Dumping or storing private keys; AKV key export; `certutil` key dump.
- Vault secrets-engine plugin; NATS/Kafka.
- New report product; ITSM; revoke-via-AAP (those stay on M5 proper).

## Relationship to M5 #83 and migrate spec

| Doc | Role |
|-----|------|
| [M5 design](2026-08-13-m5-broader-integrations-design.md) / [#83](https://github.com/glimpsovstar/hashicorp-vault-clm-discovery/issues/83) | **Parent.** Event catalogue, revoke-via-AAP, ITSM, then “cloud collectors.” This spec **narrows** the first collectors to **ADCS + AKV** and replaces the placeholder `scan_source=cloud_*` with `adcs` / `akv` for these two. ACM/GCP stay on M5 as later copies of AKV. |
| This spec | Concrete discovery ingest for ADCS then AKV. |
| [Vault import](2026-07-06-vault-import-workflow-design.md) + [Mode C](2026-07-06-mode-c-renewal-kit-design.md) | **Not this work.** Tracking, CA `import/bundle`, and reissue/deploy. |
| [Migrate + pending verify](2026-08-13-migrate-pending-verify-design.md) | ADCS/AKV/TLS leaves → Vault via Mode C + Pending-verify. Same path once collectors exist. |
| Connections Settings (future) | Durable ADCS/AKV/AAP credentials in the UI; collectors work on env until then. |
