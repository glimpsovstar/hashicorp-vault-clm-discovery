# Data Model

The schema is designed upfront to support full CLM workflows. v1 populates identity, discovery, and basic lifecycle fields; governance defaults and Vault reconciliation fields are stored with defaults until v1.1.

## 1. Core certificate identity

Maps to Vault PKI cert objects for clean reconciliation.

| Field | Type | Description |
|-------|------|-------------|
| `serial_number` | text | Vault primary key for issued certs |
| `fingerprint_sha256` | text (unique) | Cross-scan dedup key |
| `subject_cn` | text | Common Name |
| `subject_alt_names` | jsonb | DNS/IP/email SANs |
| `issuer_dn` | text | Issuer distinguished name |
| `authority_key_id` | text | Links to issuer |
| `not_before` | timestamptz | Validity start |
| `not_after` | timestamptz | Validity end |
| `key_type` | text | RSA, ECDSA, Ed25519 |
| `key_bits` | int | Key size |
| `signature_algorithm` | text | Signature algorithm |
| `is_ca` | bool | Basic constraints CA flag |
| `key_usage` | text[] | Key usage extensions |
| `ext_key_usage` | text[] | Extended key usage |
| `pem` | text | Raw certificate PEM |

## 2. Lifecycle fields

Computed on write; stored for dashboard/alerts.

| Field | Type | v1 | Description |
|-------|------|----|-------------|
| `days_until_expiry` | int | Yes | Days until `not_after` |
| `status` | enum | Yes | `valid`, `expiring_soon`, `expired`, `revoked` |
| `revocation_status` | text | No | From OCSP/CRL (v1.1) |
| `revocation_checked_at` | timestamptz | No | Last revocation check |
| `crl_distribution_points` | text[] | Yes | From cert AIA |
| `ocsp_servers` | text[] | Yes | From cert AIA |

## 3. Discovery metadata

Net-new; where/when the cert was seen.

| Field | Type | Description |
|-------|------|-------------|
| `found_at[]` | observations table | `{ ip, port, hostname, sni, tls_version, cipher_suite, observed_at }` |
| `first_discovered` | timestamptz | First observation |
| `last_seen` | timestamptz | Most recent observation |
| `scan_id` | uuid (FK) | Per observation |
| `scan_source` | text | Default `network` on scans table |
| `hostname_matches_san` | bool | Misconfiguration flag |
| `chain_status` | enum | `complete`, `self_signed`, `incomplete`, `untrusted_root` |

## 4. Reconciliation & governance

| Field | Type | v1 default | Description |
|-------|------|------------|-------------|
| `managed_status` | enum | `unmanaged` | `managed_in_vault`, `unmanaged`, `imported` — v1 defaults to `unmanaged`; dashboard **Vault** / **Imported** columns derive from this |
| `cert_scope` | enum | `external` | `internal`, `external` — set at scan via `governance.ClassifyScope` (chain, issuer DN, hostname); dashboard **Scope** column |
| `vault_issuer_ref` | text | null | Vault issuer ref if managed |
| `vault_pki_mount` | text | null | PKI mount path |
| `owner` | text | null | Asset owner |
| `team` | text | null | Owning team |
| `environment` | text | null | dev/staging/prod |
| `tags` | text[] | `{}` | Free-form tags |
| `risk_score` | int | 0 | Composite score (v1.1) |
| `remediation_state` | enum | `none` | Workflow state |

## 5. Issuer/chain records

Discovered CA/intermediate certs for import via `pki/issuers/import/bundle`.

| Field | Type | Description |
|-------|------|-------------|
| `issuer_name` | text | Friendly name |
| `issuer_id` | text | Vault-assigned on import (v1.1) |
| `ca_chain` | text[] | PEM chain |
| + identity/lifecycle fields | | Same as certificates, `is_ca: true` |

## Tables

- `certificates` — deduplicated cert inventory
- `certificate_observations` — normalized `found_at[]`
- `scans` — scan run metadata and diagnostics
- `issuers` — CA/intermediate inventory

### Scan run metadata (`scans`)

| Field | Type | Description |
|-------|------|-------------|
| `status` | enum | `pending`, `running`, `completed`, `failed` |
| `cidrs`, `hostnames`, `ports` | | Scan targets |
| `targets_total` | int | Expanded target count |
| `targets_scanned` | int | Targets processed so far |
| `certs_found` | int | Certificates **successfully persisted** (upsert OK), not probe count |
| `targets_succeeded` | int | Targets where TLS probe returned a certificate |
| `targets_failed` | int | Targets where probe failed (timeout, TLS error, no certs) |
| `upsert_failures` | int | Certificates probed successfully but not persisted |
| `expansion_warnings` | text[] | Hostname/DNS expansion warnings (non-fatal) |
| `failure_samples` | jsonb | Capped array of `{ip, port, hostname, sni, reason, kind}` samples |
| `error` | text | Fatal scan error only (status `failed`) |

Expansion warnings are not stored in `error` on successful scans.

### Dashboard column mapping (inventory)

| UI column | Source field | v1 display |
|-----------|--------------|------------|
| Vault | `managed_status` | Connected if `managed_in_vault`, else Not connected |
| Imported | `managed_status` | Imported if `imported`, else Not imported |
| Scope | `cert_scope` | Internal / External |
| Expiry | `status` | Active (green) unless `expired` or `revoked` (red) |

## Status computation

```
expired       → not_after < now
expiring_soon → not_after within 30 days (configurable via EXPIRING_SOON_DAYS)
valid         → otherwise
revoked       → v1.1 after OCSP/CRL check
```
