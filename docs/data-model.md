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
| `status` | enum | Yes | `valid`, `expiring_soon`, `expired`, `revoked` (v1.1b sets `revoked` from Vault reconcile) |
| `revocation_status` | text | v1.1b | `revoked_in_vault` when the matched Vault PKI serial is revoked; source is Vault PKI `revocation_time` via reconcile (OCSP/CRL for shadow certs is later) |
| `revocation_checked_at` | timestamptz | v1.1b | Stamped each reconcile that reads the matched Vault serial |
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
| `risk_score` | int | 0 | Max score of non-waived open findings (M3); bands critical≥80 / high≥60 |
| `risk_reasons` | jsonb | `[]` | Explainable contributors (`rule_id`, severity, title, score, waived) |
| `pqc_tag` | text | `unknown` | `classic` \| `hybrid` \| `pqc` \| `unknown` — inventory only, no PQ issuance |
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
- `connections` — Vault / AAP / EDA Settings overlay (migration `000007`)
- `audit_events` — append-only control-plane audit (migration `000008`; not the EDA `events` outbox)

### Audit events (`audit_events`, migration `000008`)

One row per 401/403 deny and per successful privileged mutation (scan create, renew, CA import, catalog-import, delete, reconcile, revoke). Never store tokens, PEM, AAP secrets, Authorization headers, or connection secret fields in `payload`.

| Field | Type | Description |
|-------|------|-------------|
| `id` | uuid PK | Row id |
| `at` | timestamptz | Event time |
| `actor_id` | text | `static:<role>` for static tokens |
| `actor_type` | text | `user` (no user directory in M1) |
| `role` | text | RBAC role, empty on unauthenticated 401 |
| `action` | text | e.g. `import_ca`, `create_scan`, or `METHOD /path` on deny |
| `target_type` | text | `scan`, `certificate`, `issuer`, or empty |
| `target_id` | text | Target UUID when known |
| `decision` | text | `allow` or `deny` |
| `request_id` | text | Chi request id |
| `remote_ip` | text | Client address |
| `payload` | jsonb | Redacted metadata only |

### Connections (`connections`, migration `000007`)

One row per integration target. Metadata is non-secret JSON; secret material is AES-256-GCM in `secrets_enc` under `CLM_CONNECTIONS_KEY`. `source=env` means Compose/12-factor still applies; a UI save sets `source=db` and overlays env for that target.

| Field | Type | Description |
|-------|------|-------------|
| `target` | text PK | `vault`, `aap`, or `eda` |
| `metadata` | jsonb | Non-secret fields (never tokens / role_id / secret_id) |
| `secrets_enc` | bytea | AEAD ciphertext; nil when secrets come from env only |
| `secrets_set` | bool | True when ciphertext holds at least one secret |
| `source` | text | `env` (default) or `db` |
| `updated_at` | timestamptz | Last upsert |
| `updated_by` | text | Actor when known (M1); may be empty |

`metadata` (never contains secrets):

| Target | Fields |
|--------|--------|
| `vault` | `deployment` (`hcp_dedicated` \| `self_managed`), `addr`, `namespace`, `auth_method` (`token` \| `approle`) |
| `aap` | `url`, `renew_template`, `renew_workflow` (bool), `skip_tls_verify` (bool), `default_mount` |
| `eda` | `webhook_url` |

Plaintext JSON sealed in `secrets_enc` (never logged, never returned on GET):

| Target | Secret keys |
|--------|-------------|
| `vault` | `token` and/or `role_id`, `secret_id` |
| `aap` | `token` |
| `eda` | `token` |

### Lifecycle jobs (`lifecycle_jobs`, migration `000009`)

Durable Mode C renew tracking (M2). Handlers stay **202**; a background worker owns AAP poll + wire verify. Distinct from the EDA `events` outbox and from `audit_events`.

| Field | Type | Description |
|-------|------|-------------|
| `id` | uuid PK | Job id (`lifecycle_job_id` in renew responses) |
| `kind` | text | e.g. `renew` |
| `status` | text | `pending_approval` → `launching` → `aap_*` → `verifying` → `verified` / `verify_failed` / `failed` |
| `predecessor_cert_id` | uuid | Cert being renewed |
| `successor_cert_id` | uuid | New cert after verify (nullable) |
| `aap_job_id` | int | Controller job id (set before 202 on on-demand renew) |
| `aap_workflow` | bool | Workflow vs job template |
| `idempotency_key` | text unique | `renew:<cert_id>:<fingerprint>` |
| `expected` / `observed` | jsonb | Wire verify inputs/outputs |
| `lease_owner` / `lease_expires_at` | text / timestamptz | Worker claim (SKIP LOCKED) |

Related: `lifecycle_job_events` (append-only timeline), `lifecycle_approvals` (auto/consent rows; SoD completeness is M1 actors).

`renewal.launched` / `renewal.completed` / `renewal.failed` also go to the EDA outbox; **completed only after verified**.

### EDA outbox catalogue (`events`, migration `000006`)

Transactional outbox delivered to Ansible EDA. `GET /api/v1/events?event_type=` filters by type.

| `event_type` | When emitted | Payload (JSON) |
|--------------|--------------|----------------|
| `cert.discovered` | First fingerprint upsert | `certificate_id`, `fingerprint_sha256`, `subject_cn`, `status`, `days_until_expiry`, `managed_status`, `cert_scope` |
| `cert.expiring` | Status becomes `expiring_soon` | same |
| `cert.revoked` | Signature-verified revoke / Vault reconcile | includes `source` |
| `blind_spot.detected` | First upsert (default unmanaged) | same as discovered |
| `renewal.requested` | Batch enqueue | renew job metadata |
| `renewal.launched` | AAP job id persisted | renew job metadata |
| `renewal.completed` | Wire verify succeeded | renew job metadata |
| `renewal.failed` | AAP or verify failure | renew job metadata |

### Scan run metadata (`scans`)

| Field | Type | Description |
|-------|------|-------------|
| `status` | enum | `pending`, `running`, `completed`, `failed` |
| `cidrs`, `hostnames`, `ports` | | Scan targets |
| `claimed_by` | text | Worker owner while running (SKIP LOCKED claim) |
| `claimed_at` | timestamptz | Last claim / heartbeat; stale running rows are reclaimable |
| `targets_total` | int | Expanded target count |
| `targets_scanned` | int | Targets processed so far |
| `certs_found` | int | Certificates **successfully persisted** (upsert OK), not probe count |
| `targets_succeeded` | int | Targets where TLS probe returned a certificate |
| `targets_failed` | int | Targets where probe failed (timeout, TLS error, no certs) |
| `upsert_failures` | int | Certificates probed successfully but not persisted |
| `expansion_warnings` | text[] | Hostname/DNS expansion warnings (non-fatal) |
| `failure_samples` | jsonb | Capped array of `{ip, port, hostname, sni, reason, kind}` samples |
| `error` | text | Fatal scan error only (status `failed`) |

Expansion warnings are not stored in `error` on successful scans. The EDA `events` outbox also has `lease_owner` / `lease_expires_at` for multi-replica dispatch.

### Explainable posture (migration `000011`)

Persisted pack+ops findings with explainable `risk_score`. Compliance pack rule IDs and SC-081 UAT ceilings are unchanged; pack `warning` is mapped to 5-level severity **once at persist** (PCI hygiene → medium, else high).

| Table | Purpose |
|-------|---------|
| `policy_versions` | Versioned ops windows (critical≤7d / high≤30d); pack logic stays in Go |
| `findings` | Upsert on `(cert_id, rule_id)`; open/resolved; `waived` flag |
| `waivers` | Suppress count/score with expiry; do not hide findings |

Recompute runs on scan complete and certificate enrichment PATCH. Waiver CRUD: `POST /certificates/{id}/waivers`, `DELETE /waivers/{id}` (remediator/approver). `GET /inventory/pqc` returns tag counts.

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
