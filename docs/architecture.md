# Architecture

## Overview

Vault CLM Discovery is an **external service** that complements HashiCorp Vault PKI. It does not run as a Vault secrets-engine plugin. Instead, it:

1. Scans network targets for TLS certificates
2. Persists a normalized certificate inventory in PostgreSQL
3. Serves a REST API and Next.js dashboard
4. Reconciles discovered certs against Vault PKI mounts (Phase 1 read-only)

```mermaid
flowchart TB
  subgraph clients [Clients]
    Dashboard[Next.js Dashboard]
    CLI[clm-scan CLI]
  end

  subgraph service [CLM Discovery Service]
    API[Go REST API]
    Worker[Scan Worker Pool]
    LifeWorker[Lifecycle Job Worker]
    Scanner[TLS Scanner]
  end

  DB[(PostgreSQL)]
  Network[Network Targets]
  AAP[AAP Controller]

  Dashboard --> API
  CLI --> DB
  API --> Worker
  API --> DB
  Worker --> Scanner
  Scanner --> Network
  Worker --> DB
  LifeWorker --> DB
  LifeWorker --> AAP
  API --> AAP
```

## Components

### TLS Scanner (`internal/scanner`)

- Expands CIDR ranges into IP:port targets
- Performs TCP connect + TLS handshake with `InsecureSkipVerify` to capture presented certificates
- Parses peer certificate chains via `crypto/x509`
- Blocks private ranges by default

### Certificate Parser (`internal/cert`)

- Extracts identity fields aligned with Vault PKI cert objects
- Computes `chain_status` and `hostname_matches_san`
- SHA-256 fingerprint as cross-scan dedup key
- Cheap `pqc_tag` (`classic`/`hybrid`/`pqc`/`unknown`) at parse — inventory only, no PQ issuance

### Posture (`internal/posture`, M3)

- Evaluates SC-081 / PCI / crypto packs plus ops classifiers → upserts `findings`
- Maps pack `warning` → 5-level severity at persist; UI never sees `warning`
- `risk_score = max(non-waived)` with `risk_reasons[]`; waivers suppress score/count, not hide
- Recompute on scan complete and enrichment PATCH

### Lifecycle job worker (`internal/lifecyclejobs`, M2 + #87)

- Persists `lifecycle_jobs` before renew/migrate **202** (on-demand includes `aap_job_id`; batch migrate emits `renewal.requested` only)
- Claims expired leases (`FOR UPDATE SKIP LOCKED`); polls with existing `aap.WaitForJob` — **never** on `r.Context()`
- Maps `aap.Status*` → CLM status; does not double-launch when `aap_job_id` is set
- After AAP success (or on migrate kickoff): **`pending_verify`** with backoff (`next_verify_at`); user badge **Pending**
- Wire verify: same CN, **new** fingerprint, later `not_after`; emit **`renewal.verified`** (not `renewal.completed` for migrate). Timeout → **`renewal.timed_out`**
- **EDA does not rescan** — CLM owns the verify loop
- Stopgap observe via inventory lookup / `ListCertificates` until M4 durable scan claims

### Store (`internal/store`)

- PostgreSQL persistence with upsert-by-fingerprint
- Normalized observations table for `found_at[]` semantics
- Lifecycle fields computed on write
- Empty OCSP/CRL arrays stored as `{}` (not NULL) so upserts satisfy NOT NULL constraints
- `cert_scope` set on upsert via `governance.ClassifyScope` (chain status, issuer DN, hostname heuristics)

### API (`internal/api`)

- Chi HTTP router with CORS for dashboard
- **Default-deny AuthN** except `GET /api/v1/health`. `CLM_AUTH_MODE=static_token` maps Bearer tokens (`CLM_STATIC_TOKENS`) to RBAC roles. `CLM_INSECURE_NO_AUTH=true` is a UAT/integration hatch (caller treated as `platform_admin`)
- RBAC: `viewer` (GET), `scanner_operator` (+ scans / collect), `remediator` (+ catalog/renew/revoke/PATCH/revocation-check/waivers), `vault_import_admin` (+ CA import/reconcile), `approver` (+ waivers), `platform_admin` (DELETE + Settings mutate), `inventory` (`GET /inventory` only — AAP, not a dashboard page)
- Consent is **intent after RBAC**: unauthorized + `consent:true` → 401/403; authorized + `consent:false` → 400
- Append-only `audit_events` on privileged mutations and 401/403 (not the EDA `events` outbox)
- Durable scan queue: `POST /scans` inserts `pending` and returns **202** immediately (never blocks on an in-memory channel). Over-cap pending → **503**
- Cloud collectors: `POST /scans/collect` with `source=cloud_akv|cloud_acm|cloud_gcp` ingests public PEMs only (upsert by `fingerprint_sha256`; private keys rejected). No cloud root keys in CLM
- ADCS collect: `POST /scans/adcs` launches AAP template `CLM - Collect ADCS` (find-by-name), ingests stdout public PEMs with `source=adcs`. No WinRM/SSH in CLM
- AKV live collect: `POST /scans/akv` lists+gets public certs into `source=cloud_akv` (same token as #99 ingest)
- Background scan poller claims rows with `FOR UPDATE SKIP LOCKED` (multi-replica safe); Compose stays **1** API replica by default
- Consent gate on scan creation
- `POST /api/v1/certificates/{id}/revoke` — consent-gated AAP launch (`clm_action=clm_revoke`); find-by-name template; **503** if AAP unset; CLM never calls Vault `pki/revoke`. Verify via existing `revocation-check` + reconcile
- AAP renew/revoke `extra_vars` contain no secrets (Vault AppRole is an AAP credential)
- `GET /api/v1/scans/{id}` — scan detail and diagnostics
- `GET /api/v1/scans/{id}/certificates` — certificates discovered in that scan
- `DELETE` on scans, certificates, and issuers (204 No Content) for demo reset — `platform_admin` only
- `POST /api/v1/reconcile` — trigger Vault PKI reconcile (503 when `VAULT_ADDR` unset); response includes a `status` of `ok`/`partial`/`failed` alongside `errors`
- `GET /api/v1/scans/{id}/blindspot` and `GET /api/v1/blindspot` — blind-spot counts
- Connections Settings: `GET|PUT|PATCH /api/v1/settings/connections` and `POST /api/v1/settings/connections/test` (see below)
- Request ID propagated into structured logs, audit rows, and JSON error responses

### Governance classification (`internal/governance`)

At certificate upsert, `ClassifyScope` assigns `cert_scope`:

- `internal` — self-signed chains, internal hostname suffixes (`.local`, `.internal`, …), Vault/internal CA issuers, dev/staging environment
- `external` — public CA issuer hints (Let's Encrypt, DigiCert, …) or default until v1.1 Vault reconciliation overrides

### Scan worker flow

`scans` **is** the queue. There is no Redis and no in-process job channel.

1. `POST /api/v1/scans` inserts a `pending` row (backpressure: `SCAN_QUEUE_MAX_PENDING` → 503) and returns 202
2. A poller claims claimable `pending` / lease-expired `running` rows with `FOR UPDATE SKIP LOCKED`, heartbeats `claimed_at` while probing, and releases the claim on graceful cancel so another replica can resume
3. Expand hostnames/CIDRs into targets; record non-fatal expansion warnings (hostname-resolved private IPs obey `ALLOW_PRIVATE_RANGES` the same as CIDRs)
4. Probe each target concurrently; on success, upsert certificate (empty AIA arrays as `{}`)
5. Increment `certs_found` only after a successful certificate upsert (not on probe alone)
6. Track `targets_succeeded` / `targets_failed`, `upsert_failures`, and capped `failure_samples`
7. On completion, persist summary counts on the `scans` row and clear the claim
8. When `RECONCILE_ON_SCAN_COMPLETE=true`, run Vault PKI reconcile (errors logged, scan still succeeds; the reconcile is bounded by a timeout so an unresponsive Vault cannot block subsequent scans)

The EDA outbox dispatcher uses the same SKIP LOCKED claim pattern so two API replicas cannot double-deliver an event. When `ITSM_WEBHOOK_URL` is set, the same drain fan-outs ticket-shaped JSON templates (`internal/itsm`) with optional HMAC (`X-CLM-Signature`).

### Observability

- JSON `slog` in `clm-discovery` and `clm-scan`; verbosity via `LOG_LEVEL`
- Scan worker logs include `scan_id`, target (`ip:port`), `hostname`, `sni`, and cert identifiers on upsert errors
- Persisted scan diagnostics on `scans`: `expansion_warnings`, probe/upsert aggregate counts, capped `failure_samples` JSON
- Scan completion emits a summary log line with targets succeeded/failed, certs found, and upsert failures

### Testing tiers

- **Unit** — `go test ./...`. Default tier; runs on every build, no external
  services.
- **Build-tagged integration** — `go test -tags uat ./internal/uat/...`.
  Excluded from the default `go test ./...` (via `//go:build uat`); exercises
  the real scanner → parser → governance → compliance pipeline against
  in-process `httptest`-served TLS certificates. Runs in CI as a separate
  step.
- **Docker-compose UAT** (`test/uat/`) — real HTTPS endpoints (nginx
  containers) behind the real API and Postgres, driven by a host-side script.
  Manual/demo tier, not run in CI. Default profile covers a self-signed
  expiry/validity cert matrix; opt-in `--profile vault` and
  `--profile letsencrypt` validate reachable-Vault shadow classification and
  a real Let's Encrypt staging certificate, respectively.

See [test/uat/README.md](../test/uat/README.md) for how to run each UAT tier,
the expected-results matrix, and intended (sometimes counter-intuitive)
behaviors to check before treating a failure as a bug. Design rationale:
[docs/superpowers/specs/2026-07-02-uat-expiry-compliance-testing-design.md](superpowers/specs/2026-07-02-uat-expiry-compliance-testing-design.md).

### Dashboard (`web/`)

- Next.js App Router UI aligned with **HashiCorp Vault’s Helios shell** (AppFrame: header, sidebar, main)
- Routes: certificate inventory (`/`), scans (`/scans`), scan detail (`/scans/[id]`), issuers (`/issuers`), certificate detail (`/certificates/[id]`), Connections (`/settings/connections`)
- Inventory table: Vault, Imported, Scope, Expiry governance columns; delete actions on inventory, scans, and issuers
- Styling uses a subset of [Helios design tokens](https://helios.hashicorp.design/foundations/colors); header logo is Flight Icons `vault-color-24` (same glyph as Vault UI)
- Connections page uses the same Helios CSS (`panel`, form fields, badges) — not shadcn/ui
- Server components call the Go API via `web/lib/api.ts` (`API_INTERNAL_URL` + `CLM_API_TOKEN`). Browser traffic uses the same-origin BFF (`web/app/api/v1/[...path]` and Settings `web/app/api/settings/connections`) which requires a signed session cookie (demo login or OIDC) before attaching server-only Authorization. No `NEXT_PUBLIC_*` tokens. AAP `GET /inventory` is not proxied and is not a dashboard page. Delete buttons remain; they succeed only when the BFF token is `platform_admin`

See [docs/superpowers/specs/2026-06-14-vault-ui-design.md](superpowers/specs/2026-06-14-vault-ui-design.md) for UI design rationale and file map.

## Deployment

Recommended: Docker Compose or Kubernetes Deployment alongside Vault infrastructure.

The service needs outbound network access to scan targets and inbound access to its API from the dashboard. It does not require co-location with Vault for v1.

## Vault integration (Phase 1)

`internal/vault` provides a read-only PKI client and reconciler:

- Authenticate via token or AppRole (login + client-token cache/renew in `internal/vault`). AWS/K8s deferred
- **Split identities:** read/reconcile uses `VAULT_TOKEN` or `VAULT_ROLE_ID`/`VAULT_SECRET_ID`; CA import requires `VAULT_IMPORT_TOKEN` or import AppRole. Import with only the read identity configured returns **503**
- List PKI mounts, serials (via Vault's `LIST` cert operation), and stored certificates
- Match by `fingerprint_sha256` to set `managed_status`, `vault_pki_mount`, `vault_issuer_ref`, `serial_number`
- All Vault HTTP calls use a bounded client timeout
- `POST /api/v1/reconcile` or optional post-scan hook (`RECONCILE_ON_SCAN_COMPLETE`); reconcile summary carries a `status` (`ok`/`partial`/`failed`)
- Process-start reconcile/import still bind `VAULT_*` / `VAULT_IMPORT_*` env from `config.Load()` (see Connections resolve)

HCP Vault Dedicated uses the same HTTP API with namespace headers. Settings UX (`hcp_dedicated` vs `self_managed`) is labels + `namespace=admin` preset only.

Future: Kubernetes/AWS auth. CA import uses `pki/issuers/import/bundle`.

## Connections settings

Operators configure Vault, AAP Controller, and the EDA webhook from **Settings → Connections** (`/settings/connections`). Compose env remains the 12-factor default; a UI save overlays that target. The UI uses human labels (**Deployment**, **Renew with**, **Template name**, **Default Vault PKI mount**); env names (`AAP_DEFAULT_MOUNT`, etc.) are unchanged.

**Default Vault PKI mount** (`default_mount` / `AAP_DEFAULT_MOUNT`) is the Vault PKI path passed to Mode C renewals when the cert/request has no mount — not an AAP resource id.

Dropdowns for PKI mounts and AAP job/workflow template **names** load from read-only options endpoints (resolved connection). Empty list or peer failure → free-text input. Options never return secrets and never launch jobs.

### Resolve order (`internal/settings`)

1. **Env default** — no `connections` row, or `source=env`: live values come from `VAULT_*` / `AAP_*` / `EDA_*`.
2. **UI overlay** — PUT/PATCH upserts the row, encrypts secrets under `CLM_CONNECTIONS_KEY`, sets `source=db`. Metadata and non-empty decrypted secrets overlay env for that target; missing secret keys fall back to env.
3. **Write-only secrets** — omitted or empty secret fields keep the stored value. JSON `null` clears a secret so the target can fall back to env.
4. **Missing `CLM_CONNECTIONS_KEY`** — env-only mode still works. PUT/PATCH that would persist new secrets → **503**. Plaintext secrets are never stored.

`settings.Resolve` is used by GET (masked `PublicView`), Test, and options. Reconcile, Mode C renew, and the EDA dispatcher still bind process env at startup and do **not** hot-reload from a UI save.

### API

All under `/api/v1/settings/connections`. The Next BFF proxies with `Authorization`.

| Method | Behavior |
|--------|----------|
| `GET` | Masked view: `configured`, `source`, metadata, `*_set` flags. Never token / `role_id` / `secret_id` values. |
| `PUT` | Replace all three targets (`vault`, `aap`, `eda` required). Invalid `deployment` / `auth_method` → 400. |
| `PATCH` | Partial update (one or more targets). Same write-only secret rule. |
| `POST /test` | Body `{"target":"vault"|"aap"|"eda"}` only. Uses **resolved** credentials on the server. Never accept a secret in the test body. |
| `GET /options/vault-pki-mounts` | `{items}` PKI mount paths via `ListPKIMounts`. Unconfigured → empty; configured but list fails → **502**. |
| `GET /options/aap-templates?kind=job\|workflow` | `{kind, items:[{id,name}]}` for selects (Settings stores **name** + `renew_workflow`). Unconfigured → empty; peer fail → **502**; bad `kind` → **400**. Never launches jobs. |

Auth: unauthenticated GET/PUT/PATCH/Test/options → **401**. `CLM_INSECURE_NO_AUTH=true` (UAT/integration) treats the caller as `platform_admin`. With a static token: `platform_admin` can read and mutate; `remediator` GET/options 200 (still no secrets), PUT/Test 403; other roles 403. 401/403 from the auth middleware write `audit_events`.

### Test probes

Server-side only. Credentials come from `settings.Resolve` (DB overlay else env).

| Target | Probe | Must not |
|--------|--------|----------|
| **Vault** | `GET /v1/sys/mounts` via `vault.Client.ListMounts` (token: `X-Vault-Token`; AppRole: login then the same call with the cached client token). Success detail `sys/mounts 200` (+ `namespace=` when set). | Persist the AppRole-derived token in the `connections` row (cache lives on the Vault client). |
| **AAP** | `GET /api/v2/me` then resolve `AAP_RENEW_TEMPLATE` by name (`FindJobTemplate` or `FindWorkflowJobTemplate` when `renew_workflow`). | **Launch a job.** No `POST .../launch`. |
| **EDA** | `eventbus.Ping`: `POST` the webhook URL with the same auth as the dispatcher (`Authorization: Bearer` when token set) and body `{"event_type":"clm.connection.test","id":"<uuid>","created_at":"<rfc3339>"}`. Success = **2xx**. | Write the `events` outbox or start the dispatcher. No NATS/Kafka. |

HCP vs self-managed does not change probes.

## Security considerations

- API is default-deny except health. Dashboard BFF attaches `CLM_API_TOKEN` only after a valid BFF session (or `CLM_BFF_INSECURE_NO_SESSION`); never `NEXT_PUBLIC_*` tokens
- Scan consent required at API and CLI — **consent is not authorization** (RBAC first, then consent)
- Private range scanning disabled by default
- Maximum IPv4 scan size: /16
- Store PEM material in PostgreSQL — protect database access accordingly
- Use read-only Vault policies for reconciliation; separate import identity (`VAULT_IMPORT_*`) for CA import
- Connection secrets are AES-256-GCM in `connections.secrets_enc` under `CLM_CONNECTIONS_KEY`; GET never echoes them; Test details redact known secret substrings
- `CLM_INSECURE_NO_AUTH` is UAT/integration-only and applies API-wide, not Settings-only
- Privileged mutations and 401/403 are recorded in `audit_events` (no tokens, PEM, or AAP secrets in `payload`)
- BFF session auth (#89): unauthenticated browser→BFF returns 401 and does not forward to `:8080`
