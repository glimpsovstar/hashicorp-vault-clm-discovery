# HashiCorp Vault CLM Discovery

Network TLS certificate discovery and lifecycle service that runs alongside HashiCorp Vault or HCP Vault. It scans IP/CIDR and hostname ranges, builds a governed certificate inventory, **reconciles the discovered certs against Vault PKI to reveal the "blind spot"** (certificates deployed on the wire that Vault never issued), evaluates SC-081/PCI/crypto compliance, and drives closed-loop renewal through Ansible Automation Platform (AAP).

It complements Vault PKI and HCP Certificates Inventory. It is **not** a Vault plugin and does not itself issue or sign certificates — CLM is the inventory system of record; Vault remains the issuance/trust system of record (see [ADR 0001](docs/adr/0001-source-of-truth-and-event-driven-automation.md)).

**New here?** See [docs/program-context.md](docs/program-context.md) — how this repo fits Vault PKI, HCP Certificates Inventory, and the Discover → Choose → Import → Manage lifecycle.

## Features

### Discovery & inventory

- Concurrent TLS probing across CIDR ranges, hostnames (DNS-resolved with correct SNI), and ports
- Certificate identity extraction aligned with Vault PKI cert objects
- Lifecycle status (`valid`, `expiring_soon`, `expired`, `revoked`)
- Discovery metadata (observations per IP/port/SNI)
- Issuer/CA inventory from presented chains
- REST API + Next.js dashboard (Vault-style Helios UI — see [UI design spec](docs/superpowers/specs/2026-06-14-vault-ui-design.md))
- Inventory governance columns: Vault connection, import state, internal/external scope, expiry badges
- Manual governance enrichment (owner, team, environment, tags)
- Scan detail page (`/scans/{id}`) with **View results** and inventory filter by scan
- DELETE API + dashboard actions to reset scans, certificates, and issuers between demos

### Vault reconcile & blind-spot reveal

- Read-only Vault PKI client (`LIST`/`READ`); reconcile matches wire certs to Vault-issued certs
- **Blind-spot reveal** — surfaces "shadow" certificates deployed but never issued by Vault, per scan and globally (`GET /scans/{id}/blindspot`, `GET /blindspot`) with a dashboard card
- Vault-revoked certs are marked `status=revoked` during reconcile (durable across rescans)

### Compliance

- SC-081 / PCI / crypto-strength evaluators (`internal/compliance`)
- Per-scan and global compliance summaries (`GET /scans/{id}/compliance`, `GET /compliance/summary`)

### Revocation checks

- CRL and OCSP checks for shadow certs (OCSP-first, CRL fallback) — `POST /certificates/{id}/revocation-check`
- Stapled OCSP captured at scan time and auto-persisted when verified-revoked
- Revocation is recorded source-accurately (`revoked_via_ocsp` / `revoked_via_crl` / `ocsp_stapled`) and is durable across rescans
- SSRF-hardened fetch path: private/loopback/link-local (incl. `169.254.169.254`) and CGNAT destinations are denied post-DNS; redirects disabled

### Reporting

- Environment scan report (`GET /scans/{id}/report`) with severity-classified insights and recommendation codes
- Aggregates cert health, expiry risk, issuer trust, and scope/governance
- Output formats: `markdown` (default), `json`, `csv` (`?format=`) — CSV is formula-injection guarded; dashboard offers CSV/JSON download. `report_version` 0.2.0.

### Import & lifecycle actions

- **Choose wizard** — recommends the next lifecycle action per cert (`GET /certificates/{id}/choose`) with a cert-detail panel
- **Catalog import** (Modes A + D) — track a wire cert in CLM (`POST /certificates/{id}/catalog-import`, consent-gated, read-only); optionally attaches per-cert `renewal` config
- **CA import to Vault** (Mode B, a Vault write) — `POST /issuers/{id}/import` with a consent modal
- Wire-vs-Vault mirror panel and "Track in CLM" button on the cert detail page

### Renewal automation (Mode C — CLM orchestrates, Vault issues, AAP deploys)

- **Renewal kit generator** — renders vault-agent HCL / an AAP playbook to reissue+deploy a cert (`GET /certificates/{id}/renewal-kit`)
- **On-demand renew** — `POST /certificates/{id}/renew` launches AAP, persists a `lifecycle_jobs` row + `renewal.launched` **before** 202 (`lifecycle_job_id` in the body), and stores `renewal_config`
- **Batch auto-renewal** — `POST /renew-expiring` enqueues one durable job per eligible cert (worker launches AAP); defaults to `EXPIRING_SOON_DAYS`
- **Durable lifecycle worker** — claims jobs, polls with `WaitForJob` (never on the HTTP request context), maps AAP status → CLM status, and marks **verified** only after wire check (same CN, new fingerprint, later `not_after`). AAP success alone is not completed
- **Read API** — `GET /lifecycle-jobs/{id}`, `GET /certificates/{id}/lifecycle-jobs`
- **Per-cert renewal config** persisted (`renewal_config` JSONB), survives rescans, feeds the dynamic inventory
- **AAP dynamic inventory** — `GET /inventory` renders Ansible `--list` JSON (host = CN, issue-role hostvars + `clm_*` metadata, `clm_renewable`/`svc_*` groups)
- Closed-loop verification = rescan + reconcile

### Events (transactional outbox → Ansible EDA)

- Transactional outbox (`events` table): state changes such as revocation emit an event in the **same DB transaction** — `GET /events`
- Event dispatcher delivers outbox events to an Ansible EDA webhook (at-least-once, dead-letters after `EVENT_MAX_ATTEMPTS`), gated by `EDA_WEBHOOK_URL`, drained on shutdown
- Message-bus transport (NATS/Kafka) is deferred until a second consumer exists (see [ADR 0001](docs/adr/0001-source-of-truth-and-event-driven-automation.md))

### Connections (Settings)

- Dashboard **Settings → Connections** (`/settings/connections`) configures Vault, AAP Controller, and the EDA webhook with human labels (not raw env names on the fields we polish): **Deployment**, **Renew with** (Job template / Workflow), **Template name**, **Default Vault PKI mount** ([#91](https://github.com/glimpsovstar/hashicorp-vault-clm-discovery/issues/91); mount clarity [#92](https://github.com/glimpsovstar/hashicorp-vault-clm-discovery/issues/92))
- Compose env (`VAULT_*`, `AAP_*`, `EDA_*`) remains the 12-factor default; env **names** are unchanged (`AAP_DEFAULT_MOUNT`, `AAP_RENEW_TEMPLATE`, `AAP_RENEW_WORKFLOW`, …). A UI save writes a per-target overlay (`source=db`) in Postgres
- **Default Vault PKI mount** (env `AAP_DEFAULT_MOUNT`) is the Vault PKI mount path passed to AAP on Mode C renew when the cert/request does not already set a mount — not an AAP resource id
- Dropdowns for PKI mounts and AAP templates are filled from read-only options APIs (resolved connection, same auth as Settings GET). Empty list or peer error → free-text input so operators can still type a path/name. Options never return secrets and never launch AAP jobs
- Secrets never reach the browser (masked `*_set` flags only). Persist them only with `CLM_CONNECTIONS_KEY` (AES-256-GCM)
- **Test connection** is server-side and uses the resolved overlay (DB else env): Vault `GET /v1/sys/mounts` (AppRole logs in first); AAP `GET /api/v2/me` then template-by-name (**does not launch a job**); EDA signed ping (`Authorization: Bearer` when a token is set, body `clm.connection.test`, **no outbox write**)
- Control-plane AuthN is default-deny except `GET /api/v1/health`. The dashboard BFF attaches `CLM_API_TOKEN`; the browser never sees Bearer tokens. Roles come from `CLM_STATIC_TOKENS`. `CLM_INSECURE_NO_AUTH=true` is a UAT/integration hatch only.

### Residual risk: dashboard BFF

M1 default-deny applies to the **Go API** (`:8080`). The Next.js BFF (`/api/v1/...`) holds ambient `CLM_API_TOKEN` authority (demo compose: `platform_admin`) until OIDC/session lands. Anyone who can reach the Next origin can perform the API mutations M1 closed on `:8080`. The control plane is **not** closed to unauthenticated mutation at the deployment edge. Follow-up: [authenticate the dashboard BFF (OIDC/session)](https://github.com/glimpsovstar/hashicorp-vault-clm-discovery/issues/89).

## Quick start

### Docker Compose

```bash
docker compose -f deploy/docker-compose.yml up --build
```

- Dashboard: http://localhost:3000
- API: http://localhost:8080/api/v1/health

In Docker, the web container calls the API at `http://api:8080` during server rendering (`API_INTERNAL_URL` + `CLM_API_TOKEN`). Browser mutations go through the same-origin BFF (`/api/v1/...`); do not put tokens in `NEXT_PUBLIC_*`.

Start a scan from the **Scans** page using **hostnames** (recommended for HTTPS sites) or CIDR ranges.

**Demo hostnames:**

```text
aap.david-joo.sbx.hashidemos.io,coffeesnob.withdevo.net
```

Port `443`, consent checked. Hostname scans resolve DNS and send the correct TLS SNI (required on shared IPs like Vercel).

**CIDR fallback** (only if you know the IP and the cert is served for that IP):

```bash
dig +short coffeesnob.withdevo.net
# use each IP as x.x.x.x/32 — may show wrong cert without hostname/SNI
```

The API container sets `ALLOW_PRIVATE_RANGES=true` for local testing.

### Local development

**Requirements:** Go 1.22+, Node 20+, PostgreSQL 16, [golang-migrate](https://github.com/golang-migrate/migrate)

```bash
# Database
export DATABASE_URL=postgres://clm:clm@localhost:5432/clm?sslmode=disable
migrate -path migrations -database "$DATABASE_URL" up

# API
export ALLOW_PRIVATE_RANGES=true
export LOG_LEVEL=info   # info (default), debug, trace, warn, error
export CLM_STATIC_TOKENS=platform_admin:clm-demo-platform-admin
go run ./cmd/clm-discovery

# Dashboard (BFF uses CLM_API_TOKEN; match a role in CLM_STATIC_TOKENS)
export CLM_API_TOKEN=clm-demo-platform-admin
cd web && npm ci && npm run dev
```

### CLI scan

```bash
export DATABASE_URL=postgres://clm:clm@localhost:5432/clm?sslmode=disable
export ALLOW_PRIVATE_RANGES=true
export LOG_LEVEL=info
go run ./cmd/clm-scan --cidrs=127.0.0.1/32 --ports=443 --i-consent-to-scan
```

## Authorized scanning

Only scan networks you own or have explicit permission to test. The API and CLI require explicit consent before scanning.

**Consent is not authorization.** RBAC runs first: an unauthenticated or under-privileged caller with `consent:true` gets **401/403**, not 400. After the caller is authorized, `consent:false` (or missing) on a consent-gated mutation still returns **400**. Checking the dashboard consent box does not grant a role.

Private RFC1918, loopback, and link-local ranges are blocked unless `ALLOW_PRIVATE_RANGES=true` (applies to CIDR targets and to IPs resolved from hostnames).

`POST /api/v1/scans` enqueues a durable `pending` row and returns **202** immediately. A background poller claims work with Postgres `FOR UPDATE SKIP LOCKED` (safe across API replicas; Compose still runs **one** API replica by default). Too many pending scans → **503**.

## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | (required) | PostgreSQL connection string |
| `ADDR` | `:8080` | API listen address |
| `LOG_LEVEL` | `info` | Structured log verbosity: `info`, `debug`, `trace`, `warn`, `error` |
| `CORS_ORIGINS` | `http://localhost:3000` | Allowed CORS origins (comma-separated) |
| `ALLOW_PRIVATE_RANGES` | `false` | Allow scanning RFC1918/loopback/link-local ranges (CIDRs **and** hostname-resolved IPs) |
| `SCAN_TIMEOUT` | `5s` | Per-target TLS probe timeout |
| `DEFAULT_CONCURRENCY` | `50` | Default per-scan probe concurrency |
| `SCAN_QUEUE_MAX_PENDING` | `32` | Max pending scan rows; further `POST /scans` → 503 |
| `SCAN_WORKER_SLOTS` | `2` | Concurrent claimed scans per API process |
| `SCAN_CLAIM_INTERVAL` | `2s` | How often the poller looks for claimable scans |
| `SCAN_LEASE_TTL` | `30s` | Stale `claimed_at` older than this is reclaimable |
| `SCAN_WORKER_ID` | (hostname+id) | Claim owner identity for this process |
| `EXPIRING_SOON_DAYS` | `30` | Days before expiry for `expiring_soon` status (also the default `renew-expiring` window) |
| **Vault (reconcile / import)** | | |
| `VAULT_ADDR` | (empty) | HashiCorp Vault API address; empty disables Vault integration |
| `VAULT_NAMESPACE` | (empty) | Vault enterprise namespace header (`X-Vault-Namespace`) |
| `VAULT_TOKEN` | (empty) | Vault token for **read/reconcile** (`token` auth). Does **not** authorize CA import. |
| `VAULT_ROLE_ID` | (empty) | AppRole role_id when `VAULT_AUTH_METHOD=approle` (read/reconcile) |
| `VAULT_SECRET_ID` | (empty) | AppRole secret_id when `VAULT_AUTH_METHOD=approle` (never logged) |
| `VAULT_AUTH_METHOD` | `token` | Auth method: `token` or `approle` (`aws` is not implemented) |
| `VAULT_IMPORT_TOKEN` | (empty) | Dedicated Vault token for CA import. Required (or import AppRole) or `POST /issuers/{id}/import` returns **503**. |
| `VAULT_IMPORT_AUTH_METHOD` | (empty) | Import auth method; empty inherits read method, or `token`/`approle` from which import creds are set |
| `VAULT_IMPORT_ROLE_ID` | (empty) | Import AppRole role_id (with `VAULT_IMPORT_SECRET_ID`) |
| `VAULT_IMPORT_SECRET_ID` | (empty) | Import AppRole secret_id (never logged) |
| `RECONCILE_ON_SCAN_COMPLETE` | `false` | Automatically reconcile against Vault after each scan finishes |
| **AAP (Mode C renewals)** | | |
| `AAP_URL` | (empty) | Ansible Automation Platform Controller URL; empty ⇒ renew endpoints return 503 |
| `AAP_TOKEN` | (empty) | AAP API token (never logged) |
| `AAP_RENEW_TEMPLATE` | `CLM - Issue Certificate` | Job template (or workflow) name resolved by the renew endpoints (Settings label: **Template name**) |
| `AAP_RENEW_WORKFLOW` | `false` | When true, resolve `AAP_RENEW_TEMPLATE` as a workflow job template (Settings: **Renew with** → Workflow) |
| `AAP_SKIP_TLS_VERIFY` | `false` | Skip TLS verification to the AAP Controller (lab use only) |
| `AAP_DEFAULT_MOUNT` | `pki` | Default **Vault PKI mount path** for Mode C renew when the cert/request has no mount (AAP `extra_vars.mount`). Not an AAP id. Settings label: **Default Vault PKI mount** |
| **Events (EDA dispatcher)** | | |
| `EDA_WEBHOOK_URL` | (empty) | Ansible EDA webhook URL; empty ⇒ dispatcher does not start |
| `EDA_WEBHOOK_TOKEN` | (empty) | Bearer token for the EDA webhook (never logged) |
| `EVENT_DISPATCH_INTERVAL` | `15s` | Outbox drain interval |
| `EVENT_DISPATCH_BATCH` | `50` | Max events delivered per drain |
| `EVENT_MAX_ATTEMPTS` | `10` | Delivery attempts before an event is dead-lettered |
| **Settings (Connections overlay)** | | |
| `CLM_CONNECTIONS_KEY` | (empty) | AES-256-GCM key for UI-persisted connection secrets (32-byte raw or 64-char hex). Empty = env-only mode: Compose still works; PUT/PATCH that persist secrets return 503. Server-side only (not in Next.js) |
| **Control plane (AuthN / RBAC)** | | |
| `CLM_AUTH_MODE` | `static_token` | AuthN mode. Only `static_token` in M1 (empty is treated as `static_token`) |
| `CLM_STATIC_TOKENS` | (empty) | Comma-separated `role:token` (or `role:sha256:<64 hex>`). Roles: `viewer`, `scanner_operator`, `remediator`, `vault_import_admin`, `approver`, `platform_admin`, `inventory`. DELETE requires `platform_admin`. `GET /inventory` is the AAP inventory role only — not a dashboard page |
| `CLM_API_TOKEN` | (empty) | **Dashboard/BFF only** (Next.js server). Bearer sent to the Go API. Must match a `CLM_STATIC_TOKENS` value (typically `platform_admin` so demo Deletes succeed). Never `NEXT_PUBLIC_*` |
| `CLM_INSECURE_NO_AUTH` | `false` | UAT/integration hatch: skip Bearer and treat the caller as `platform_admin` on **all** `/api/v1` routes except health (already public). Not a production auth substitute. Prefer this on existing UAT scripts; or send `Authorization: Bearer` |

Both `clm-discovery` and `clm-scan` emit JSON logs to stdout. Set `LOG_LEVEL=debug` to see target expansion summaries; `trace` adds per-target probe outcomes. Vault/AAP/EDA tokens and URLs are read from the environment and never logged.

**Env vs Settings overlay.** Compose env is the live default for reconcile, Mode C renew, and the EDA dispatcher (bound at process start). **Settings → Connections** stores metadata plus encrypted secrets (`source=db`). **Test** and the Connections **options** endpoints use `settings.Resolve` (DB overlay else env). A UI save does **not** hot-reload already-started reconcile/renew/dispatch clients — set the matching env (or restart the process after changing env) for those runtime paths. AppRole (`VAULT_AUTH_METHOD=approle`) uses `VAULT_ROLE_ID` / `VAULT_SECRET_ID` (or the Settings AppRole fields); login + client-token cache/renew lives in `internal/vault`. Clearing a stored secret is an explicit JSON `null` so that target falls back to env.

## Architecture

See [docs/architecture.md](docs/architecture.md) (includes dashboard / Vault UI alignment), the source-of-truth + event-driven design in [ADR 0001](docs/adr/0001-source-of-truth-and-event-driven-automation.md), and the reporting design in [docs/reporting-architecture.md](docs/reporting-architecture.md).

## Dashboard UI

The web app mirrors HashiCorp Vault’s **AppFrame** layout (sidebar nav, page headers, HDS colors). Design spec and implementation plan:

- [docs/superpowers/specs/2026-06-14-vault-ui-design.md](docs/superpowers/specs/2026-06-14-vault-ui-design.md)
- [docs/superpowers/plans/2026-06-14-vault-ui-dashboard.md](docs/superpowers/plans/2026-06-14-vault-ui-dashboard.md)

**Settings → Connections** (`/settings/connections`) uses the existing Helios CSS (panels, form fields, badges) — not shadcn/ui. Compact **Deployment** radios (Self-managed / HCP Dedicated); AAP **Renew with** radios (Job template / Workflow); **Template name** and **Default Vault PKI mount** as `<select>` when options APIs return items, otherwise free-text. The Next.js BFF proxies `/api/settings/connections` **and** `/api/v1/*` (except AAP `/inventory`) to the Go API with `CLM_API_TOKEN`. The browser never calls Vault/AAP or `:8080` with tokens. Delete buttons stay in the UI; they succeed only when the BFF token is `platform_admin`.

Official Vault logo: `@hashicorp/flight-icons` **vault-color-24** (gold chevron), matching [Vault’s app header](https://github.com/hashicorp/vault/blob/main/ui/lib/core/addon/components/sidebar/frame.hbs).

### Report viewer

A completed scan's detail page links to **View report** (`/scans/{id}/report`), a
view-first environment report rendered in the dashboard: summary tiles, insights,
and recommended actions. From there you can:

- **Download** the report as Markdown, CSV, or JSON.
- **Take action inline** — *Track in CLM* for each shadow certificate (on the wire
  but not managed in Vault) and *Import CA to Vault* for each CA issuer observed in
  the scan.

On the scan's blind-spot card, **Show shadow certs** re-runs the read-only Vault
reconcile to refresh the counts (it changes nothing in Vault); each button carries a
`?` help popover explaining what it does.

## Data model

See [docs/data-model.md](docs/data-model.md).

## API

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/health` | Health check |
| POST | `/api/v1/scans` | Start scan (`consent: true` required) |
| GET | `/api/v1/scans` | List scans |
| GET | `/api/v1/scans/{id}` | Scan detail (status, diagnostics, counts) |
| GET | `/api/v1/scans/{id}/certificates` | Certificates discovered in a scan |
| GET | `/api/v1/scans/{id}/blindspot` | Blind-spot (shadow certs) for a scan |
| GET | `/api/v1/scans/{id}/compliance` | Compliance summary for a scan |
| GET | `/api/v1/scans/{id}/report` | Environment report (`?format=markdown\|json\|csv`) |
| GET | `/api/v1/scans/{id}/findings` | Persisted posture findings for a scan |
| DELETE | `/api/v1/scans/{id}` | Delete scan record |
| GET | `/api/v1/certificates` | List certificates (`?scan_id=` / `?sort=risk_score` / `?min_risk=` / `?pqc_tag=`) |
| GET | `/api/v1/certificates/{id}` | Certificate detail + observations (`risk_score`, `risk_reasons`, `pqc_tag`) |
| GET | `/api/v1/certificates/{id}/pem` | Certificate PEM |
| GET | `/api/v1/certificates/{id}/choose` | Recommended next lifecycle action |
| GET | `/api/v1/certificates/{id}/findings` | Open findings for a certificate |
| GET | `/api/v1/certificates/{id}/waivers` | Waivers for a certificate |
| POST | `/api/v1/certificates/{id}/waivers` | Create waiver (expiry required; remediator/approver) |
| DELETE | `/api/v1/waivers/{id}` | Revoke waiver |
| GET | `/api/v1/certificates/{id}/renewal-kit` | Generate vault-agent / AAP renewal kit (`?target=`, `?mount=`, `?role=`, ...) |
| POST | `/api/v1/certificates/{id}/revocation-check` | CRL/OCSP revocation check |
| POST | `/api/v1/certificates/{id}/catalog-import` | Track cert in CLM (Modes A/D, consent-gated) |
| POST | `/api/v1/certificates/{id}/renew` | On-demand renew via Vault + AAP (consent-gated); 202 includes `lifecycle_job_id` |
| PATCH | `/api/v1/certificates/{id}` | Update governance fields |
| DELETE | `/api/v1/certificates/{id}` | Delete certificate |
| GET | `/api/v1/certificates/{id}/lifecycle-jobs` | List durable lifecycle jobs for a certificate |
| GET | `/api/v1/lifecycle-jobs/{id}` | Lifecycle job status, AAP id, expected/observed |
| GET | `/api/v1/issuers` | List issuers/CAs |
| POST | `/api/v1/issuers/{id}/import` | Import CA bundle into Vault (Mode B, consent-gated) |
| DELETE | `/api/v1/issuers/{id}` | Delete issuer |
| POST | `/api/v1/reconcile` | Reconcile inventory against Vault PKI |
| POST | `/api/v1/renew-expiring` | Enqueue durable renew jobs for expiring certs (consent-gated; worker launches AAP) |
| GET | `/api/v1/inventory` | Ansible dynamic inventory (`--list` JSON, `?within_days=N`). AAP service role only — not a dashboard page |
| GET | `/api/v1/inventory/pqc` | PQC tag inventory counts (`classic` / `hybrid` / `pqc` / `unknown`) |
| GET | `/api/v1/events` | List outbox events (`?event_type=` filters catalogue types) |
| GET | `/api/v1/blindspot` | Global blind-spot (shadow certs) |
| GET | `/api/v1/compliance/summary` | Global compliance summary |
| GET | `/api/v1/settings/connections` | Masked Connections view (no secret values) |
| PUT | `/api/v1/settings/connections` | Replace Vault, AAP, and EDA metadata (write-only secrets) |
| PATCH | `/api/v1/settings/connections` | Partial Connections update (omit/empty secret = keep; JSON `null` = clear) |
| POST | `/api/v1/settings/connections/test` | Server-side probe (`{"target":"vault"|"aap"|"eda"}`; no secrets in body) |
| GET | `/api/v1/settings/connections/options/vault-pki-mounts` | PKI mount paths from resolved Vault (`{items}`; empty if unconfigured; **502** if configured but list fails). No secrets |
| GET | `/api/v1/settings/connections/options/aap-templates?kind=job\|workflow` | Template `{id,name}` list for selects (Settings stores **name** only). Empty if unconfigured; **502** on peer fail; **400** bad `kind`. Never launches jobs |

## License

Mozilla Public License 2.0 — see [LICENSE](LICENSE).

## Cursor rules

- **Org:** [glimpsovstar/cursor-org-rules](https://github.com/glimpsovstar/cursor-org-rules) — SDLC, Superpowers, commit policy (`~/.cursor/rules/org-*.mdc` or Team Rules dashboard)
- **Project:** `.cursor/rules/` — tests, docs, SDLC demo, architecture context
- **Workflow:** [CONTRIBUTING.md](CONTRIBUTING.md) · [docs/demo-flow.md](docs/demo-flow.md) · [.prompts-history.md](.prompts-history.md)

## Roadmap

Shipped since v1: Vault PKI reconcile + blind-spot reveal, SC-081/PCI/crypto compliance, environment reports, CRL/OCSP/stapled revocation, catalog + CA import, Choose wizard, and Mode C renewal automation (AAP renew, batch `renew-expiring`, dynamic inventory, transactional outbox → Ansible EDA). See [progress.md](progress.md) for the detailed log.

- **Event Phase 2:** message-bus transport (NATS/Kafka) — deferred until a second consumer exists ([ADR 0001](docs/adr/0001-source-of-truth-and-event-driven-automation.md))
- **Live validation:** end-to-end against a real AAP Controller + EDA webhook
- **v2:** read-only cloud CA source collectors (AWS ACM, Azure Key Vault, GCP Certificate Manager) into the same inventory — closing the shadow-CA blind spot in a single pane

Lifecycle and HCP positioning: [docs/program-context.md](docs/program-context.md) · [lifecycle spec](docs/superpowers/specs/2026-06-14-clm-lifecycle-workflow-design.md)
