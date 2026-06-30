# HashiCorp Vault CLM Discovery

Network TLS certificate discovery service that runs alongside HashiCorp Vault or HCP Vault. Scans IP/CIDR ranges, builds a certificate inventory with lifecycle metadata, and exposes an independent dashboard for CLM workflows.

Vault PKI reconciliation is planned for v1.1.

**New here?** See [docs/program-context.md](docs/program-context.md) — how this repo fits Vault PKI, HCP Certificates Inventory, and the Discover → Choose → Import → Manage lifecycle.

## Features (v1)

- Concurrent TLS probing across CIDR ranges and ports
- Certificate identity extraction aligned with Vault PKI cert objects
- Lifecycle status (`valid`, `expiring_soon`, `expired`)
- Discovery metadata (observations per IP/port/SNI)
- Issuer/CA inventory from presented chains
- REST API + Next.js dashboard (Vault-style Helios UI — see [UI design spec](docs/superpowers/specs/2026-06-14-vault-ui-design.md))
- Inventory governance columns: Vault connection, import state, internal/external scope, expiry badges
- Scan detail page (`/scans/{id}`) with **View results** and inventory filter by scan
- DELETE API + dashboard actions to reset scans, certificates, and issuers between demos
- Manual governance enrichment (owner, team, environment, tags)

## Quick start

### Docker Compose

```bash
docker compose -f deploy/docker-compose.yml up --build
```

- Dashboard: http://localhost:3000
- API: http://localhost:8080/api/v1/health

In Docker, the web container calls the API at `http://api:8080` during server rendering (`API_INTERNAL_URL`); your browser still uses `http://localhost:8080`.

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
go run ./cmd/clm-discovery

# Dashboard
cd web && npm install && NEXT_PUBLIC_API_URL=http://localhost:8080 npm run dev
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

Private RFC1918, loopback, and link-local ranges are blocked unless `ALLOW_PRIVATE_RANGES=true`.

## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | (required) | PostgreSQL connection string |
| `LOG_LEVEL` | `info` | Structured log verbosity: `info`, `debug`, `trace`, `warn`, `error` |
| `ALLOW_PRIVATE_RANGES` | `false` | Allow scanning RFC1918/loopback ranges |
| `SCAN_TIMEOUT` | `5s` | Per-target TLS probe timeout |
| `DEFAULT_CONCURRENCY` | `50` | Default scan worker concurrency |
| `EXPIRING_SOON_DAYS` | `30` | Days before expiry for `expiring_soon` status |
| `VAULT_ADDR` | (empty) | HashiCorp Vault API address; empty disables Vault integration |
| `VAULT_NAMESPACE` | (empty) | Vault enterprise namespace header (`X-Vault-Namespace`) |
| `VAULT_TOKEN` | (empty) | Vault token for `token` auth (`X-Vault-Token`) |
| `VAULT_AUTH_METHOD` | `token` | Auth method: `token`, `approle`, or `aws` (Phase 1 implements `token` only) |

Both `clm-discovery` and `clm-scan` emit JSON logs to stdout. Set `LOG_LEVEL=debug` to see target expansion summaries; `trace` adds per-target probe outcomes.

## Architecture

See [docs/architecture.md](docs/architecture.md) (includes dashboard / Vault UI alignment).

## Dashboard UI

The web app mirrors HashiCorp Vault’s **AppFrame** layout (sidebar nav, page headers, HDS colors). Design spec and implementation plan:

- [docs/superpowers/specs/2026-06-14-vault-ui-design.md](docs/superpowers/specs/2026-06-14-vault-ui-design.md)
- [docs/superpowers/plans/2026-06-14-vault-ui-dashboard.md](docs/superpowers/plans/2026-06-14-vault-ui-dashboard.md)

Official Vault logo: `@hashicorp/flight-icons` **vault-color-24** (gold chevron), matching [Vault’s app header](https://github.com/hashicorp/vault/blob/main/ui/lib/core/addon/components/sidebar/frame.hbs).

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
| DELETE | `/api/v1/scans/{id}` | Delete scan record |
| GET | `/api/v1/certificates` | List certificates (`?scan_id=` filters by scan) |
| GET | `/api/v1/certificates/{id}` | Certificate detail + observations |
| PATCH | `/api/v1/certificates/{id}` | Update governance fields |
| DELETE | `/api/v1/certificates/{id}` | Delete certificate |
| GET | `/api/v1/issuers` | List issuers/CAs |
| DELETE | `/api/v1/issuers/{id}` | Delete issuer |

## License

Mozilla Public License 2.0 — see [LICENSE](LICENSE).

## Cursor rules

- **Org:** [glimpsovstar/cursor-org-rules](https://github.com/glimpsovstar/cursor-org-rules) — SDLC, Superpowers, commit policy (`~/.cursor/rules/org-*.mdc` or Team Rules dashboard)
- **Project:** `.cursor/rules/` — tests, docs, SDLC demo, architecture context
- **Workflow:** [CONTRIBUTING.md](CONTRIBUTING.md) · [docs/demo-flow.md](docs/demo-flow.md) · [.prompts-history.md](.prompts-history.md)

## Roadmap

- **Phase 1 (v1.1 + report v0):** Vault PKI reconcile, blind-spot dashboard, SC-081/PCI compliance, scan report download — [plan](docs/superpowers/plans/2026-06-30-phase-1-blind-spot-reveal-demo.md) · [demo flow](docs/demo-flow.md)
- **v1.1b:** OCSP/CRL revocation checks
- **v1.2:** CA import/bundle, vault-agent/AAP integration hooks, optional HCP reporting ingest, baseline/delta reports
- **v2:** Cloud provider certificate sources (AWS ACM, etc.)

Lifecycle and HCP positioning: [docs/program-context.md](docs/program-context.md) · [lifecycle spec](docs/superpowers/specs/2026-06-14-clm-lifecycle-workflow-design.md)
