# HashiCorp Vault CLM Discovery

Network TLS certificate discovery service that runs alongside HashiCorp Vault or HCP Vault. Scans IP/CIDR ranges, builds a certificate inventory with lifecycle metadata, and exposes an independent dashboard for CLM workflows.

Vault PKI reconciliation is planned for v1.1.

## Features (v1)

- Concurrent TLS probing across CIDR ranges and ports
- Certificate identity extraction aligned with Vault PKI cert objects
- Lifecycle status (`valid`, `expiring_soon`, `expired`)
- Discovery metadata (observations per IP/port/SNI)
- Issuer/CA inventory from presented chains
- REST API + Next.js dashboard (Vault-style Helios UI — see [UI design spec](docs/superpowers/specs/2026-06-14-vault-ui-design.md))
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
go run ./cmd/clm-discovery

# Dashboard
cd web && npm install && NEXT_PUBLIC_API_URL=http://localhost:8080 npm run dev
```

### CLI scan

```bash
export DATABASE_URL=postgres://clm:clm@localhost:5432/clm?sslmode=disable
export ALLOW_PRIVATE_RANGES=true
go run ./cmd/clm-scan --cidrs=127.0.0.1/32 --ports=443 --i-consent-to-scan
```

## Authorized scanning

Only scan networks you own or have explicit permission to test. The API and CLI require explicit consent before scanning.

Private RFC1918, loopback, and link-local ranges are blocked unless `ALLOW_PRIVATE_RANGES=true`.

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
| GET | `/api/v1/certificates` | List certificates |
| GET | `/api/v1/certificates/{id}` | Certificate detail + observations |
| PATCH | `/api/v1/certificates/{id}` | Update governance fields |
| GET | `/api/v1/issuers` | List issuers/CAs |

## License

Mozilla Public License 2.0 — see [LICENSE](LICENSE).

## Cursor rules

- **Org:** [glimpsovstar/cursor-org-rules](https://github.com/glimpsovstar/cursor-org-rules) — SDLC, Superpowers, commit policy (`~/.cursor/rules/org-*.mdc` or Team Rules dashboard)
- **Project:** `.cursor/rules/` — tests, docs, SDLC demo, architecture context
- **Workflow:** [CONTRIBUTING.md](CONTRIBUTING.md) · [docs/demo-flow.md](docs/demo-flow.md) · [.prompts-history.md](.prompts-history.md)

## Roadmap

- **v1.1:** Vault PKI reconciliation (`managed_in_vault`, issuer mapping, import bundle workflow)
- **v1.1:** OCSP/CRL revocation checks
- **v2:** Cloud provider certificate sources (AWS ACM, etc.)
