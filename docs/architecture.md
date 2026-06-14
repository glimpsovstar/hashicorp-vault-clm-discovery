# Architecture

## Overview

Vault CLM Discovery is an **external service** that complements HashiCorp Vault PKI. It does not run as a Vault secrets-engine plugin. Instead, it:

1. Scans network targets for TLS certificates
2. Persists a normalized certificate inventory in PostgreSQL
3. Serves a REST API and Next.js dashboard
4. (v1.1) Reconciles discovered certs against Vault PKI mounts

```mermaid
flowchart TB
  subgraph clients [Clients]
    Dashboard[Next.js Dashboard]
    CLI[clm-scan CLI]
  end

  subgraph service [CLM Discovery Service]
    API[Go REST API]
    Worker[Scan Worker Pool]
    Scanner[TLS Scanner]
  end

  DB[(PostgreSQL)]
  Network[Network Targets]

  Dashboard --> API
  CLI --> DB
  API --> Worker
  Worker --> Scanner
  Scanner --> Network
  Worker --> DB
  API --> DB
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

### Store (`internal/store`)

- PostgreSQL persistence with upsert-by-fingerprint
- Normalized observations table for `found_at[]` semantics
- Lifecycle fields computed on write

### API (`internal/api`)

- Chi HTTP router with CORS for dashboard
- Background scan worker with bounded concurrency
- Consent gate on scan creation
- Request ID propagated into structured logs and JSON error responses
- Scan diagnostics exposed on `GET /api/v1/scans/{id}`

### Observability

- JSON `slog` in `clm-discovery` and `clm-scan`; verbosity via `LOG_LEVEL`
- Scan worker logs include `scan_id`, target (`ip:port`), `hostname`, `sni`, and cert identifiers on upsert errors
- Persisted scan diagnostics on `scans`: `expansion_warnings`, probe/upsert aggregate counts, capped `failure_samples` JSON
- Scan completion emits a summary log line with targets succeeded/failed, certs found, and upsert failures

- Scan completion emits a summary log line with targets succeeded/failed, certs found, and upsert failures

### Dashboard (`web/`)

- Next.js App Router UI aligned with **HashiCorp Vault’s Helios shell** (AppFrame: header, sidebar, main)
- Routes: certificate inventory (`/`), scans (`/scans`), issuers (`/issuers`), certificate detail (`/certificates/[id]`)
- Styling uses a subset of [Helios design tokens](https://helios.hashicorp.design/foundations/colors); header logo is Flight Icons `vault-color-24` (same glyph as Vault UI)
- Server components call the Go API via `web/lib/api.ts` (`API_INTERNAL_URL` in Docker, `NEXT_PUBLIC_API_URL` in browser)

See [docs/superpowers/specs/2026-06-14-vault-ui-design.md](superpowers/specs/2026-06-14-vault-ui-design.md) for UI design rationale and file map.

## Deployment

Recommended: Docker Compose or Kubernetes Deployment alongside Vault infrastructure.

The service needs outbound network access to scan targets and inbound access to its API from the dashboard. It does not require co-location with Vault for v1.

## Vault integration (v1.1)

A separate `internal/vault` client will:

- Authenticate via AppRole or Kubernetes JWT
- List PKI mounts, issuers, and stored certificates
- Match by `fingerprint_sha256` to set `managed_status`
- Optionally import discovered CA bundles via `pki/issuers/import/bundle`

HCP Vault Dedicated uses the same HTTP API with namespace headers.

## Security considerations

- Scan consent required at API and CLI
- Private range scanning disabled by default
- Maximum IPv4 scan size: /16
- Store PEM material in PostgreSQL — protect database access accordingly
- Use read-only Vault policies for reconciliation; separate policy for CA import
