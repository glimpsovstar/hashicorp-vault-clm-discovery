# Progress — Vault CLM Discovery

Resume context for a fresh session. Keep this current (see repo SDLC in `CONTRIBUTING.md`).

## Goal / scope

Standalone Go service + PostgreSQL + Next.js dashboard that discovers TLS
certificates on the wire (network scan), builds a governed inventory, reconciles
against Vault PKI to reveal the "blind spot" (deployed certs Vault never issued),
and evaluates SC-081/PCI/crypto compliance. Complements Vault PKI / HCP
Certificates Inventory; it is **not** a Vault plugin and does not issue/renew certs.

North star and roadmap: `docs/program-context.md`.

## Done

- **v1** — concurrent TLS scan (CIDR + hostname/SNI), cert inventory, observations,
  issuer inventory, governance columns, Helios-style dashboard, demo reset APIs.
  On `main`.
- **Phase 1 (blind-spot reveal)** — read-only Vault PKI client + reconcile
  (`internal/vault`), SC-081/PCI/crypto evaluators (`internal/compliance`),
  scan report v0 (`internal/report`), blind-spot API + dashboard card.
  Merged to `main` via PRs #28, #29, #30 (incl. two rounds of review fixes).
- **UAT & expiry/validity testing** — build-tagged Go integration test
  (`internal/uat/expiry_compliance_uat_test.go`, `//go:build uat`) plus a
  docker-compose UAT stack (`test/uat/`) with `vault` and `letsencrypt` profiles,
  self-cleaning `run-uat.sh`, and a CI step. Complete on branch
  `feat/uat-expiry-compliance-testing` (committed, pushed) — **not yet merged**.

## In progress

- Nothing actively coding. Working tree clean on `feat/uat-expiry-compliance-testing`.

## Next

1. **Land the UAT branch** — open PR for `feat/uat-expiry-compliance-testing`,
   `Fixes` the UAT issue, squash-merge to `main`.
2. **Delete stale remote branch** `origin/feature/27-phase-1-blind-spot` (Phase 1
   content already on `main`; local branch + worktree already removed).
3. **v1.1b** — OCSP/CRL revocation alignment (planned, not started).
4. **v1.2** — full environment scan report, catalog/CA import
   (`pki/issuers/import/bundle`), "Choose" wizard, vault-agent/AAP hooks,
   optional HCP reporting ingest.
5. **v2** — cloud CA sources (ACM, etc.).

## Key context

- **Module:** `github.com/glimpsovstar/hashicorp-vault-clm-discovery`.
- **SDLC (per `CONTRIBUTING.md`):** Issue → design spec (`docs/superpowers/specs/`)
  → plan (`docs/superpowers/plans/`) → `feature/<issue#>-slug` branch → tests-first
  → docs → verify → PR → squash-merge. Superpowers + Cursor rules drive it.
- **Verify commands:**
  ```bash
  go test ./...
  go test -tags uat ./internal/uat/...     # expiry/validity integration test
  sh test/uat/run-uat.sh                   # full docker UAT (up --wait -> driver -> down)
  go build ./...
  cd web && npm run build
  ```
- **Local run:** needs `DATABASE_URL`, `ALLOW_PRIVATE_RANGES=true`; migrations via
  `golang-migrate` (`migrate -path migrations -database "$DATABASE_URL" up`).
- **Vault reconcile:** enabled only when `VAULT_ADDR` is set; auth via
  `VAULT_TOKEN` (`token` method implemented). Read-only PKI (`LIST/READ`).
- **Gotchas:** UAT Go test is build-tagged and excluded from default `go test ./...`;
  expiry offsets use a `+12h` buffer; test certs are RSA-2048/SHA-256 to avoid
  crypto findings. `Go is not installed on the current dev machine` — tests must be
  run where the Go toolchain is available.
