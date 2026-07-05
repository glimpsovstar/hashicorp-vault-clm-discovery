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
  self-cleaning `run-uat.sh`, and a CI step. Merged to `main` via PR #31
  (pre-merge sub-agent review: APPROVE WITH NITS; nits fixed — signal-safe
  teardown, resilient poll, numeric-safe assertions).
- **v1.1b — revocation alignment** — reconcile now marks Vault-revoked certs as
  `status=revoked` (reads `revocation_time` already returned by `ReadCert`; no
  extra Vault call, no migration). Revoked status is durable across rescans.
  Merged to `main` via PR #33 (issue #32). Sub-agent review APPROVE WITH NITS;
  MAJOR durability gap + MINORs fixed.
- **#24 — environment scan report** — Radar-style, cert-only report expanding
  report v0: insight classifier (severity + recommendation codes), aggregators
  (cert health, expiry risk, issuer trust, scope/governance), new Markdown
  sections, and CSV export (`format=csv`, formula-injection guarded). Dashboard
  gains CSV/JSON download. `report_version` 0.2.0. Merged via PR #34.
- **#25 import workflow — PR 1 (modes A + D)** — catalog import
  (`POST /certificates/{id}/catalog-import` → `managed_status=imported`,
  consent-gated, read-only) and a read-only Wire-vs-Vault mirror panel on the
  cert detail page + "Track in CLM" button. Merged via PR #35. Issue #25 stays
  open for PR 2.

## In progress

- Nothing actively coding. On `main`, working tree clean.

## Next

1. **#25 PR 2 — mode B (CA import)** — `POST /issuers/{id}/import` → Vault
   `pki/issuers/import/bundle` (first **write** path); needs a read-write PKI
   policy + consent modal. Spec:
   `docs/superpowers/specs/2026-07-06-vault-import-workflow-design.md`.
2. Remaining v1.2 — "Choose" wizard, vault-agent/AAP hooks, optional HCP
   reporting ingest.
3. **OCSP/CRL for shadow (non-Vault) certs**; mode C reissue (v1.3+).
4. **v2** — cloud CA sources (ACM, etc.).

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
  crypto findings. Go toolchain installed locally via Homebrew (go1.26.4).
