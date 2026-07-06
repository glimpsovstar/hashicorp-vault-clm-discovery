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
  cert detail page + "Track in CLM" button. Merged via PR #35.
- **#25 import workflow — PR 2 (mode B, CA import)** — first Vault **write**:
  `vault.ImportIssuerBundle` + `POST /issuers/{id}/import` (consent, validated
  mount, is_ca/503/502 handling), `GetIssuer`/`SetIssuerVaultRef`, and an
  "Import CA to Vault" consent modal. Merged via PR #36. (Review caught dropped
  DELETE/reconcile routes — restored + Router-level test guards added.)
- **Terraform Vault integration validation** — `test/integration/`: scenario 1
  (local, **in CI**) provisions the whole stack via `docker`+`vault`+`tls`
  providers (postgres, migrate, app, Vault dev + PKI, self-signed nginx) and a
  build-tagged Go driver runs scan → import CA (mode B) → verify in Vault, then
  destroys. Scenario 2 (HCP, opt-in) configures PKI on an existing cluster.
  Merged via PR #37; validated end-to-end (CI `integration` job green).
- **#38 Choose wizard** — `lifecycle.ChooseRecommendation` (pure, cycle-free)
  maps cert signals to a next-action code; `GET /certificates/{id}/choose` +
  a "Recommended next step" panel on cert detail. Merged via PR #39.
- **#40 CRL revocation for shadow certs** — `internal/revocation.CheckCRL`
  (fetch DP, parse, membership, verify sig vs issuer) + `POST /certificates/{id}/
  revocation-check` (persists revoked only when signature-verified; advisory
  otherwise) + "Check revocation" button. SSRF-hardened. Merged via PR #41.
- **#42 OCSP revocation** — `CheckOCSP` + combined `Check` (OCSP-first, CRL
  fallback); revocation persisted source-accurately (`revoked_via_ocsp|crl`).
  Merged via PR #43.
- **HCP integration lane VALIDATED** — minted a fresh token via the TPM cert-auth
  flow (`vault-auth` → `~/.vault-tpm/token` → `source ~/.vault-tpm/vault-env.sh`),
  `terraform apply` configured `pki-clm-int` on the live cluster, imported a test
  CA (mode B) successfully, then `terraform destroy` (clean). TPM token step saved
  to memory (`/memories/hcp-vault-access.md`).

- **#44 Mode C renewal kit** — `internal/renewal.Generate` renders vault-agent
  HCL / AAP playbook to reissue+deploy a cert from a Vault PKI role;
  `GET /certificates/{id}/renewal-kit` + a cert-detail panel. CLM generates, the
  operator deploys, rescan+reconcile verifies. CN validated as a DNS hostname
  (review caught a HIGH template-injection risk). Merged via PR #45.

## In progress

- **Paused** (2026-07-06) pending user go-ahead. Direction confirmed below.

## Next (confirmed order)

1. **Hardening (first):**
   - Private-IP deny on the CRL/OCSP fetch — resolve host, reject loopback/
     link-local/RFC-1918 (closes residual blind-SSRF on the attacker-influenced
     CRL/OCSP URL from the scanned cert).
   - OCSP stapling capture at scan — read the server's stapled OCSP response
     during the existing TLS probe; populate revocation status automatically.
2. **Mode C full automation** — the IBM/HashiCorp/Red Hat "Eliminate Certificate
   Risk at Scale" solution brief closed loop (Vault issues/governs; **AAP**
   deploys/rotates/verifies; CLM = "monitor inventory + orchestrate + verify").
   Builds on the renewal kit (#44) — turn the generated AAP playbook into a
   **triggered** action:
   - `internal/aap` client (launch job template `/api/v2/job_templates/{id}/launch`
     + poll job status; mockable/httptest-tested);
   - **on-demand `POST /certificates/{id}/renew` + auto-policy** (renew when
     < N days to expiry);
   - closed-loop verify (rescan -> reconcile -> managed_in_vault).
   - **User HAS an AAP Controller** and will provide URL + token (like the HCP
     cluster) for end-to-end validation.
3. **v2 cloud CA sources** — read-only collectors for ACM / Azure Key Vault /
   GCP Certificate Manager into the same inventory (single pane; closes shadow-CA
   blind spot).

## HCP note
- `hcpvenv` alias token is stale/expired — do NOT use it. Mint fresh via TPM:
  `~/Documents/work-related/vault-related/mba-tpm-hcp-vault/auth-with-tpm.sh`
  then `source ~/.vault-tpm/vault-env.sh` (VAULT_NAMESPACE=admin). Pass to TF via
  `TF_VAR_vault_addr/vault_namespace/vault_token` env.

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
