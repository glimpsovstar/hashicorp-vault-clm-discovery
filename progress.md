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

- **#68 report viewer + in-report actions** — view-first `/scans/{id}/report` page
  (summary, insights, recommendations) in the Vault UI, with a Download menu
  (md/csv/json) and inline import actions (Track in CLM per shadow cert, Import CA
  to Vault per issuer). Blind-spot card: "Reconcile with Vault" → "Show shadow certs"
  and three download buttons → one "View report" link; reusable `?` HelpPopover.
  Frontend-only (`web/`); selection logic extracted to `web/lib/report.ts` (tested).
  Subagent code review (no correctness bugs). Docker-compose smoke validated
  end-to-end. Merged via PR #70. Also **#67**: README refreshed to current feature
  set (PR #69).
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
- **#46 private-IP deny (blind-SSRF guard)** — `revocation.NewFetchClient()` adds
  a `net.Dialer.Control` hook that refuses non-public dial addresses (loopback,
  unspecified, link-local incl. `169.254.169.254`, RFC-1918/ULA, RFC-6598 CGNAT),
  checked post-DNS so DNS-rebinding is blocked; shared by CRL + OCSP and the API
  `revCheck`. Redirects disabled, no egress proxy (documented). Merged via PR #47
  (sub-agent security review: no blockers; CGNAT gap + doc notes fixed).
- **#48 stapled OCSP capture at scan** — `revocation.ParseStapledOCSP` (pure, no
  network; fails closed — requires `leaf.CheckSignatureFrom(issuer)` since the
  scanned chain is untrusted, then verifies the staple signature). Scanner reads
  `tls.ConnectionState.OCSPResponse`; runner auto-persists via
  `MarkRevoked(id, "ocsp_stapled")` only when verified-revoked. `UpsertCertificate`
  now preserves any `revoked_via_*` status across rescans. Merged via PR #49
  (sub-agent review: both MAJOR findings — leaf↔issuer binding + durable-revoked
  CASE — fixed pre-merge).

## In progress

- **Report / blind-spot UI polish (post-#68).**
  - **#71 — blind-spot tile help** (branch `fix/71-blind-spot-tile-help`): moved the
    `?` HelpPopovers off the "Show shadow certs" / "View report" controls onto the
    **On wire**, **Shadow certs**, **SC-081 violations** metric tiles (the affordances
    that actually need explaining). Test-first (`blind-spot-card.test.tsx`); UI-only.
    Spec + plan under `docs/superpowers/`. Pending subagent review → PR.
  - **#73 — report redesign (Vault Radar style)** (branch `feature/73-report-redesign`):
    rebuilt `/scans/{id}/report` as a severity overview + Vault-coverage meter + one
    filterable findings table (severity + kind filters, search) + per-row drill-in,
    replacing the four flat panels. Normalizer extracted to tested
    `web/lib/findings.ts` (folds insights + shadow certs + CA issuers into one
    `Finding[]`); client `report-explorer.tsx`; thin server page. Reuses the existing
    Track-in-CLM / Import-CA actions. Light-theme only. Test-first (findings 12,
    explorer 5; suite 36/36); tsc + web build green. Severity thresholds hard-coded
    for v1 — follow-up filed to make them configurable. Phase 1 of the shared
    inventory visual language (phases 2–3 = blind-spot card + inventory table).
    Pending subagent review → PR.

- **Item 2 — Mode C full automation (Vault + AAP closed loop).**
  - ~~PR 1 — `internal/aap` client~~ — DONE (#50 / PR #51): dynamic template
    discovery by name, launch with extra_vars, status normalization, WaitForJob
    with transient-failure tolerance. httptest-covered.
  - ~~PR 2 — `POST /certificates/{id}/renew`~~ — DONE (#52 / PR #53): consent-gated
    endpoint resolves the AAP template by name and launches it with extra_vars
    (CN/mount/role/service/target_hosts/ttl/alt_names). All values validated
    (CN DNS host; ttl/alt_names SSTI-guarded). `renewLauncher` seam + config.
  - ~~PR 3a — persist per-cert renewal config~~ — DONE (#54 / PR #55): migration
    000005 `renewal_config JSONB`, `store.SetRenewalConfig`, optional `renewal`
    object on catalog-import. Survives rescans. Feeds the AAP dynamic inventory.
  - ~~PR 3b — `POST /renew-expiring` batch auto-renewal~~ — DONE (#58 / PR #60):
    `store.ListRenewable` + consent-gated batch endpoint (defaults to
    EXPIRING_SOON_DAYS), one shared `launchRenewal`/`validateRenewalLaunch` path
    with the on-demand renew. Closed-loop verify = existing rescan+reconcile.
  - ~~AAP dynamic-inventory endpoint~~ — DONE (#61 / PR #62): `internal/inventory`
    renders the Ansible `--list` JSON (host=CN, issue-role hostvars + clm_* meta,
    `ansible_connection: local`, `clm_renewable`/`svc_*` groups); `GET /inventory`
    from `store.ListRenewable` with `?within_days=N`.
  - ~~Event outbox Phase 1a~~ — DONE (#63 / PR #64): migration 000006 `events`
    table, `store.Event`, transactional `MarkRevoked` emits `cert.revoked` in the
    same tx, `GET /events`.
  - ~~Event dispatcher Phase 1b~~ — DONE (#65 / PR #66): `internal/eventbus`
    delivers outbox events to an Ansible EDA webhook (at-least-once, dead-letter
    after N attempts), gated by `EDA_WEBHOOK_URL`, drained on shutdown.
  - **Event Phase 1 COMPLETE.** Phase 2 (message bus) deferred until a 2nd consumer.
  - AAP contract captured in memory (repo/clm-discovery.md); creds live on the
    user's Mac (TF-deployed AAP), never committed.

- **Architecture decided (ADR 0001)** — source of truth + event-driven design.
  See [docs/adr/0001-source-of-truth-and-event-driven-automation.md](docs/adr/0001-source-of-truth-and-event-driven-automation.md).
  - **CLM = inventory system of record** (managed + shadow + governance +
    renewal config); **Vault = issuance/trust SoR**. Works on HCP and TFE/
    self-managed (no dependence on the HCP-only cert dashboard).
  - **AAP builds dynamic inventory from a read-only CLM REST endpoint** (pulls),
    fed by `renewal_config` — not by querying Vault directly.
  - **Events via a transactional outbox.** Phase 1 transport = Ansible EDA
    webhook (no bus). Phase 2 = message bus (NATS/Kafka) when a 2nd consumer
    appears. Outbox + EDA is the reactive path; `POST /renew-expiring` is the
    batch path; both share one internal "launch renewal" service.

## Next (confirmed order)

1. **Hardening (first):**
   - ~~Private-IP deny on the CRL/OCSP fetch~~ — DONE (#46 / PR #47).
   - ~~OCSP stapling capture at scan~~ — DONE (#48 / PR #49).
2. **Mode C full automation** (Vault issues/governs; **AAP** deploys/rotates/
   verifies; CLM = monitor + orchestrate + verify):
   - ~~AAP client~~ (#50), ~~renew endpoint~~ (#52), ~~renewal-config persistence~~ (#54).
   - ~~`POST /renew-expiring` batch auto-renewal~~ (#58).
   - ~~AAP dynamic-inventory endpoint~~ (#61).
   - ~~Transactional outbox~~ (#63) + ~~Ansible EDA webhook dispatcher~~ (#65) — event Phase 1 DONE.
   - **Message bus transport** (event Phase 2; ADR 0001) — deferred until a 2nd consumer exists.
   - **Live validation** against the user's real AAP Controller + EDA webhook —
     user provides URL + token (like the HCP cluster); pending.
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
