# UAT & Integration Testing: certificate expiry / validity compliance

**Date:** 2026-07-02
**Status:** Design (approved for planning)
**Related:** SC-081 compliance pack ([2026-06-30-compliance-standards-packs-design.md](2026-06-30-compliance-standards-packs-design.md)), blind-spot reveal ([2026-06-30-blind-spot-reveal-design.md](2026-06-30-blind-spot-reveal-design.md))

## Motivation

Current SC-081 tests feed `compliance.CertInput` **directly** into the evaluator. Nothing exercises the real end-to-end path a live certificate travels:

```text
TLS endpoint → scanner probe → cert.ParseCertificate → store.Certificate
            → lifecycle.Compute + governance.ClassifyScope → EvaluateSC081 → blind-spot / report
```

We need tests that mint certificates with controlled validity windows, serve them over real HTTPS, scan them, and assert the app's reaction — both to guard against regressions and to **confirm the observed behavior is intended** (the core UAT question). Two behaviors in particular are surprising-but-intended and must be demonstrated explicitly, not assumed.

## Background: two independent SC-081 time dimensions

The proposed windows conflate two distinct rules; the design keeps them separate.

- **Time-to-expiry** — how far `not_after` is from *now*. Drives `sc081.expiry.*`:
  `expired` (past) · `critical` (≤14d) · `warning` (≤60d) · none (>60d).
  Evaluated **live** against `not_after` at request time.
- **Issued validity** — `not_after − not_before` (the certificate's total lifetime). Drives `sc081.validity.*` against ceilings phased in by issuance date: **199d** (from 2026-03-15), 99d (2027-03-15), 64d (2028-03-15), 47d (2029-03-15).

`not_before` and `not_after` are set **independently** so both dimensions are covered.

### Scope → severity downgrade (intended, must be demonstrated)

`governance.ClassifyScope` tags self-signed chains as **`internal`**. `sc081ExpirySeverity` downgrades an internal, non-prod expiry finding to **`info`**, and `info` findings are **excluded** from `SC081ViolationCount`. Therefore a self-signed cert expiring tomorrow surfaces as an `info` finding that does **not** count as a violation. This is intended; the UAT proves it and documents it.

To exercise full `critical`/`warning` severity without a public CA, a discovered cert is **enriched to `environment=prod`** via the existing `PATCH /api/v1/certificates/{id}` — the downgrade condition is `internal && !prod`, so a prod internal cert keeps full severity. Every self-signed scenario is therefore asserted **twice**: as-discovered (internal → `info`, not counted) and prod-enriched (full severity, counted).

## Goals

- G1. Prove the real scan→parse→compliance pipeline produces the correct SC-081 findings for every expiry window and for the issued-validity ceiling.
- G2. Exercise and document the boundary conditions: `≤14` critical, `≤60` warning, already-expired, and issued-validity over/under the active ceiling.
- G3. Prove the internal→`info`→not-counted downgrade, and the prod-enriched → full-severity → counted path.
- G4. Prove self-signed (Vault-unmatched) certs surface as **shadow certs** in the blind-spot summary.
- G5. Provide a deterministic, CI-runnable regression test **and** a realistic, demo-able manual UAT.
- G6. Optionally validate the real external-CA path via Let's Encrypt (staging).

## Non-goals (YAGNI)

- No Let's Encrypt **production** issuance.
- No attempt to force controlled expiry on Let's Encrypt certs (LE is fixed at 90 days).
- No assertions on PCI / crypto packs beyond what incidentally appears.
- No external-network dependency in the default `go test ./...` run.

## Scenario matrix

Self-signed certs, `not_before = now` unless noted. Each row is asserted **as internal (default)** and **as prod-enriched**. Validity expectations are derived from the **active ceiling at run time** (199d today) so the matrix does not rot as ceilings phase in.

| id | not_before | not_after | expiry finding | sev (internal) | sev (prod) | validity finding | counts as violation (prod) |
|----|-----------|-----------|----------------|----------------|-----------|------------------|----------------------------|
| expired    | now−30d | now−1d  | `expiry.expired`  | info | critical | — | yes |
| exp-7      | now | now+7d  | `expiry.critical` | info | critical | — | yes |
| exp-14     | now | now+14d | `expiry.critical` (≤14 boundary) | info | critical | — | yes |
| exp-15     | now | now+15d | `expiry.warning`  | info | warning  | — | yes |
| exp-30     | now | now+30d | `expiry.warning`  | info | warning  | — | yes |
| exp-45     | now | now+45d | `expiry.warning`  | info | warning  | — | yes |
| exp-60     | now | now+60d | `expiry.warning` (≤60 boundary) | info | warning | — | yes |
| exp-61     | now | now+61d | none | — | — | — | no |
| valid-99   | now | now+99d | none | — | — | none (99d ≤ active ceiling) | no |
| valid-400  | now | now+400d | none | — | — | `validity.<ceiling>` (critical) | yes |

Notes:
- `valid-400` flags a **validity** violation (issued lifetime exceeds the ceiling) while having **no expiry** finding — the key demonstration that the two dimensions are independent.
- All self-signed certs are Vault-unmatched → each must appear in `blindspot.shadow` and none in `vault_managed`.

### Let's Encrypt lane (optional, external)

| id | issuance | not_after | scope | expiry finding | validity finding |
|----|----------|-----------|-------|----------------|------------------|
| le-staging | now (ACME) | now+90d | **external** | none (90 > 60) | none (90 < ceiling) |

A fresh LE staging cert is compliant and classified `external` **without** enrichment. Its assertions: `cert_scope == external`, parses cleanly, produces **no false findings**. It cannot demonstrate critical/warning (expiry is not controllable) — that remains the self-signed lane's job.

## Deliverable 1 — Go integration test (CI regression guard)

- **Location:** `internal/uat/` package (new), file gated with `//go:build uat`.
- **Run:** `go test -tags uat ./internal/uat/...` — excluded from the default `go test ./...`.
- **Mechanism:** for each matrix row, generate an in-memory cert (`crypto/x509`) with the specified `not_before`/`not_after`, serve it from an in-process `tls`/`httptest` server on `127.0.0.1`, drive the **real prober** to fetch and parse it, then run the **real** `lifecycle.Compute`, `governance.ClassifyScope`, and `compliance.EvaluateSC081`/`EvaluateCerts`.
- **Assertions per row:** parsed `NotAfter` matches; expiry rule id + severity match (internal); after setting `Environment=prod`, severity matches (prod); validity rule matches the active ceiling; `SC081ViolationCount` counts only non-`info` findings.
- **No DB, no network egress** — deterministic and fast; safe to add as a dedicated CI step.
- **Anti-rot:** validity expectations computed from the active ceiling for `time.Now()`, not hardcoded rule ids.

## Deliverable 2 — docker-compose UAT (manual, realistic, demo-able)

- **Location:** `test/uat/`.
- **Base services:** `postgres`, `clm-discovery` (app), and N `nginx` HTTPS endpoints (one port per self-signed matrix cert).
- **Cert generation:** `test/uat/gen-certs.sh` mints the matrix certs with controlled dates (openssl) into a shared volume before the endpoints start.
- **Compose profiles:**
  - default — self-signed matrix only (all shadow certs).
  - `vault` — adds a Vault dev server; a subset of certs are issued/imported so the run also demonstrates **managed vs shadow**.
  - `letsencrypt` — adds a `lego` sidecar that obtains an **LE staging** cert (requires `ACME_EMAIL` + a domain you control) and serves it as an external endpoint.
- **Driver:** `test/uat/driver.sh` (bash + curl + jq):
  1. wait for `/api/v1/health`;
  2. `POST /api/v1/scans` with the endpoints + `consent=true`; poll until `completed`;
  3. fetch `/api/v1/scans/{id}/compliance` and `/blindspot`; assert every matrix cell;
  4. `PATCH` the expiry certs to `environment=prod`; re-fetch; assert full-severity + violation counts;
  5. exit non-zero on any mismatch, printing an expected-vs-actual table.
- **Secrets:** `ACME_EMAIL` env var; `test/uat/.env.example` committed with `you@example.com`; the real value (e.g. the maintainer's ACME account email) lives only in a **gitignored `test/uat/.env`**, documented in `test/uat/README.md`.

## Intended behaviors this UAT will surface and document

1. Self-signed (internal, non-prod) expiry findings are `info` and **do not** count as SC-081 violations — by design.
2. A fresh Let's Encrypt cert yields **zero** findings (compliant) and `cert_scope == external`.
3. `exp-14` and `exp-60` fall on the inclusive side of their thresholds (`≤14`, `≤60`).
4. Issued-validity and time-to-expiry are independent: `valid-400` is a validity violation with no expiry finding.

Each is stated in `test/uat/README.md` as **expected**, so a mismatch means a real bug, not confusion.

## Success criteria

- `go test -tags uat ./internal/uat/...` passes; every matrix row asserted in both scope modes.
- `docker compose -f test/uat/docker-compose.uat.yml up` + `driver.sh` exits 0 with the full matrix matching; `--profile vault` shows managed vs shadow; `--profile letsencrypt` (with a domain) shows an external compliant cert.
- No regression to the default `go test ./...` / `web` suites.

## SDLC process (per CONTRIBUTING.md)

This work follows the repo's SDLC workflow:

1. **Design** — this spec (Superpowers `brainstorming` gate). ✅
2. **Plan** — `docs/superpowers/plans/2026-07-02-uat-expiry-compliance-testing.md` (Superpowers `writing-plans`).
3. **Branch** — `feat/uat-expiry-compliance-testing` from `main`.
4. **Implement (TDD)** — the Go integration test is written test-first per row; `driver.sh` assertions are authored before wiring the compose services.
5. **Docs** — update `CONTRIBUTING.md` (add the `-tags uat` and docker-compose UAT verification commands), `docs/architecture.md` (testing tiers), and add `test/uat/README.md`.
6. **Verify** — `go test ./...`, `go test -tags uat ./internal/uat/...`, `go build ./...`, `cd web && npm run build`, and a docker-compose UAT smoke run.
7. **PR** — against `main` with the matrix results; adversarial code review (incl. Fable pass) before merge.
8. **Merge** — squash to `main`.

### Documentation deliverables

- `test/uat/README.md` — how to run each profile, env vars (incl. `ACME_EMAIL`), and the expected-results matrix with the four intended behaviors above.
- `CONTRIBUTING.md` — add UAT/integration verification commands to the existing verification list.
- `docs/architecture.md` — a short "Testing tiers" note (unit → `-tags uat` integration → docker-compose UAT).

## File layout

```text
docs/superpowers/specs/2026-07-02-uat-expiry-compliance-testing-design.md   # this doc
docs/superpowers/plans/2026-07-02-uat-expiry-compliance-testing.md          # writing-plans output
internal/uat/expiry_compliance_uat_test.go                                  # //go:build uat
test/uat/
  README.md
  docker-compose.uat.yml
  gen-certs.sh
  driver.sh
  .env.example            # committed placeholders (you@example.com)
  nginx/                   # per-endpoint TLS server config
.gitignore                 # add test/uat/.env
```

## Risks / constraints

- **LE requires a public domain + reachable ACME challenge** and is rate-limited → `letsencrypt` profile is opt-in and off by default; the default UAT and all CI run without it.
- **LE expiry is fixed at 90 days** → LE validates the external path only, never the expiry matrix.
- **Ceiling phase-in** → validity expectations are computed from the active ceiling at run time to avoid date-rot.
- **Personal email** must never be committed → enforced via gitignored `.env` + placeholder in `.env.example`.
