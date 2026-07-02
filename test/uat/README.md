# UAT: Expiry & Validity Compliance Testing

This directory holds the manual/demo User Acceptance Testing (UAT) suite for
the SC-081 expiry and issued-validity compliance rules. It complements (does
not replace) the build-tagged Go integration test in `internal/uat/`.

Both exercise the **real** scanner → parser → governance → compliance
pipeline against **real TLS handshakes** — no mocked certificates or
stubbed compliance logic. The Go test does this in-process with
`httptest`-served self-signed certs; the docker-compose stack does it against
real HTTPS endpoints (nginx containers), including an opt-in real Let's
Encrypt staging certificate.

See the design spec for full rationale:
[docs/superpowers/specs/2026-07-02-uat-expiry-compliance-testing-design.md](../../docs/superpowers/specs/2026-07-02-uat-expiry-compliance-testing-design.md).

## Running the Go integration test

```bash
go test -tags uat ./internal/uat/...
```

This test is build-tagged (`//go:build uat`) so it is **excluded** from the
default `go test ./...` run. It also runs in CI as a separate step. It spins
up ten in-process HTTPS servers (one per matrix cert below), probes each with
the real scanner, and evaluates compliance both as-discovered (internal
scope) and prod-enriched (via a synthetic `environment=prod` certificate).

## Running the docker-compose UAT

The compose stack builds the real API image, a Postgres database, and one
nginx HTTPS endpoint per matrix cert, then a host-side driver script exercises
the API exactly as an operator would.

### Default profile — self-signed matrix

```bash
cd test/uat
docker compose -f docker-compose.uat.yml up -d --build
```

Then, **from the host** (not inside a container — the driver uses host
`curl` + `jq`):

```bash
API=http://localhost:8080 sh driver.sh
```

`gen-certs` mints the ten-certificate matrix (self-signed, exact
`NotBefore`/`NotAfter`) into `./certs/` before the endpoints start. Each
`uat-<id>` nginx service serves its matching `<id>.crt`/`<id>.key` on `:443`,
rendered from `nginx/endpoint.conf.template` via nginx's default `envsubst`
template suffix (`.template` → `/etc/nginx/conf.d/default.conf`).

**Important — hostnames vs. certificate CNs are intentionally different.**
The driver scans the Docker Compose **service names** (`uat-<id>`, e.g.
`uat-exp-14`), because that's what the app container's resolver can look up
via Docker's internal DNS from inside the compose network. But compliance
findings and stored certificates are keyed by the certificate's **Subject
CN**, which `gen-certs` sets to `<id>.uat.test` (e.g. `exp-14.uat.test`) —
not the service name. So the driver maps `id -> uat-<id>` for scanning and
`id -> <id>.uat.test` for matching findings/certs. If you're reading scan
output and wondering why the target hostname doesn't match the certificate's
CN, this is why — it's expected, not a bug.

The driver:
1. POSTs a scan for all ten `uat-<id>` service names on port 443.
2. Polls until the scan completes.
3. Asserts as-discovered (internal) severities and rule IDs per cert against
   the expected-results matrix below (all `info`, since these are
   self-signed).
4. PATCHes each cert with an expected prod severity to `environment=prod`,
   re-fetches compliance, and asserts full severity now applies.
5. Asserts the blind-spot endpoint reports `vault_managed=0` and
   `shadow>=1` (all matrix certs are self-signed, so they're all shadow).

### `--profile vault` — reachable-Vault validation

Validates that a reachable Vault with no matching PKI-issued certs still
correctly yields `vault_managed=0` (i.e., the app doesn't error out or
misclassify certs just because Vault is reachable).

```bash
cd test/uat
VAULT_ADDR=http://vault:8200 VAULT_TOKEN=root \
  docker compose -f docker-compose.uat.yml --profile vault up -d --build
```

This starts a `hashicorp/vault:1.17` dev-mode container alongside the
default stack. Because every UAT matrix cert is self-signed (not
Vault-issued), they remain classified as `shadow` even with Vault reachable
— this profile is not testing "certs move to vault_managed," it's testing
that a live Vault doesn't break shadow classification.

### `--profile letsencrypt` — real external certificate

Issues a real Let's Encrypt **staging** certificate via HTTP-01 and serves
it over HTTPS, to validate the pipeline against a genuine externally-issued
(non-self-signed) certificate.

Requires:
- A public domain you control, with DNS pointing at this host and port `:80`
  reachable from the internet (HTTP-01 challenge).
- A `test/uat/.env` file (gitignored — never commit real values) with real
  `ACME_EMAIL` and `LE_DOMAIN`, copied from the committed placeholder file:

```bash
cd test/uat
cp .env.example .env   # edit .env: set real ACME_EMAIL and LE_DOMAIN
docker compose -f docker-compose.uat.yml --profile letsencrypt up -d --build
```

This starts `lego` (issues the cert into `./le/`) and `uat-letsencrypt`
(nginx serving it, templated from `nginx/le.conf.template`). A freshly
issued LE cert is expected to produce **zero compliance findings** and
`cert_scope=external` — see intended behavior 2 below.

## Environment variables

| Variable | Where | Purpose |
|---|---|---|
| `VAULT_ADDR` | shell env, `--profile vault` | Vault address the `app` service passes through (`http://vault:8200`) |
| `VAULT_TOKEN` | shell env, `--profile vault` | Vault token the `app` service passes through (`root` in dev mode) |
| `ACME_EMAIL` | `test/uat/.env` (gitignored), `--profile letsencrypt` | ACME account email for Let's Encrypt staging |
| `LE_DOMAIN` | `test/uat/.env` (gitignored), `--profile letsencrypt` | Public domain to issue the staging cert for |

`test/uat/.env.example` documents these with placeholder values and is the
only version committed to the repo. Copy it to `test/uat/.env` (already
gitignored, along with `test/uat/certs/` and `test/uat/le/`) and fill in real
values before using `--profile letsencrypt`.

## Expected-results matrix

Ten certs are minted at fixed offsets from "now" (`gen-certs`, +12h buffer so
day-floor math lands cleanly). Each is evaluated **twice**: as-discovered
(no `environment` set → `cert_scope=internal` for self-signed certs) and
prod-enriched (`environment=prod`, via `PATCH /api/v1/certificates/{id}`).

| id | not_after | expiry finding | sev internal | sev prod | validity finding |
|---|---|---|---|---|---|
| `expired` | now − 1d | `sc081.expiry.expired` | info | critical | — |
| `exp-7` | now + 7d | `sc081.expiry.critical` | info | critical | — |
| `exp-14` | now + 14d | `sc081.expiry.critical` | info | critical | — |
| `exp-15` | now + 15d | `sc081.expiry.warning` | info | warning | — |
| `exp-30` | now + 30d | `sc081.expiry.warning` | info | warning | — |
| `exp-45` | now + 45d | `sc081.expiry.warning` | info | warning | — |
| `exp-60` | now + 60d | `sc081.expiry.warning` | info | warning | — |
| `exp-61` | now + 61d | none | — | — | — |
| `valid-99` | now + 99d | none | — | — | none (point-in-time: ≤ active ceiling) |
| `valid-400` | now + 400d | none | — | — | `sc081.validity.*` critical |

`sev internal` / `sev prod` are severities of the `sc081.expiry.*` finding
under each evaluation. `internal` severities are **always `info`** for these
self-signed certs, regardless of how close to expiry — see intended behavior
1 below. `validity finding` is independent of `environment`/scope (see
intended behavior 4).

## Intended behaviors (read this before triaging a FAIL)

A `FAIL` line from `driver.sh`, or a failing `go test -tags uat`, is a
**real finding** — it means the pipeline's actual behavior diverged from
this table. Before treating it as a regression, check it against these four
intended behaviors, since some outcomes are counter-intuitive by design:

1. **Self-signed → internal scope → expiry findings are `info` and are NOT
   counted in `SC081ViolationCount`, by design.** An as-discovered
   self-signed cert 3 days from expiry still reports `sc081.expiry.critical`
   at severity `info` and contributes `0` to the violation count. This is
   intentional: internal-scope certs are informational until an operator
   confirms production relevance (via `environment=prod`), at which point
   the same rule reports full severity and counts toward violations.
2. **A fresh Let's Encrypt certificate yields zero findings and
   `cert_scope=external`.** The `--profile letsencrypt` lane is the positive
   control: a genuinely externally-issued, long-lived-enough, currently
   valid certificate should produce no compliance findings at all.
3. **`exp-14` and `exp-60` fall on the inclusive side of the ≤14 / ≤60 day
   thresholds** — both are `sc081.expiry.critical`/`.warning` respectively,
   not `none`. The boundary certs one day later (`exp-15` moves from
   critical to warning; `exp-61` has no finding) confirm the thresholds are
   `<=`, not `<`.
4. **Issued-validity and time-to-expiry are independent dimensions.**
   `valid-400` (400-day total validity period) is a validity violation
   (`sc081.validity.*`, critical) with **no** expiry finding at all — it's
   not close to expiring, but its total issued lifetime exceeds policy. The
   two rule families never proxy for each other.

Additionally: `valid-99`'s validity outcome is **point-in-time** — whether a
99-day-validity cert is flagged depends on the active maximum-validity
ceiling, which tightens over time per the CA/Browser Forum schedule. The Go
integration test intentionally does not assert an outcome for `valid-99`'s
validity dimension; it only asserts the robust, schedule-independent case
(`valid-400`, which exceeds every ceiling in the phase-in schedule).
