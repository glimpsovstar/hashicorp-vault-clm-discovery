## Problem

Vault, AAP Controller, and the EDA webhook are configured only via env (`VAULT_ADDR`/`VAULT_TOKEN`, `AAP_*`, `EDA_*`). The dashboard tells operators to edit compose/README. There is no Settings UI, no connection test, and no way to persist credentials without a restart. Operators cannot tell whether HCP Dedicated vs self-managed Vault, Controller, or EDA actually work until reconcile/renew/dispatch fails.

## Proposed solution

Add a **Connections** settings page and API (`GET`/`PUT`/`PATCH /api/v1/settings/connections`, `POST .../test` with `{target: vault|aap|eda}`).

Three integrations: **Vault** (token + AppRole; HCP vs self-managed is UX only), **AAP Controller** (OAuth2 bearer; test = `GET /api/v2/me` + template-by-name, **must not launch a job**), **EDA webhook** (signed ping, expect 2xx; no message bus).

Connection metadata in Postgres; secrets encrypted at rest (`CLM_CONNECTIONS_KEY`) or env as overlay/fallback. Env remains the 12-factor Compose default; UI writes override that deployment. Secrets never returned to the browser (masked; write-only on PATCH). Next BFF attaches `Authorization`; no `NEXT_PUBLIC` tokens.

**M1 #79:** AppRole client is implemented in M1; Settings consumes it. If M1 is unmerged, Settings mutations must refuse unless `CLM_INSECURE_NO_AUTH` (UAT).

## Acceptance criteria

- [ ] `GET /api/v1/settings/connections` never includes token / role_id / secret_id / AAP token / EDA token values.
- [ ] PATCH omitting a secret leaves the stored value unchanged; subsequent Test still succeeds.
- [ ] Vault Test: token probe and AppRole login+probe via httptest; token method still works.
- [ ] AAP Test: `/api/v2/me` + resolve template by name; **no** job launch.
- [ ] EDA Test: signed ping (`clm.connection.test`), 2xx; no outbox insert; no NATS/Kafka.
- [ ] Unauthenticated Settings GET/PUT/Test → 401 (or refuse unless `CLM_INSECURE_NO_AUTH` if M1 not merged).
- [ ] `remediator` GET (masked) only; `platform_admin` PUT/PATCH/Test.
- [ ] Env-only Compose works with no `connections` rows and no `CLM_CONNECTIONS_KEY`.
- [ ] UI save without `CLM_CONNECTIONS_KEY` → 503; no plaintext secrets in Postgres.
- [ ] README / architecture / data-model / demo-flow document overlay vs env; UI replaces “set VAULT_ADDR in README” as the only path.

## Test plan

- [ ] `go test ./...` and `go build ./...`
- [ ] `cd web && npm ci && npm test && npm run build`
- [ ] httptest: Vault token + AppRole; AAP me+template with zero `/launch`; EDA ping 2xx
- [ ] Confirm GET JSON has `token_set` / `*_set` flags only
- [ ] UAT/Compose still boot from env without Settings rows

## Superpowers spec

`docs/superpowers/specs/2026-08-13-connections-settings-design.md`

Plan: `docs/superpowers/plans/2026-08-13-connections-settings.md`

Depends on: M1 [#79](https://github.com/glimpsovstar/hashicorp-vault-clm-discovery/issues/79). Parent: GCM closed-loop umbrella.

## Out of scope

Userpass / LDAP / JWT / AWS / cert / Kubernetes Vault auth, OIDC login UI, second Vault import-identity card, NATS/Kafka, ITSM, cloud collectors, Vault plugin, private keys in CLM, launching AAP jobs from Test, general (non-connection) preferences.
