# Connections (Settings) — design

**Status:** Approved  
**Date:** 2026-08-13  
**Parent:** [GCM closed-loop roadmap](2026-08-13-gcm-closed-loop-roadmap-design.md)  
**Depends on:** [M1 #79](https://github.com/glimpsovstar/hashicorp-vault-clm-discovery/issues/79) — [control-plane security](2026-08-13-m1-control-plane-security-design.md)  
**Plan:** [2026-08-13-connections-settings.md](../plans/2026-08-13-connections-settings.md)  
**Issue:** [connections-settings.md](../issues/connections-settings.md)

---

## Problem

Vault, AAP, and EDA are configured only via env (`VAULT_ADDR`/`VAULT_TOKEN`, `AAP_*`, `EDA_*`). The dashboard tells operators to edit compose/README. There is no Settings UI, no connection test, and no way to persist credentials without restarting the process. `VAULT_AUTH_METHOD=approle` is documented but unimplemented in this repo (M1 owns the client; this feature consumes it).

Operators cannot tell whether HCP Dedicated vs self-managed Vault, Controller, or the EDA webhook actually work until a reconcile, renew, or dispatch fails.

## Goal

Ship a **Connections** settings page with three tested integrations: **Vault**, **AAP Controller**, **EDA webhook**. Secrets never reach the browser. Env remains the 12-factor Compose default; UI writes overlay that deployment. Test calls are server-side and must not launch AAP jobs or enqueue outbox events.

## Locked decisions

- CLM is **not** a Vault plugin. AAP is the only deploy plane. No private keys in CLM. No NATS/Kafka (EDA stays HTTP webhook).
- Settings v1 is **Connections only** (not a general preferences dump).
- Vault: one HTTP client. **HCP Dedicated vs self-managed is UX only** (labels, `namespace=admin` preset, cluster URL help). Same Vault API.
- Vault auth v1 = **token** (already works) + **AppRole** (`role_id` + `secret_id`, login + renew). Userpass / LDAP / JWT / AWS / cert / Kubernetes are out of scope.
- AAP auth v1 = OAuth2 bearer (`AAP_TOKEN`) only.
- Persistence: connection **metadata** in Postgres; **secret material** encrypted at rest with a server-side key (`CLM_CONNECTIONS_KEY` or equivalent) **or** keep env as overlay/fallback.
- GET requires `platform_admin` (or `remediator` read-only, no secrets). PUT/PATCH + Test are privileged mutations.
- Next.js BFF attaches `Authorization`; no `NEXT_PUBLIC` tokens.

## Relationship to M1 #79

| Concern | Owner |
|---------|--------|
| AuthN/Z, RBAC, `audit_events`, default-deny except health | **M1** |
| Vault AppRole login + token cache/renew (`VAULT_ROLE_ID` / `VAULT_SECRET_ID`) | **M1 implements the client** |
| Connections API, encrypted store, Test endpoints, Settings UI | **This feature** |
| Settings UI AppRole fields | Consumes M1’s AppRole client; does not reimplement login |

If M1 is not merged when this ships:

1. Settings API **must not be world-writable**. Refuse PUT/PATCH/Test unless `CLM_INSECURE_NO_AUTH=true` (UAT only) — same escape hatch as M1.
2. AppRole client may be implemented in this change **only if** M1 has not landed it (see plan Task 2). Prefer merging M1 first.

Split read vs import Vault identities remain an M1 concern. Connections v1 stores **one** Vault connection (the reconcile/read identity). Import-identity split is not a second Settings card.

## Data model

Next unused migration at implement time (do not assume `000007`). One row per integration target.

```sql
CREATE TABLE connections (
    target          TEXT PRIMARY KEY CHECK (target IN ('vault', 'aap', 'eda')),
    metadata        JSONB NOT NULL DEFAULT '{}',
    secrets_enc     BYTEA,                 -- nil when secrets come from env only
    secrets_set     BOOLEAN NOT NULL DEFAULT FALSE,
    source          TEXT NOT NULL DEFAULT 'env' CHECK (source IN ('env', 'db')),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by      TEXT
);
```

`metadata` (never contains secrets):

| Target | Fields |
|--------|--------|
| `vault` | `deployment` (`hcp_dedicated` \| `self_managed`), `addr`, `namespace`, `auth_method` (`token` \| `approle`) |
| `aap` | `url`, `renew_template`, `renew_workflow` (bool), `skip_tls_verify` (bool), `default_mount` |
| `eda` | `webhook_url` |

`secrets_enc` is AES-256-GCM (or equivalent AEAD) under `CLM_CONNECTIONS_KEY`. Plaintext JSON, never logged:

| Target | Secret keys |
|--------|-------------|
| `vault` | `token` and/or `role_id`, `secret_id` |
| `aap` | `token` |
| `eda` | `token` |

### Resolution (env overlay)

1. **Compose / 12-factor default:** `internal/config` env (`VAULT_*`, `AAP_*`, `EDA_*`) is the live config when no DB row exists or `source=env`.
2. **UI save:** upsert the row, encrypt secrets, set `source=db`. That deployment then **overrides** env for that target.
3. **PATCH write-only secrets:** omitted or empty secret fields mean **keep stored value**. Never echo secrets back. Clearing a secret is an explicit `"token": null` (or equivalent) so operators can fall back to env.
4. **Missing `CLM_CONNECTIONS_KEY`:** env-only mode still works. PUT/PATCH that would persist secrets → **503** with a clear error. Do not store plaintext secrets in Postgres.

Runtime clients (`internal/vault`, `internal/aap`, `internal/eventbus`) read the **resolved** connection, not raw env alone.

## API

All under `/api/v1/settings/connections`. Next BFF proxies with `Authorization`; the browser never calls `:8080` with tokens in `NEXT_PUBLIC_*`.

### `GET /api/v1/settings/connections`

Auth: `platform_admin` or `remediator`.

Returns **masked** view. Secrets never appear. Example:

```json
{
  "vault": {
    "configured": true,
    "source": "env",
    "deployment": "self_managed",
    "addr": "https://vault.example.com:8200",
    "namespace": "",
    "auth_method": "token",
    "token_set": true,
    "role_id_set": false,
    "secret_id_set": false
  },
  "aap": {
    "configured": false,
    "source": "env",
    "url": "",
    "renew_template": "CLM - Issue Certificate",
    "renew_workflow": false,
    "skip_tls_verify": false,
    "default_mount": "pki",
    "token_set": false
  },
  "eda": {
    "configured": false,
    "source": "env",
    "webhook_url": "",
    "token_set": false
  }
}
```

`configured` is true when the resolved client would report `Configured()` (addr/url present). `*_set` flags only.

### `PUT /api/v1/settings/connections`

Auth: `platform_admin`. Replaces all three targets’ metadata; secrets follow write-only rules. Invalid `auth_method` / `deployment` / `target` → 400.

### `PATCH /api/v1/settings/connections`

Auth: `platform_admin`. Partial update (one or more targets). Same write-only secret rule.

### `POST /api/v1/settings/connections/test`

Auth: `platform_admin`. Body:

```json
{ "target": "vault" }
```

`target` is `vault` | `aap` | `eda`. Uses **resolved** (DB overlay else env) credentials on the **server**. Never accept a secret in the test body (that would leak via logs/BFF). Response:

```json
{ "ok": true, "target": "vault", "detail": "sys/health 200; namespace=admin" }
```

Failure: `ok: false` plus a **non-secret** detail (status code, “template not found”). 4xx for bad `target`; 401/403 per M1; 503 if the target is not configured.

Audit (when M1 `audit_events` exists): write on PUT/PATCH/Test (success and deny). Never log tokens, `secret_id`, or PEM.

## Test assertions

Server-side only. httptest the peer; do not hit production.

| Target | Probe | Must not |
|--------|--------|----------|
| **Vault** | `token`: `GET /v1/sys/health` (or `sys/mounts`) with `X-Vault-Token` (+ `X-Vault-Namespace` when set). `approle`: login `POST /v1/auth/approle/login` then same health/mounts call with the returned client token. | Persist the AppRole-derived token in the Connections row (cache lives in the Vault client, per M1). |
| **AAP** | `GET /api/v2/me` with `Authorization: Bearer`. Then resolve `AAP_RENEW_TEMPLATE` by name (`FindJobTemplate` or `FindWorkflowJobTemplate` when `renew_workflow`). | **Launch a job.** No `POST .../launch`. |
| **EDA** | Signed ping: `POST` the webhook URL with the **same auth as** `eventbus.Dispatcher` (`Authorization: Bearer` when token set) and body `{"event_type":"clm.connection.test","id":"<uuid>","created_at":"<rfc3339>"}`. Success = **2xx**. | Write the `events` outbox or start the dispatcher. No NATS/Kafka. |

HCP vs self-managed does not change probes — only default namespace (`admin` for HCP) and help text.

## Security

- Secrets **never** returned to the browser. Masked after save; write-only on PATCH.
- Encrypt-at-rest key is server-side only (`CLM_CONNECTIONS_KEY`). Not in Next.js env.
- Test handlers run in the Go API. Next.js must not receive or forward peer secrets.
- If M1 middleware is present: unauthenticated GET/PUT/Test → 401; `viewer` / `scanner_operator` → 403; `remediator` GET 200 (no secrets), PUT/Test 403.
- If M1 is absent: Settings mutations **refuse** unless `CLM_INSECURE_NO_AUTH` (UAT). Do not ship a world-writable Settings API.
- `AAP_SKIP_TLS_VERIFY` remains lab-only; UI must label it as such.
- Never log `VAULT_TOKEN`, `VAULT_SECRET_ID`, `AAP_TOKEN`, `EDA_WEBHOOK_TOKEN`, or decrypted `secrets_enc`.

## UI

New sidebar item **Settings** → **Connections** (`/settings/connections`). Three cards (Vault, AAP Controller, EDA webhook).

- Vault: toggle HCP Dedicated / self-managed; HCP presets `namespace=admin` and cluster-URL help (HCP portal vs `https://<cluster>:8200`). Auth method select: token | AppRole. Password inputs for secrets; after save show “configured” not the value.
- AAP: maps existing env labels (`AAP_URL`, token, template name, workflow checkbox, skip TLS, default mount).
- EDA: webhook URL + token. Copy: HTTP webhook only; no message bus.
- Each card: **Save** and **Test connection**. Test result is the API `detail` string. Failure must not expose secrets.
- Replace README / `reconcile-button` / `blind-spot-card` copy that tells operators to set `VAULT_ADDR`/`VAULT_TOKEN` in env as the only path — point at Settings (env remains valid for Compose).

Use **shadcn/ui** for this page (Card, Input, Button, Select, Checkbox) composed with the existing `app-shell` / sidebar. Do not restyle the whole dashboard.

## Acceptance criteria

- [ ] `GET /api/v1/settings/connections` never includes token / role_id / secret_id / AAP token / EDA token values.
- [ ] PATCH omitting `token` leaves the stored secret unchanged; subsequent Test still succeeds.
- [ ] Vault Test with token: httptest health/mounts 200 → `{ok:true}`.
- [ ] Vault Test with AppRole: httptest login then authenticated probe; token method still works.
- [ ] AAP Test calls `/api/v2/me` and template-by-name; **zero** launch requests recorded by httptest.
- [ ] EDA Test POSTs a `clm.connection.test` ping, expects 2xx, does not insert into `events`.
- [ ] Unauthenticated Settings GET/PUT/Test → 401 (or refuse unless `CLM_INSECURE_NO_AUTH` if M1 not merged).
- [ ] `remediator` can GET (masked) but not PUT/Test; `platform_admin` can both.
- [ ] Env-only Compose still works with no `connections` rows and no `CLM_CONNECTIONS_KEY`.
- [ ] UI save without `CLM_CONNECTIONS_KEY` → 503, no plaintext in Postgres.
- [ ] README / architecture / data-model / demo-flow document overlay vs env and authorized scanning unchanged.
- [ ] `go test ./...`, `go build ./...`, `cd web && npm ci && npm test && npm run build`.

## Out of scope

Userpass / LDAP / JWT / AWS / cert / Kubernetes Vault auth; OIDC login UI; second Vault import-identity card; NATS/Kafka; ITSM; cloud CA collectors; Vault plugin; storing private keys; launching AAP jobs from Test; general (non-connection) user preferences.
