# Connections Settings — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a Connections settings page and API so operators can configure and test Vault, AAP Controller, and the EDA webhook without putting secrets in the browser or launching jobs.

**Architecture:** Postgres `connections` rows hold non-secret metadata; secret material is AEAD-encrypted with `CLM_CONNECTIONS_KEY`. Env (`VAULT_*` / `AAP_*` / `EDA_*`) remains the 12-factor default; a UI save overlays env for that target. Test handlers run in the Go API (httptest in unit tests). Next BFF attaches `Authorization`. Vault AppRole is consumed from M1; implement the client here only if M1 has not landed it.

**Tech Stack:** Go chi + pgx, existing `internal/vault` / `internal/aap` / `internal/eventbus`, AES-GCM, Next.js App Router, shadcn/ui (new to `web/` — Cards/Inputs/Buttons only).

## Global Constraints

- Spec: `docs/superpowers/specs/2026-08-13-connections-settings-design.md`
- CLM is not a Vault plugin; AAP is the only deploy plane; no private keys; no NATS/Kafka.
- Secrets never returned to the browser; write-only on PATCH; Test body must not include secrets.
- AAP Test must not `POST .../launch`. EDA Test must not write the `events` outbox.
- HCP vs self-managed is UX only (namespace default + help). One Vault client.
- Depends on M1 #79. If M1 is unmerged: Settings mutations refuse unless `CLM_INSECURE_NO_AUTH`. AppRole client: M1 implements; Settings consumes; Task 2 fills the gap only if missing.
- Next unused migration number at implement time (do not assume `000007`).
- `go test ./...`, `go build ./...`, `cd web && npm ci && npm test && npm run build` before PR.
- Do not invent Userpass/LDAP/JWT/AWS/cert/k8s Vault auth.

## File structure

- `migrations/00000N_connections.{up,down}.sql` — `connections` table
- `internal/config/config.go` — `CLM_CONNECTIONS_KEY`; keep existing Vault/AAP/EDA env
- `internal/store/connections.go` — CRUD + encrypt/decrypt
- `internal/settings/resolve.go` — env overlay vs DB
- `internal/vault/auth.go` — AppRole login/renew **only if M1 did not add it**
- `internal/api/handlers_settings.go` — GET/PUT/PATCH + Test
- `internal/api/server.go` — routes; RBAC when M1 middleware exists
- `web/app/settings/connections/page.tsx` + shadcn components
- `web/components/sidebar-nav.tsx` — Settings link
- `web/lib/api.ts` — BFF-safe fetch (no `NEXT_PUBLIC` secrets)
- README, `docs/architecture.md`, `docs/data-model.md`, `docs/demo-flow.md`

---

### Task 1: Connections schema + encrypted store

**Files:**
- Create: `migrations/00000N_connections.up.sql`, `migrations/00000N_connections.down.sql`
- Create: `internal/store/connections.go`, `internal/store/connections_test.go`
- Modify: `internal/config/config.go` — `ConnectionsKey string \`envconfig:"CLM_CONNECTIONS_KEY" default:""\``
- Modify: `internal/store/store.go` — wire methods if the package uses a Store struct

**Interfaces:**
- Produces: `store.Connection{Target, Metadata json.RawMessage, SecretsSet bool, Source string, UpdatedAt time.Time, UpdatedBy string}`
- Produces: `UpsertConnection(ctx, target, metadata, secrets map[string]string, keepSecrets []string, actor string) error` — empty secret keys in `keepSecrets` leave ciphertext unchanged
- Produces: `GetConnections(ctx) ([]store.Connection, error)` and `DecryptSecrets(row) (map[string]string, error)` — Decrypt used only by API/runtime, never serialized to HTTP

- [ ] **Step 1:** Write failing tests: encrypt → persist → decrypt round-trip; `Get` DTO has no secret bytes; upsert with omitted token keeps previous ciphertext; missing `CLM_CONNECTIONS_KEY` on upsert returns a typed error (mapped to 503 later).
- [ ] **Step 2:** Run `go test ./internal/store/ -count=1` — expect FAIL (types/table missing).
- [ ] **Step 3:** Add migration (`target TEXT PRIMARY KEY CHECK (target IN ('vault','aap','eda'))`, `metadata JSONB`, `secrets_enc BYTEA`, `secrets_set`, `source`, `updated_at`, `updated_by`). Implement AES-256-GCM with key from config (32-byte hex or raw 32-byte). Never log plaintext.
- [ ] **Step 4:** Re-run store tests — PASS.
- [ ] **Step 5:** Commit `feat: add encrypted connections store`.

---

### Task 2: Vault AppRole client (skip if M1 already merged)

**Files:**
- Create or modify: `internal/vault/auth.go`, `internal/vault/auth_test.go`
- Modify: `internal/vault/client.go` — `Config` gains `RoleID`, `SecretID`; token path unchanged
- Modify: `internal/config/config.go` — `VAULT_ROLE_ID`, `VAULT_SECRET_ID` if M1 has not added them

**Interfaces:**
- Consumes: existing `vault.Client` HTTP + namespace headers
- Produces: `Login(ctx) error` / `EnsureToken(ctx) error` — AppRole login, cache client token, renew before expiry; `token` auth still sets `X-Vault-Token` from config

- [ ] **Step 1:** If `internal/vault` already logs in via AppRole (M1), **skip this task** and consume that API from Task 4. Record the skip in the PR.
- [ ] **Step 2:** Otherwise write httptest: AppRole login then `sys/mounts` (or `sys/health`) sends `X-Vault-Token`; `token` method still works without login.
- [ ] **Step 3:** Run `go test ./internal/vault/ -count=1` — expect FAIL if new tests, else PASS and skip implement.
- [ ] **Step 4:** Minimal login + renew; do not add userpass/LDAP/JWT/AWS/cert/k8s.
- [ ] **Step 5:** Tests PASS. Commit `feat: add Vault AppRole login and renew` (omit commit if skipped).

---

### Task 3: Settings resolve + GET/PUT/PATCH handlers

**Files:**
- Create: `internal/settings/resolve.go`, `internal/settings/resolve_test.go`
- Create: `internal/api/handlers_settings.go`, `internal/api/handlers_settings_test.go`
- Modify: `internal/api/server.go` — `GET|PUT|PATCH /api/v1/settings/connections`

**Interfaces:**
- Consumes: `store` connections + `config.Config` env
- Produces: `settings.Resolved` with `Vault vault.Config`, `AAP aap.Config`, `EDA eventbus.Config` plus masked `PublicView`
- Produces: JSON as in the spec (`token_set` / `role_id_set` / `secret_id_set`, never secret values)

- [ ] **Step 1:** Write resolve tests: no DB row → env; DB `source=db` overlays env; empty PATCH token keeps DB secret; HCP metadata does not change client type.
- [ ] **Step 2:** Write API tests: GET body has no `s.` / `hvs.` / raw tokens; unauthenticated → 401 (or 403/401 refuse if M1 absent **unless** `CLM_INSECURE_NO_AUTH`); `remediator` GET 200 PUT 403; `platform_admin` PUT 200; PUT without connections key and with new secrets → 503.
- [ ] **Step 3:** Run `go test ./internal/settings/ ./internal/api/ -count=1 -run Connections` — expect FAIL.
- [ ] **Step 4:** Implement resolve + handlers. Wire chi routes. If M1 RBAC exists, require `platform_admin` for PUT/PATCH and `platform_admin|remediator` for GET. If not: default-deny Settings mutations unless `CLM_INSECURE_NO_AUTH`. Append `audit_events` when that store exists.
- [ ] **Step 5:** Tests PASS. Commit `feat: add connections settings API`.

---

### Task 4: Connection test handlers

**Files:**
- Modify: `internal/api/handlers_settings.go` — `POST /api/v1/settings/connections/test`
- Modify: `internal/api/handlers_settings_test.go`
- Modify: `internal/aap/client.go` — export or add `Me(ctx) error` if missing (GET `/api/v2/me`); reuse `FindJobTemplate` / `FindWorkflowJobTemplate`
- Modify: `internal/eventbus` only if a small `Ping(ctx, url, token)` helper is cleaner than duplicating `deliver` headers — **do not** call `MarkEventDelivered` or insert outbox rows

**Interfaces:**
- Consumes: `settings.Resolved` + `{ "target": "vault"|"aap"|"eda" }`
- Produces: `{ "ok": bool, "target": string, "detail": string }`

- [ ] **Step 1:** httptest Vault: token probe `sys/health` or `sys/mounts` 200 → `ok:true`; AppRole login then probe (use Task 2 / M1 client).
- [ ] **Step 2:** httptest AAP: `/api/v2/me` 200 + template lookup 200 → `ok:true`; assert **zero** requests to `/launch`. Missing template → `ok:false`, still no launch.
- [ ] **Step 3:** httptest EDA: POST ping body `event_type=clm.connection.test` with Bearer when token set; 2xx → `ok:true`; assert store `events` row count unchanged.
- [ ] **Step 4:** Run `go test ./internal/api/ -count=1 -run ConnectionTest` — FAIL then implement; re-run PASS.
- [ ] **Step 5:** Commit `feat: add connection test endpoints`.

---

### Task 5: Connections UI (shadcn)

**Files:**
- Create: `web/app/settings/connections/page.tsx` (+ client form component if needed)
- Create: `web/components/ui/*` via shadcn (Button, Card, Input, Label, Select, Checkbox) — first use in this repo
- Modify: `web/components/sidebar-nav.tsx` — `{ href: "/settings/connections", label: "Settings" }`
- Modify: `web/lib/api.ts` — `getConnections`, `putConnections`/`patchConnections`, `testConnection`; server-side fetch attaches `Authorization` from a **server-only** env (M1 helper if present). No `NEXT_PUBLIC_VAULT_*` / `NEXT_PUBLIC_AAP_*`.
- Modify: `web/components/reconcile-button.tsx`, `web/components/blind-spot-card.tsx` — point operators at Settings, not “set VAULT_ADDR in README” as the only path
- Test: `web/app/settings/connections/*.test.tsx` (or colocated) — form does not render secret values after save (`token_set`); Test button POSTs `{target}` only

**Interfaces:**
- Consumes: masked GET JSON from Task 3
- Produces: PATCH/PUT metadata + write-only secret fields; Test `{target}`

- [ ] **Step 1:** Add shadcn (init + the components above). Do not migrate inventory/scans to shadcn in this PR.
- [ ] **Step 2:** Vault card: HCP Dedicated / self-managed; HCP presets `namespace=admin` + cluster URL help; auth token | AppRole; masked secrets after save.
- [ ] **Step 3:** AAP card maps `AAP_URL`, token, template, workflow, skip TLS (lab label), default mount. EDA card: webhook URL + token; copy that EDA is HTTP webhook only.
- [ ] **Step 4:** Save + Test per card; show `detail`; never put secrets in client console or `NEXT_PUBLIC_*`.
- [ ] **Step 5:** `cd web && npm test && npm run build`. Commit `feat: add Connections settings page`.

---

### Task 6: Docs + verification

**Files:**
- Modify: `README.md` — Settings + env overlay; `CLM_CONNECTIONS_KEY`; keep env table as Compose default
- Modify: `docs/architecture.md` — Connections API, resolve order, Test probes
- Modify: `docs/data-model.md` — `connections` table
- Modify: `docs/demo-flow.md` — configure Vault via Settings (env still valid)

- [ ] **Step 1:** Document: env default; UI overlay; secrets masked; AppRole owned by M1 client; AAP Test does not launch; EDA Test is a signed ping (Bearer, same as dispatcher).
- [ ] **Step 2:** Run `go test ./...` and `go build ./...`.
- [ ] **Step 3:** Run `cd web && npm ci && npm test && npm run build`.
- [ ] **Step 4:** Commit `docs: document Connections settings and env overlay`.
