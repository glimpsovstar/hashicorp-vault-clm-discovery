# M1 Control Plane Security — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Default-deny the HTTP API except health; attach actor+role to every privileged mutation; implement Vault AppRole with split read/import identities.

**Architecture:** Chi authn middleware + RBAC table + append-only `audit_events`. Static Bearer tokens first; OIDC later. Next BFF attaches `Authorization`. Consent stays as intent after RBAC.

**Tech Stack:** Go chi, pgx, existing envconfig, Next.js server fetch.

## Global Constraints

- Spec: `docs/superpowers/specs/2026-08-13-m1-control-plane-security-design.md`
- Do not invent a user directory or Vault plugin.
- Keep SSTI/mount validators.
- Update UAT/integration in the same change as default-deny.
- Next unused migration number at implement time (do not assume 000007).
- `go test ./...`, `go build ./...`, `cd web && npm ci && npm test && npm run build` before PR.

## File structure

- `internal/config/config.go` — auth mode, tokens, Vault role/secret id
- `internal/api/auth.go`, `rbac.go`, `middleware.go`, `server.go`
- `internal/store/audit.go` + migration
- `internal/vault/auth.go` — AppRole login/renew
- `web/lib/api.ts` + server-only token helper
- `.github/workflows/ci.yml` — `npm ci` + audit
- README, `docs/architecture.md`, `docs/demo-flow.md`, UAT compose

---

### Task 1: Config + failing auth tests

- [ ] Add `CLM_AUTH_MODE`, token/role config, `CLM_INSECURE_NO_AUTH`, `VAULT_ROLE_ID`/`VAULT_SECRET_ID`.
- [ ] Write middleware tests: missing token → 401; health → 200.
- [ ] Run tests; expect fail until middleware exists.

### Task 2: Authn + RBAC

- [ ] Parse Bearer; load actor+role; default-deny.
- [ ] Permission matrix per spec; 403 + audit deny.
- [ ] Consent still 400 after authz; unauthorized + consent true is 401/403.

### Task 3: Audit store

- [ ] Migration `audit_events`.
- [ ] `AppendAudit` on mutations and 401/403.
- [ ] Never log secrets/PEM.

### Task 4: Vault AppRole + split client

- [ ] Login/renew; token path unchanged.
- [ ] Import uses write identity when configured.
- [ ] httptest coverage.

### Task 5: Dashboard + CI + docs

- [x] BFF or server-only Authorization; lock DELETE/inventory.
- [x] `npm ci` + audit in CI; UAT/integration Bearer or insecure flag.
- [x] Docs: consent ≠ authorization.
- [x] `go test ./...` && `go build ./...` && web build.
