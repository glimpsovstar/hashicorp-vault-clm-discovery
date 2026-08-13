# M1 — Secure the control plane — design

**Status:** Draft  
**Date:** 2026-08-13  
**Parent:** [GCM closed-loop roadmap](2026-08-13-gcm-closed-loop-roadmap-design.md)  
**Plan:** [2026-08-13-m1-control-plane-security.md](../plans/2026-08-13-m1-control-plane-security.md)  
**Priority:** P0 — production release blocker

---

## Problem

`internal/api/server.go` `Router()` has RequestID / RealIP / Recoverer / logger / CORS only. Any client that can reach `:8080` can list inventory, download PEM, launch scans, import CAs, and fire AAP renewals. `consent:true` is a JSON boolean (often hardcoded in the UI). Vault/AAP/EDA use long-lived env tokens; `VAULT_AUTH_METHOD=approle` is documented but unimplemented. Deletes, PATCH, reconcile, and `GET /inventory` skip even consent.

## Goal

Unauthenticated requests cannot read inventory or trigger any mutation except `GET /api/v1/health`. Every privileged mutation has an **actor**, a **role**, and an **audit row**. Vault uses AppRole (or token for laptop) with **split** read vs import identities.

## AuthN (phased)

| Stage | Mechanism |
|-------|-----------|
| First slice (this milestone) | `CLM_AUTH_MODE=static_token` — hashed/static Bearer tokens mapped to roles. Next **BFF** attaches `Authorization`; browser should not need `NEXT_PUBLIC` secrets. |
| Escape hatch | `CLM_INSECURE_NO_AUTH=true` **only** for existing UAT/integration until they are updated in the same change. |
| Later (same spec, later PR ok) | OIDC for humans; JWT/mTLS for AAP inventory pull. |

Default-deny except health.

## RBAC

| Role | Allow |
|------|--------|
| `viewer` | GET inventory, scans, reports, compliance, events |
| `scanner_operator` | + `POST /scans` (still requires consent) |
| `remediator` | + catalog-import, renew, renew-expiring, revocation-check, PATCH |
| `vault_import_admin` | + CA import, reconcile |
| `approver` | Stub: no writes in M1; M2 fills dual-control |
| `platform_admin` | DELETE demo-reset |
| inventory service | `GET /inventory` only (AAP) |

Consent remains **intent** after RBAC: authorized + `consent:false` → 400; unauthorized + `consent:true` → 401/403 (not 400).

## Actor audit

New append-only `audit_events` (do **not** overload the EDA `events` outbox):

`at, actor_id, actor_type, role, action, target_type, target_id, decision, request_id, remote_ip, payload`

Write on scan/renew/import/catalog/delete/reconcile/revoke **and** on 401/403. Never log tokens, PEM, or AAP secrets.

## Vault identities

- Implement `approle` login + token cache/renew (`VAULT_ROLE_ID` / `VAULT_SECRET_ID`).
- Keep `token` for laptop/HCP admin demos.
- Two clients or two AppRoles: **reconcile** (LIST/READ) vs **import** (`issuers/import/bundle` only). Refuse import if only the read identity is configured.
- AAP continues to hold issue/renew credentials; CLM must not put Vault creds in extra_vars.

## npm / CI

`npm ci` in CI; `npm audit --omit=dev` (or audit-ci); pin Next if required. Do not block M1 on a full SBOM platform.

## Acceptance criteria

- [ ] Unauthenticated `GET /api/v1/certificates` → 401; `GET /api/v1/health` → 200.
- [ ] `viewer` cannot `POST /scans` even with `consent:true` (403).
- [ ] `scanner_operator` scan 202 with consent, 400 without; cannot import CA.
- [ ] Successful CA import writes an audit row with actor.
- [ ] DELETE without `platform_admin` → 403.
- [ ] AppRole: httptest Vault login then `X-Vault-Token` on `sys/mounts`; token method still works.
- [ ] Import uses import identity when both configured.
- [ ] UAT/integration updated (`INSECURE_NO_AUTH` or Bearer).
- [ ] README/architecture/demo-flow state: consent is not authorization.

## Out of scope

OIDC login UI (can follow), fine-grained env tenancy, M2 job approvals, NATS, Vault plugin.
