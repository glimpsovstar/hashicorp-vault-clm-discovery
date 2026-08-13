## Problem

`Router()` has RequestID / RealIP / Recoverer / logger / CORS only. Any client that can reach `:8080` can list inventory, download PEM, launch scans, import CAs, and fire AAP renewals. `consent:true` is a JSON boolean, not authorization. `VAULT_AUTH_METHOD=approle` is documented but unimplemented. Deletes, PATCH, reconcile, and `GET /inventory` skip even consent.

## Proposed solution

Default-deny the HTTP API except health. Static Bearer tokens mapped to roles (OIDC later). Next BFF attaches `Authorization`. Append-only `audit_events` (not the EDA outbox). Implement Vault AppRole with **split** read vs import identities. Consent stays as intent **after** RBAC.

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

## Test plan

- [ ] `go test ./...` and `go build ./...`
- [ ] `cd web && npm ci && npm test && npm run build`
- [ ] CI uses `npm ci` + `npm audit --omit=dev` (or audit-ci)
- [ ] UAT/integration still pass with Bearer or explicit insecure flag

## Superpowers spec

`docs/superpowers/specs/2026-08-13-m1-control-plane-security-design.md`

Plan: `docs/superpowers/plans/2026-08-13-m1-control-plane-security.md`

Parent: GCM closed-loop umbrella.

## Out of scope

OIDC login UI, fine-grained env tenancy, M2 job approvals, NATS, Vault plugin.
