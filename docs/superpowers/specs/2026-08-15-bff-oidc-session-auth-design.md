# BFF OIDC / session auth — design

**Status:** Approved (issue #89 implementation mandate)  
**Date:** 2026-08-15  
**Issue:** [#89](https://github.com/glimpsovstar/hashicorp-vault-clm-discovery/issues/89)  
**Plan:** [2026-08-15-bff-oidc-session-auth.md](../plans/2026-08-15-bff-oidc-session-auth.md)  
**Depends on:** M1 (#79) Go API default-deny + static Bearer tokens

---

## Problem

M1 closed unauthenticated mutation on the Go API (`:8080`). The Next.js same-origin BFF still attaches ambient `CLM_API_TOKEN` (demo: `platform_admin`) to every proxied request. Anyone who can reach the Next origin can perform the mutations M1 closed on `:8080`.

## Goal

Browser callers to the Next origin cannot mutate (or otherwise use) the Go API via the BFF without an authenticated server-side session. `CLM_API_TOKEN` is never ambient authority for anonymous BFF callers. Demo Delete/Settings still work for an authenticated `platform_admin` operator. Docs close the residual-risk paragraph.

## Locked decisions

| Decision | Choice |
|----------|--------|
| Auth plane | **BFF session first**; optional OIDC later behind the same session cookie |
| Session | Signed httpOnly cookie (`clm_bff_session`); HMAC with `CLM_BFF_SESSION_SECRET` |
| Demo login | `POST /api/auth/login` with password matching `CLM_BFF_DEMO_PASSWORD` → session role `platform_admin` (demo compose) |
| Token attach | BFF attaches `CLM_API_TOKEN` **only when** a valid session exists (or caller already sent `Authorization`) |
| Unauthenticated BFF | **401** JSON `{ "error": "authentication required" }` — do not forward to Go API |
| SSR | Server components may still call Go directly with `CLM_API_TOKEN` (trusted server→server). Residual risk is browser→BFF only |
| OIDC | Optional: when `CLM_BFF_OIDC_ISSUER` + client id/secret set, `/api/auth/oidc/start` + `/api/auth/oidc/callback` establish the same session cookie. Demo password path remains for compose without an IdP |
| Escape | `CLM_BFF_INSECURE_NO_SESSION=true` — UAT/integration only; restores ambient token attach (documented like Go `CLM_INSECURE_NO_AUTH`) |

## Components

1. **`web/lib/bff-session.ts`** — create / read / clear signed session; role claim.
2. **`web/app/api/auth/login|logout|me`** — session lifecycle.
3. **`web/app/api/auth/oidc/start|callback`** — optional OIDC (Authorization Code + PKCE when configured).
4. **`web/lib/api-proxy.ts`** — require session (or insecure hatch) before attaching `CLM_API_TOKEN`.
5. **Login UI** — minimal `/login` page so demo Delete/Settings remain operable.
6. **Docs** — README + architecture: remove residual-risk paragraph; document env vars.

## Data flow

```
Browser → BFF /api/v1/...
  no session → 401 (no Go call, no token)
  session OK → Authorization: Bearer $CLM_API_TOKEN → Go API (RBAC unchanged)
```

## Acceptance criteria

- [ ] Unauthenticated BFF DELETE/Settings/mutations → 401; Go never sees the request.
- [ ] After demo login (or OIDC), BFF attaches token; Delete/Settings succeed for `platform_admin` token.
- [ ] `CLM_API_TOKEN` not attached for anonymous BFF callers.
- [ ] Go API default-deny unchanged.
- [ ] Residual-risk BFF paragraph removed or marked closed in README + architecture.

## Out of scope

- Changing demo compose to a non-admin token
- Refusing DELETE at the BFF by path
- Replacing Go static-token AuthN
- Fine-grained per-user token mapping beyond one demo role
