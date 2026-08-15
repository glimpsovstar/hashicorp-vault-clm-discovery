# BFF OIDC / session auth — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans or subagent-driven-development. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Require an authenticated BFF session before attaching `CLM_API_TOKEN` so anonymous browser callers cannot mutate the Go API via Next.

**Architecture:** Signed httpOnly session cookie; demo password login (+ optional OIDC); `proxyToAPI` returns 401 without session unless `CLM_BFF_INSECURE_NO_SESSION`.

**Tech Stack:** Next.js 15 App Router, Vitest, Web Crypto HMAC (no new heavy auth SDK required for session).

## Global Constraints

- Spec: `docs/superpowers/specs/2026-08-15-bff-oidc-session-auth-design.md`
- Issue #89; branch `feature/89-bff-oidc-session`
- Go API AuthN unchanged
- TDD: failing Vitest first
- Docs: README + architecture residual-risk closed
- `cd web && npm test && npm run build`; no Cursor co-author

---

### Task 1: Session helper + proxy gate (TDD)

- [ ] Failing tests: unsigned / missing cookie → proxy 401, no fetch; valid session → Bearer attached; insecure hatch restores ambient token
- [ ] Implement `web/lib/bff-session.ts` (HMAC-SHA256 cookie)
- [ ] Update `web/lib/api-proxy.ts`
- [ ] Update existing proxy tests for session requirement

### Task 2: Auth routes + login page

- [ ] `POST /api/auth/login`, `POST /api/auth/logout`, `GET /api/auth/me`
- [ ] Optional OIDC start/callback when issuer configured (httptest-style unit tests for URL build / state cookie)
- [ ] Minimal `/login` page + link from layout when unauthenticated mutations matter

### Task 3: Compose + docs + verify

- [ ] docker-compose web env: `CLM_BFF_SESSION_SECRET`, `CLM_BFF_DEMO_PASSWORD`
- [ ] README / architecture: close residual risk; document env
- [ ] `npm test` + `npm run build` in `web/`
- [ ] Commit, PR `Fixes #89`, merge
