# M5 Broader Integrations — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Finish the event catalogue, add revoke-via-AAP, then optional ITSM webhook and cloud collectors.

**Architecture:** Same launch path as renew. CLM does not call Vault revoke. No CLM deployers. No NATS. No LLM severity.

**Tech Stack:** Existing outbox, aap client, revocation detection, future read-only cloud SDKs.

## Global Constraints

- Spec: `docs/superpowers/specs/2026-08-13-m5-broader-integrations-design.md`
- **Do not start before M1–M2.**
- Non-goals in the spec are binding.

## File structure

- `internal/store` emit remaining ADR types
- `internal/api` revoke handler (AAP)
- docs: extra_vars contract
- later: webhook sink, `internal/collectors/`

---

### Task 1: Event catalogue

- [ ] Emit `cert.discovered`, `cert.expiring`, remaining `renewal.*` if needed, `blind_spot.detected`.
- [ ] `GET /events?event_type=`; document payloads.

### Task 2: Freeze AAP contract + revoke via AAP

- [ ] Spec extra_vars for `clm_revoke` (serial, mount, certificate_id, reason).
- [ ] Consent `POST /certificates/{id}/revoke` → named template; verify OCSP/CRL + reconcile.
- [ ] No `vault.Client.Revoke`.

### Task 3: ITSM webhook (optional)

- [ ] HTTP templates from catalogue events; HMAC optional; no ServiceNow SDK.

### Task 4: Cloud collectors (v2)

- [ ] Read-only ACM/AKV/GCP → same fingerprint inventory; `scan_source=cloud_*`.

### Task 5: AI last or skip

- [ ] Summary only if 1–3 exist; never LLM-chosen severity.
