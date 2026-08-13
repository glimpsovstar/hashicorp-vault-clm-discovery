# M5 — Broader integrations — design

**Status:** Draft (do not implement before M1–M2)  
**Date:** 2026-08-13  
**Parent:** [GCM closed-loop roadmap](2026-08-13-gcm-closed-loop-roadmap-design.md)  
**Plan:** [2026-08-13-m5-broader-integrations.md](../plans/2026-08-13-m5-broader-integrations.md)

---

## Problem

Detection of revocation, AAP **renew** launch, and an EDA outbox are shipped. The ADR event catalogue is almost empty (`cert.revoked` only). There is no revoke **action**, no ITSM, no cloud CA collectors. GCM’s ticket + multi-source ingest sit here — **after** identity and jobs exist.

## Goal

Complete the catalogue, add revoke-via-AAP (not `vault.Client.Revoke`), then optional ITSM webhook and read-only cloud collectors.

## Order inside M5

1. Emit remaining ADR types (`cert.discovered`, `cert.expiring`, `renewal.*` if M2 didn’t, `blind_spot.detected`).
2. Freeze AAP extra_vars contract (renew as-is + `clm_revoke`).
3. Consent-gated `POST /certificates/{id}/revoke` → named AAP template → verify via existing OCSP/CRL + reconcile.
4. ITSM as HTTP webhook consumer of the catalogue (no ServiceNow SDK, no NATS).
5. Read-only ACM / AKV / GCP CM collectors (`scan_source=cloud_*`).
6. Optional LLM **summary** only; never severity.

## Non-goals (explicit)

- Vault secrets-engine plugin
- NATS/Kafka
- LLM deciding severity or act/no-act
- CLM calling Vault `pki/revoke` or `issue` directly (AAP executes)
- CLM SSH / typed k8s / cert-manager deployers
- Bidirectional CMDB sync

## Acceptance criteria (when this milestone starts)

- [ ] `GET /events?event_type=` filters; catalogue documented.
- [ ] Revoke action 503 if AAP unset; does not call Vault revoke from CLM.
- [ ] extra_vars contain no secrets; find-by-name only.
- [ ] ITSM is templates over catalogue events.
- [ ] Cloud collectors upsert by `fingerprint_sha256`; no cloud root keys in CLM.

## Out of scope

Everything in Non-goals. Policy engine / OPA / NL authoring (research R2).
