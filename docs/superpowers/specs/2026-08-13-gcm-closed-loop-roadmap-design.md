# GCM closed-loop roadmap — design

**Status:** Draft for review (docs PR)  
**Date:** 2026-08-13  
**Source:** [gcm-vault-pki-gap-analysis2.md](file:///Users/djoo/Documents/gcm-vault-pki-gap-analysis2.md) (video + repo review at `d7f42a5`)  
**Not source:** VaultBridge `vault-plugin-pki-clm` export (rejected architecture)  
**Parent:** [ADR 0001](../../adr/0001-source-of-truth-and-event-driven-automation.md)  
**Tracker:** [2026-08-13-gcm-closed-loop-tracker.md](../plans/2026-08-13-gcm-closed-loop-tracker.md)

---

## Problem

IBM GCM’s 5:43 lab video shows a **management plane** around HashiCorp Vault PKI: discover a weak cert on the wire → score it → renew **through Vault** → deploy → **rescan and prove** the new identity is served.

Vault PKI already issues, revokes, and stores what it issued. It does not discover, score the estate, or prove a target is serving the new cert.

This repo already covers a large slice of that loop (scan, inventory, reconcile/shadow, SC-081/PCI/crypto, AAP launch, outbox). The remaining gap is not “build a Vault plugin.” It is **production control-plane security + durable jobs + independent wire verification**.

## Goal served

Ship the smallest GCM-like loop **inside CLM-discovery + AAP**, one milestone at a time:

> Discover → assess → (approve) → Vault signs CSR via AAP → AAP deploys → CLM independently verifies fingerprint on the wire.

## Locked decisions

1. **CLM is not a Vault plugin.** Standalone Go + Postgres + Next.js. Vault = issuance SoR; CLM = inventory SoR; AAP = actuation.
2. **Do not put scanners, SSH, or ServiceNow inside Vault.**
3. **Do not add CLM SSH / typed k8s deployers.** AAP remains the only deploy plane.
4. **Private keys never persist in CLM.** Default CSR-on-target / AAP; no ZIP-key default.
5. **AI does not decide severity.** Deterministic rules; optional prose later (M5).
6. **No NATS/Kafka** until a second event consumer exists (ADR 0001 Phase 2).
7. **Tackle order:** M1 → M2 → M4 core → M3 → M5. Do not start M5 first. M3 can run after M1 (needs waiver actors).
8. **Operational expiry rubric** stays **≤7 critical / ≤30 high / else medium** (shipped report UI). SC-081 keeps ≤14/≤60. A prior &lt;14-high / &lt;30-medium / else-low request is rejected (collapses `critical`, collides with SC-081).

## Milestone map

| # | Issue theme | Priority | Goal | Spec | Plan |
|---|-------------|----------|------|------|------|
| M1 | Secure the control plane | **P0** | AuthN/Z, RBAC, actor audit, Vault AppRole + split identities | [m1](2026-08-13-m1-control-plane-security-design.md) | [plan](../plans/2026-08-13-m1-control-plane-security.md) |
| M2 | Durable jobs + closed-loop renew | **P0/P1** | Persist AAP job, WaitForJob in a worker, expected-vs-observed verify | [m2](2026-08-13-m2-durable-lifecycle-jobs-design.md) | [plan](../plans/2026-08-13-m2-durable-lifecycle-jobs.md) |
| M3 | Explainable posture | P1 | Persist findings, compute `risk_score`, waivers, PQC tags | [m3](2026-08-13-m3-explainable-posture-design.md) | [plan](../plans/2026-08-13-m3-explainable-posture.md) |
| M4 | Durable scan queue | P1 | Replace `chan(32)` with Postgres `SKIP LOCKED` | [m4](2026-08-13-m4-durable-scan-queue-design.md) | [plan](../plans/2026-08-13-m4-durable-scan-queue.md) |
| M5 | Broader integrations | P2 | Event catalogue, revoke-via-AAP, ITSM webhook, cloud collectors | [m5](2026-08-13-m5-broader-integrations-design.md) | [plan](../plans/2026-08-13-m5-broader-integrations.md) |

## Recommended next three (do these first)

1. **M1** — API authentication / RBAC / actor audit (release blocker).
2. **M2** — Persistent renewal job + automatic expected-vs-observed verification.
3. **M4 core** — Durable Postgres scan queue (M2 verify can use a direct `scanrunner.Run` stopgap; M4 makes it HA-safe).

M3 can proceed after M1 (needs actor for waivers). M5 after M1–M2.

## Out of scope (roadmap)

- `vault-plugin-secrets-clm` / `vault-plugin-pki-discovery`
- In-Vault or in-CLM SSH/WinRM/generic shell
- NATS/Kafka
- LLM-chosen severity or act/no-act
- PQC/hybrid **issuance** (inventory tags only in M3)
- Fine-grained Org→Team→Project RBAC (research R2)

## Success

Operators can run the GCM lab narrative on this product **without** a world-writable API, **without** losing AAP jobs on restart, and **with** a job that is `verified` only when the wire presents the new cert.
