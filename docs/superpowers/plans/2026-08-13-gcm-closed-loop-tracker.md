# GCM closed-loop tracker

> Master checkbox list. Implement **one milestone issue at a time** using that milestone’s plan. Do not start M5 before M1–M2.

**Roadmap spec:** [2026-08-13-gcm-closed-loop-roadmap-design.md](../specs/2026-08-13-gcm-closed-loop-roadmap-design.md)

**Source:** `gcm-vault-pki-gap-analysis2.md` + parallel code research (2026-08-13).

## GitHub issues

| Milestone | Issue | Body |
|-----------|-------|------|
| Umbrella | [#78](https://github.com/glimpsovstar/hashicorp-vault-clm-discovery/issues/78) | [umbrella](../issues/umbrella-gcm-closed-loop.md) |
| M1 | [#79](https://github.com/glimpsovstar/hashicorp-vault-clm-discovery/issues/79) | [m1](../issues/m1-control-plane-security.md) |
| M2 | [#80](https://github.com/glimpsovstar/hashicorp-vault-clm-discovery/issues/80) | [m2](../issues/m2-durable-lifecycle-jobs.md) |
| M4 | [#81](https://github.com/glimpsovstar/hashicorp-vault-clm-discovery/issues/81) | [m4](../issues/m4-durable-scan-queue.md) |
| M3 | [#82](https://github.com/glimpsovstar/hashicorp-vault-clm-discovery/issues/82) | [m3](../issues/m3-explainable-posture.md) |
| M5 | [#83](https://github.com/glimpsovstar/hashicorp-vault-clm-discovery/issues/83) | [m5](../issues/m5-broader-integrations.md) |
| Connections Settings | [#85](https://github.com/glimpsovstar/hashicorp-vault-clm-discovery/issues/85) | [connections](../issues/connections-settings.md) |
| ADCS + AKV collectors | [#86](https://github.com/glimpsovstar/hashicorp-vault-clm-discovery/issues/86) | [collectors](../issues/adcs-akv-collectors.md) |
| Migrate + pending verify | [#87](https://github.com/glimpsovstar/hashicorp-vault-clm-discovery/issues/87) | [migrate](../issues/migrate-pending-verify.md) |

## Priority order

1. [ ] **M1** Secure the control plane — [#79](https://github.com/glimpsovstar/hashicorp-vault-clm-discovery/issues/79) · [spec](../specs/2026-08-13-m1-control-plane-security-design.md) · [plan](2026-08-13-m1-control-plane-security.md)
2. [ ] **M2** Durable jobs + wire verify — [#80](https://github.com/glimpsovstar/hashicorp-vault-clm-discovery/issues/80) · [spec](../specs/2026-08-13-m2-durable-lifecycle-jobs-design.md) · [plan](2026-08-13-m2-durable-lifecycle-jobs.md)
3. [ ] **M4 core** Durable scan queue — [#81](https://github.com/glimpsovstar/hashicorp-vault-clm-discovery/issues/81) · [spec](../specs/2026-08-13-m4-durable-scan-queue-design.md) · [plan](2026-08-13-m4-durable-scan-queue.md)
4. [ ] **M3** Explainable posture — [#82](https://github.com/glimpsovstar/hashicorp-vault-clm-discovery/issues/82) · [spec](../specs/2026-08-13-m3-explainable-posture-design.md) · [plan](2026-08-13-m3-explainable-posture.md)
5. [ ] **M5** Broader integrations — [#83](https://github.com/glimpsovstar/hashicorp-vault-clm-discovery/issues/83) · [spec](../specs/2026-08-13-m5-broader-integrations-design.md) · [plan](2026-08-13-m5-broader-integrations.md)
6. [ ] **Connections Settings** (after M1) — [#85](https://github.com/glimpsovstar/hashicorp-vault-clm-discovery/issues/85) · [spec](../specs/2026-08-13-connections-settings-design.md) · [plan](2026-08-13-connections-settings.md)
7. [ ] **Migrate + pending verify** (after M2) — [#87](https://github.com/glimpsovstar/hashicorp-vault-clm-discovery/issues/87) · [spec](../specs/2026-08-13-migrate-pending-verify-design.md) · [plan](2026-08-13-migrate-pending-verify.md)
8. [ ] **ADCS then AKV collectors** (after M1; M5 sibling) — [#86](https://github.com/glimpsovstar/hashicorp-vault-clm-discovery/issues/86) · [spec](../specs/2026-08-13-adcs-akv-collectors-design.md) · [plan](2026-08-13-adcs-akv-collectors.md)

M3 can run after M1 (needs actor for waivers). M4 core can overlap M2 (M2 verify has a `scanrunner.Run` stopgap). Connections Settings consumes M1 AppRole. Migrate extends M2. Collectors must not ship collect APIs before M1.

## Won’t do

- [x] ~~Vault CLM/discovery plugin~~ — cancelled (ADR 0001)
- [x] ~~SSH/WinRM/ZIP-key push in CLM~~ — cancelled
- [x] ~~NATS/Kafka before a second consumer~~ — deferred (ADR Phase 2)

## Already shipped (do not re-plan)

- [x] Network TLS scan + observations
- [x] Vault fingerprint reconcile / shadow certs
- [x] SC-081 / PCI / crypto + scan report
- [x] AAP renewal **launch** (kit, on-demand, batch)
- [x] Outbox + EDA (`cert.revoked` only)
