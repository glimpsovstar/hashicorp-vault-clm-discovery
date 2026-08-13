## Problem

IBM GCM’s lab narrative is a management plane around Vault PKI: discover a weak cert → score it → renew through Vault → deploy → rescan and prove the new identity is served. This repo already scans, inventories, reconciles/shadows, runs SC-081/PCI/crypto, and **launches** AAP renewals. The remaining gap is not a Vault plugin. It is production control-plane security, durable jobs, and independent wire verification.

## Proposed solution

Implement the closed loop **inside CLM-discovery + AAP**, one child issue at a time:

> Discover → assess → (approve) → Vault signs CSR via AAP → AAP deploys → CLM independently verifies fingerprint on the wire.

Child milestones (do not implement this umbrella issue):

| # | Priority | Theme |
|---|----------|--------|
| M1 | P0 | Secure the control plane |
| M2 | P0/P1 | Durable jobs + wire verify |
| M4 core | P1 | Durable scan queue |
| M3 | P1 | Explainable posture |
| M5 | P2 | Broader integrations (after M1–M2) |

**Tackle order:** M1 → M2 → M4 core → M3 → M5.

## Acceptance criteria

- [ ] Specs/plans/tracker merged (this docs PR).
- [ ] One GitHub issue per milestone, linked here.
- [ ] No Vault CLM plugin, no CLM SSH/k8s deployers, no NATS before a second consumer.
- [ ] Each milestone ships in its own implementation PR with `Fixes #<child>`.

## Test plan

Docs-only for this umbrella. Implementation verification lives on child issues (`go test ./...`, `go build ./...`, web build, Compose where noted).

## Superpowers spec

- Roadmap: `docs/superpowers/specs/2026-08-13-gcm-closed-loop-roadmap-design.md`
- Tracker: `docs/superpowers/plans/2026-08-13-gcm-closed-loop-tracker.md`
- ADR: `docs/adr/0001-source-of-truth-and-event-driven-automation.md`

## Out of scope

- `vault-plugin-secrets-clm` / `vault-plugin-pki-discovery`
- In-Vault or in-CLM SSH/WinRM
- NATS/Kafka
- LLM-chosen severity
- PQC/hybrid issuance
- Empty implementation PRs
