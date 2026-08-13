## Problem

Detection of revocation, AAP **renew** launch, and an EDA outbox are shipped. The ADR event catalogue is almost empty (`cert.revoked` only). There is no revoke **action**, no ITSM, no cloud CA collectors.

## Proposed solution

**Do not start before M1–M2.** Then: emit remaining ADR event types → freeze AAP extra_vars including `clm_revoke` → consent-gated revoke via AAP (not `vault.Client.Revoke`) → optional ITSM HTTP webhook → read-only ACM/AKV/GCP collectors. Optional LLM **summary** only; never severity.

## Acceptance criteria

- [ ] `GET /events?event_type=` filters; catalogue documented.
- [ ] Revoke action 503 if AAP unset; does not call Vault revoke from CLM.
- [ ] extra_vars contain no secrets; find-by-name only.
- [ ] ITSM is templates over catalogue events.
- [ ] Cloud collectors upsert by `fingerprint_sha256`; no cloud root keys in CLM.

## Test plan

- [ ] Outbox emit tests for new event types
- [ ] Revoke handler does not import/call Vault revoke
- [ ] Collector upsert-by-fingerprint tests (when that slice starts)
- [ ] `go test ./...`

## Superpowers spec

`docs/superpowers/specs/2026-08-13-m5-broader-integrations-design.md`

Plan: `docs/superpowers/plans/2026-08-13-m5-broader-integrations.md`

## Out of scope

Vault secrets-engine plugin, NATS/Kafka, LLM act/no-act, CLM calling Vault `pki/revoke` or `issue`, CLM SSH/k8s/cert-manager deployers, bidirectional CMDB sync.
