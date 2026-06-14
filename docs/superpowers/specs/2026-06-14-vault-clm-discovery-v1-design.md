# Vault CLM Discovery v1 — Design Spec

**Status:** Approved (retroactive documentation for demo SDLC)  
**Date:** 2026-06-14  
**Issue:** #1  

## Problem

HashiCorp Vault PKI issues and tracks certificates it generates, but has **no network discovery** — no inventory of TLS certificates actually in use on hosts and load balancers. Operators need an external companion that:

- Scans network targets for presented TLS certificates
- Normalizes cert metadata aligned with Vault PKI objects
- Stores discovery context (where/when seen)
- Exposes an independent dashboard for CLM-style review

## Solution

External Go service + PostgreSQL + Next.js dashboard (not a Vault secrets-engine plugin).

### Components

| Component | Responsibility |
|-----------|----------------|
| Go scanner | CIDR expansion, TLS probe, x509 parse |
| Go API | REST inventory, scan orchestration, enrichment |
| PostgreSQL | Certificates, observations, scans, issuers |
| Next.js UI | Inventory, scan trigger, cert detail, issuers |

### Non-goals (v1)

- Vault PKI reconciliation (v1.1)
- OCSP/CRL revocation checks (schema only)
- Cloud provider APIs

## Acceptance criteria

- [ ] Scan CIDR ranges on configurable ports with consent gate
- [ ] Dedup certificates by SHA-256 fingerprint
- [ ] Store full identity + lifecycle + discovery metadata per data model
- [ ] REST API for scans, certificates, issuers, enrichment PATCH
- [ ] Dashboard: inventory, scans, cert detail, issuers
- [ ] Docker Compose local deployment
- [ ] `go test ./...` and CI green

## Test plan

- Unit tests for cert parse, lifecycle, CIDR expansion
- Docker Compose: health, scan public target, cert in inventory
- Manual: dashboard pages load, governance PATCH persists

## References

- [docs/data-model.md](../data-model.md)
- [docs/architecture.md](../architecture.md)
- Org rules: [glimpsovstar/cursor-org-rules](https://github.com/glimpsovstar/cursor-org-rules)
