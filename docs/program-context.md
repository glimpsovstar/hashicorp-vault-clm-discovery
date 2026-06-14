# Program context — Vault PKI / CLM

Short onboarding for engineers joining **Vault CLM Discovery**. Read this before schema, API, or integration work.

## North star

**HashiCorp Vault PKI** issues and tracks certificates it generates. It does **not** discover what is actually deployed on TLS endpoints (load balancers, ingress, VMs). Operators also need to see **shadow certs** (public CA, legacy PKI) that never passed through Vault.

This repo is the **external deployment + governance layer**:

| Question | Answered by |
|----------|-------------|
| What did Vault **issue or revoke**? | Vault PKI; on HCP Vault Dedicated also **HCP Certificates Inventory** (audit/compliance UI) |
| What is **on the wire** right now? | **CLM Discovery** (network TLS scan + observations) |
| Is a deployed cert **Vault-managed**? | CLM reconcile (v1.1) via Vault PKI HTTP API — `managed_status` |

CLM **complements** Vault PKI and HCP inventory; it does **not** replace them or push scan rows into HCP.

## What this repo is not

- **Not** a Vault secrets-engine plugin — standalone Go service + PostgreSQL + Next.js dashboard
- **Not** a cert issuer or renewer (v1.1 reconcile is **read-only**)
- **Not** able to inject external scan results into HCP Certificates Inventory (telemetry-only catalog)

See also: `.cursor/rules/project-context.mdc`, `docs/architecture.md` § Overview.

## CLM lifecycle (operator workflow)

End-to-end story: **Discover → Choose → Import → Manage**. Mapped to versions in the [lifecycle design spec](superpowers/specs/2026-06-14-clm-lifecycle-workflow-design.md).

| Phase | Purpose | Shipped | Planned |
|-------|---------|---------|---------|
| **Discover** | TLS scan, dedup by `fingerprint_sha256`, where/when seen | **v1** | Post-scan reconcile hook (v1.1) |
| **Choose** | Public vs private (`cert_scope`), CA in Vault?, root vs intermediate | Heuristics at scan (v1) | Reconcile-informed (v1.1); wizard (v1.2) |
| **Import** | CA/leaf material into Vault PKI | Issuer table from chains (v1) | `pki/issuers/import/bundle` (v1.2) |
| **Manage** | Expiry, drift, renewal orchestration | Dashboard + governance PATCH (v1) | PKI reconcile (v1.1), OCSP/CRL (v1.1b), vault-agent/AAP links (v1.2) |

GitHub: [#20](https://github.com/glimpsovstar/hashicorp-vault-clm-discovery/issues/20) (lifecycle design), [#17](https://github.com/glimpsovstar/hashicorp-vault-clm-discovery/issues/17) (HCP integration).

## Related HashiCorp products

| Product | Role relative to CLM |
|---------|---------------------|
| **Vault PKI secrets engine** | Source of truth for issued certs; reconcile target for v1.1 (`LIST/READ` stored certs) |
| **HCP Certificates Inventory** | HCP-only audit UI fed by PKI **telemetry** (issue/revoke after reporting enablement) — [docs](https://developer.hashicorp.com/hcp/docs/vault/reporting/certificates-inventory-reporting) |
| **Vault Enterprise / OSS (self-managed)** | Same PKI HTTP API as HCP Dedicated; **no** in-Vault Certificates Inventory UI — CLM + API reconcile fill the gap |
| **vault-agent** | Deploy/renew leaf certs to apps (v1.2+ reference architecture; CLM validates deployment via rescan) |
| **HCP Vault Reporting API** | Optional v1.2 audit metadata ingest — HCP-only; does not replace Vault PKI reconcile |

**HCP vs self-managed:** Reconciliation uses the **Vault cluster HTTP API** (works everywhere). HCP inventory is a **filtered, forward-only telemetry view**; Vault PKI `LIST/READ` is authoritative for matching, including pre-reporting issuances. Detail: [HCP integration spec](superpowers/specs/2026-06-14-hcp-vault-cert-inventory-integration-design.md).

## Version roadmap

| Version | Scope | Status |
|---------|-------|--------|
| **v1** | Network scan, inventory, observations, governance columns, Helios UI, demo reset | **Shipped** |
| **v1.1** | `internal/vault/` client, PKI reconcile, `POST /api/v1/reconcile`, Vault column live | Planned — [implementation plan](superpowers/plans/2026-06-14-clm-lifecycle-v1.1.md) |
| **v1.1b** | OCSP/CRL revocation alignment | Planned |
| **v1.2** | CA import/bundle, Choose wizard, vault-agent/AAP hooks, optional HCP reporting ingest | Planned |
| **v2** | Cloud CA sources (ACM, etc.) | Planned |

## Demo vs production

| Aspect | Demo (today) | Production intent |
|--------|--------------|-------------------|
| Deployment | Docker Compose on laptop | K8s / VM alongside Vault infra; outbound scan access |
| Vault link | Vault column shows **Not connected** until v1.1 reconcile | AppRole/K8s JWT read-only PKI policy |
| Data reset | DELETE APIs + UI for clean demos | Retain history; scheduled rescans for drift |
| Scan targets | Public demo hostnames (`docs/demo-flow.md`) | Customer-owned CIDRs/hostnames + consent |
| Narrative | Cursor SDLC demo (`.prompts-history.md`, `CONTRIBUTING.md`) | Operator lifecycle per specs above |

## Official HashiCorp references

- [Vault PKI secrets engine API](https://developer.hashicorp.com/vault/api-docs/secret/pki) — list/read certs, import bundle
- [HCP Vault reporting](https://developer.hashicorp.com/hcp/docs/vault/reporting) and [certificates inventory](https://developer.hashicorp.com/hcp/docs/vault/reporting/certificates-inventory-reporting)
- [HCP Vault Reporting API](https://github.com/hashicorp/cloud-vault-reporting/blob/main/docs/api-docs/20250505.md) (HCP-only)
- [Helios design tokens](https://helios.hashicorp.design/) — dashboard UI alignment

## Where to read next (this repo)

1. **Run it:** `README.md` quick start, `docs/demo-flow.md`
2. **How it works:** `docs/architecture.md`, `docs/data-model.md`
3. **What to build next:** `docs/superpowers/plans/2026-06-14-clm-lifecycle-v1.1.md`
4. **Design depth:** `docs/superpowers/specs/` (lifecycle, HCP, v1 product)
5. **SDLC / demo arc:** `CONTRIBUTING.md`, `.prompts-history.md`

Before changing schema or API fields, read `docs/data-model.md` and the lifecycle/HCP specs — governance columns and reconcile fields are designed for the full CLM story, not only v1.
