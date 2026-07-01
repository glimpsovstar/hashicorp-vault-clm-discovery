# Compliance standards packs — SC-081 & PCI baseline

**Status:** Approved for Phase 1 implementation  
**Date:** 2026-06-30  
**Research source:** [CLM-discovery-research §9.0 Release 1](https://github.com/glimpsovstar/CLM-discovery-research/blob/main/doc/03-vault-gap-and-plugin.md#90-release-1-commitment-vs-product-vision)  
**Parent plan:** [Phase 1 blind-spot reveal demo](../plans/2026-06-30-phase-1-blind-spot-reveal-demo.md)  
**Related:** [reporting architecture](../../reporting-architecture.md), [data model](../../data-model.md)

---

## Problem

Operators and auditors need findings in **regulatory language**, not raw cert metadata. Release 1 commits to SC-081v3 and PCI 4.2.1.1 baseline reports plus algorithm inventory. The prototype v1 computes lifecycle status (`valid`, `expiring_soon`, `expired`) but does not evaluate compliance rules or produce audit-ready summaries.

---

## Goal served

**G2 — Compliance reporting:** Flag SC-081 validity violations, weak crypto, and PCI inventory gaps on discovered certificates; aggregate into scan-level and estate-level reports.

---

## Scope (Phase 1)

### In scope

| Pack | Rules | Output |
|------|-------|--------|
| **SC-081v3** | Max validity vs enforcement schedule; days remaining vs next phase | Per-cert finding + scan summary count |
| **PCI 4.2.1.1 (baseline)** | Inventory completeness: untagged prod certs, missing owner on external scope | Per-cert finding + scan summary count |
| **Algorithm inventory** | RSA &lt; 2048, SHA-1 signature, weak key types | Per-cert finding + algorithm breakdown in report |

### Out of scope (Phase 1)

- ISM, DORA, APRA template packs (Release 2+)
- Baseline/delta comparison across monitor cycles (Phase 2)
- Webhooks on finding (Phase 2)
- Auto-remediation or operate actions

---

## SC-081 enforcement schedule

Rules use **issued validity period** (`not_after - not_before`) compared to the CA/B Forum SC-081v3 ceiling for the cert's `not_before` date.

| Effective from | Max issued validity (days) | Rule ID |
|----------------|---------------------------|---------|
| 2026-03-15 | 199 | `sc081.validity.199d` |
| 2027-03-15 | 99 | `sc081.validity.99d` |
| 2028-03-15 | 64 | `sc081.validity.64d` |
| 2029-03-15 | 47 | `sc081.validity.47d` |

Additional SC-081-adjacent rules (Phase 1):

| Rule ID | Condition | Severity |
|---------|-----------|----------|
| `sc081.expiry.expired` | Cert's `not_after` is in the past | `critical` |
| `sc081.expiry.critical` | Public/external scope cert expires within 14 days | `critical` |
| `sc081.expiry.warning` | Public/external scope cert expires within 60 days | `warning` |

`cert_scope = internal` certs still get validity checks but expiry severity is `info` unless `environment = prod`.

Expiry is evaluated **live** against the certificate's `not_after` at evaluation
time, not against a `days_until_expiry` value frozen at scan time — a report
generated days after a scan reflects current expiry. A certificate whose
`not_after` is in the past is classified `expired` (not "expires in 0 days"),
including one that expired within the last day.

---

## PCI 4.2.1.1 baseline rules

PCI inventory is about **knowing what you have**. Phase 1 uses governance fields already on `certificates`:

| Rule ID | Condition | Severity |
|---------|-----------|----------|
| `pci.inventory.missing_owner` | `cert_scope = external` AND `owner` IS NULL | `warning` |
| `pci.inventory.untagged_prod` | `environment = prod` AND (`owner` IS NULL OR `tags` empty) | `warning` |
| `pci.inventory.not_in_vault` | `managed_status = unmanaged` AND `cert_scope = external` AND `environment = prod` | `info` |

These are **inventory hygiene** findings, not a full PCI attestation engine.

---

## Algorithm inventory rules

| Rule ID | Condition | Severity |
|---------|-----------|----------|
| `crypto.rsa.weak_key` | `key_type = RSA` AND `key_bits < 2048` | `critical` |
| `crypto.signature.sha1` | `signature_algorithm` contains `SHA1` or `SHA-1` | `critical` |
| `crypto.key.ecdsa.weak` | `key_type = ECDSA` AND `key_bits < 256` | `warning` |

Report includes aggregate counts: `{ rsa_2048_plus, rsa_under_2048, ecdsa, ed25519, sha1_signatures }`.

---

## Data model

### Finding (in-memory / API; not persisted in Phase 1)

```go
type Finding struct {
    RuleID      string    // e.g. sc081.validity.199d
    Pack        string    // sc081 | pci | crypto
    Severity    string    // critical | warning | info
    Title       string    // human-readable one-liner
    Detail      string    // auditor-facing explanation
    CertID      uuid.UUID
    Fingerprint string
    SubjectCN   string
}
```

### Compliance summary (API response)

```go
type ComplianceSummary struct {
    ScanID              uuid.UUID
    GeneratedAt         time.Time
    TotalCerts          int
    FindingsBySeverity  map[string]int
    FindingsByPack      map[string]int
    AlgorithmInventory  AlgorithmInventory
    SC081ViolationCount int
    PCIFindingCount     int
    Findings            []Finding
}
```

Phase 1 computes findings **on read** from certificate rows. Persisting findings to a `compliance_findings` table is deferred to Phase 2 (audit event stream).

---

## API (Phase 1)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/scans/{id}/compliance` | Compliance summary for certs in scan |
| GET | `/api/v1/compliance/summary` | Estate-wide summary (all certs; optional `?scan_id=`) |
| GET | `/api/v1/scans/{id}/report` | Markdown/JSON scan report including compliance section |

Accept header or `?format=markdown|json` for report endpoint.

---

## Report sections (scan report v0)

1. **Executive summary** — targets, certs found, Vault-managed vs shadow (requires reconcile)
2. **Blind-spot reveal** — `vault_managed_count`, `discovered_count`, `shadow_count`
3. **SC-081 posture** — violation count, list of overlong validity certs
4. **PCI inventory gaps** — missing owner, untagged prod
5. **Algorithm inventory** — key type breakdown, weak crypto list
6. **Scan diagnostics** — existing probe/upsert stats from `scans` row

---

## Non-goals

- Full ISM/DORA/APRA mapping
- Automated waiver/exception workflow
- Policy engine or YAML rule authoring
- Persisted finding history (Phase 2)

---

## Acceptance criteria

- [ ] Given a cert with 365-day validity and `not_before` after 2026-03-15, evaluator returns `sc081.validity.199d` finding with severity `critical`
- [ ] Given RSA 1024-bit cert, evaluator returns `crypto.rsa.weak_key`
- [ ] Given external prod cert with no owner, evaluator returns `pci.inventory.missing_owner`
- [ ] `GET /api/v1/scans/{id}/compliance` returns summary JSON with counts matching manual evaluation
- [ ] Scan report Markdown includes blind-spot and SC-081 sections
- [ ] Unit tests cover each rule with table-driven fixtures

---

## Self-review

| Requirement | Covered |
|-------------|---------|
| SC-081 validity schedule | Yes — § SC-081 enforcement schedule |
| Algorithm inventory | Yes — § Algorithm inventory rules |
| PCI baseline | Yes — § PCI 4.2.1.1 baseline rules |
| No operate/remediation | Yes — § Out of scope |
| Research Release 1 alignment | Yes — matches §9.0 committed scope |
