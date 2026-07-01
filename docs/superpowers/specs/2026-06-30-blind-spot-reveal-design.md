# Blind-spot reveal demo — design

**Status:** Approved for Phase 1 implementation  
**Date:** 2026-06-30  
**Research source:** [CLM-discovery-research §11–§12](https://github.com/glimpsovstar/CLM-discovery-research/blob/main/doc/certificate-lifecycle-management-research-report.md)  
**Parent plan:** [Phase 1 blind-spot reveal demo](../plans/2026-06-30-phase-1-blind-spot-reveal-demo.md)  
**Related:** [HCP Vault integration spec](2026-06-14-hcp-vault-cert-inventory-integration-design.md), [lifecycle workflow spec](2026-06-14-clm-lifecycle-workflow-design.md)

---

## Problem

Vault PKI and HCP Certificates Inventory only show **Vault-issued** certificates. Operators cannot answer: *"How many certs are on the wire that Vault never issued?"* The POV demo must land in ten seconds:

> Vault sees **N** certs. We found **M**. Here are **K** SC-081 violations.

Prototype v1 scans and inventories certs but the Vault column always shows "Not connected" until reconcile ships, and there is no aggregate blind-spot view.

---

## Goal served

**G1 — Vault blind-spot visibility:** Correlate discovered inventory with Vault PKI; surface shadow cert count in dashboard and reports.

---

## Metrics

| Metric | Definition | Source |
|--------|------------|--------|
| `vault_managed_count` | Certs with `managed_status = managed_in_vault` | CLM DB after reconcile |
| `discovered_count` | Certs in scan (or estate) | CLM DB |
| `shadow_count` | `discovered_count - vault_managed_count` (same fingerprint dedup) | Computed |
| `vault_pki_count` | Certs read from Vault PKI during reconcile (may exceed matched if not on wire) | Reconcile summary |

**Blind-spot headline:** `shadow_count` certs visible on the network that Vault does not manage.

Optional fourth stat for demo narrative: `vault_only_count` — certs in Vault PKI with no CLM observation (deferred to Phase 1 stretch; log in reconcile summary only).

---

## User flows

### Flow A — POV demo (primary)

1. Operator runs scan against demo hostnames + Vault-connected estate
2. Reconcile runs (`RECONCILE_ON_SCAN_COMPLETE=true` or manual button)
3. Dashboard **Overview** or scan detail shows blind-spot card: N / M / K
4. Operator downloads scan report or opens compliance tab
5. Narrative: shadow certs + SC-081 violations → Release 2 migration story

### Flow B — Reconcile without scan

1. Operator configures `VAULT_ADDR` + auth
2. Clicks **Reconcile with Vault** on inventory page
3. Inventory Vault column updates; blind-spot counts refresh

---

## UI — blind-spot card

Location: scan detail page (`/scans/[id]`) and optional home dashboard strip.

```
┌─────────────────────────────────────────────────────────┐
│  Blind-spot reveal                                      │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐ │
│  │ Vault    │  │ On wire  │  │ Shadow   │  │ SC-081   │ │
│  │ managed  │  │ (scan)   │  │ certs    │  │ violations│ │
│  │    12    │  │    47    │  │    35    │  │     8    │ │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘ │
│  [Reconcile with Vault]  [Download report]                │
└─────────────────────────────────────────────────────────┘
```

States:

- **Vault not configured:** card shows discovered count only; CTA links to README reconcile setup
- **Reconcile pending:** spinner after scan complete
- **Reconcile complete:** all four metrics populated

---

## API

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/reconcile` | Trigger Vault PKI reconcile; returns summary |
| GET | `/api/v1/scans/{id}/blindspot` | `{ vault_managed, discovered, shadow, sc081_violations }` |
| GET | `/api/v1/blindspot` | Estate-wide blind-spot summary |

Reconcile response:

```json
{
  "mounts_scanned": 2,
  "vault_certs_read": 15,
  "matched": 12,
  "unmatched_clm": 35,
  "status": "ok",
  "errors": []
}
```

`status` classifies the run so a total failure is never presented as a
successful "0 matched": `ok` (no errors), `partial` (some certs read, some
mount/cert reads failed), or `failed` (errors occurred and no certificate could
be read at all). Per-mount/per-cert failures are listed in `errors`. The
dashboard surfaces `partial`/`failed` explicitly rather than showing success.

---

## Vault integration (read-only)

Reuses [HCP integration spec](2026-06-14-hcp-vault-cert-inventory-integration-design.md):

- Auth: AppRole, token, or AWS IAM
- `LIST sys/mounts` → filter PKI
- `LIST {mount}/certs` → `READ {mount}/cert/{serial}`
- Match on `fingerprint_sha256`
- Update `managed_status`, `vault_pki_mount`, `vault_issuer_ref`, `serial_number`

**Complement narrative:** HCP Certificates Inventory = Vault telemetry UI. CLM reconcile = fingerprint match against live PKI store + network discovery. Both needed for full picture.

---

## Non-goals (Phase 1)

- Write to Vault PKI
- Import & replace workflow
- HCP Reporting API ingest (v1.2)
- Real-time sync / webhooks

---

## Acceptance criteria

- [ ] After reconcile, at least one demo cert shows Vault column "Connected"
- [ ] Blind-spot card on scan detail shows correct shadow count for a known test estate
- [ ] POV demo script completable in under 2 minutes (scan → reconcile → report)
- [ ] Reconcile is idempotent (re-run does not duplicate or corrupt rows)
- [ ] 503 when Vault not configured; scan still succeeds

---

## Self-review

| Requirement | Covered |
|-------------|---------|
| Vault vs discovered comparison | Yes — § Metrics |
| POV ten-second narrative | Yes — § User flows |
| Read-only Vault | Yes — § Vault integration |
| Dashboard surfacing | Yes — § UI |
| Research §12 action #1 | Yes |
