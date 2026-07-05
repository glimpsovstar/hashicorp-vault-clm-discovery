# Design: Environment scan report (Radar-style, cert-only) — #24

- **Issue:** #24 (Discover-phase artifact; complements #14 diagnostics)
- **Status:** Implemented (approach approved). On-demand generation; report_version 0.2.0; formats markdown/json/csv.
- **Architecture:** [docs/reporting-architecture.md](../../reporting-architecture.md) (this spec is the concrete implementation of it)
- **Builds on:** report v0 (`internal/report`: `Document`, `Generate`, `BuildForScan`, `RenderMarkdown`, `RenderJSON`) shipped in Phase 1

## Problem

Report v0 renders blind-spot + compliance + diagnostics for a completed scan.
Issue #24 asks for the full Radar-style **environment report**: per-scan
certificate health, expiry risk, issuer trust, scope/governance breakdown, a
classified **insight list** with severity + recommendation codes, and a **CSV**
export — without leaking PEM or implying a full Vault posture review.

## Goals

| ID | Goal | Success criteria |
|----|------|------------------|
| G1 | Radar-style sections | Document + Markdown gain cert-health, expiry-risk, issuer-trust, scope/governance, recommendations sections |
| G2 | Insight model | Pure classifier maps each scan cert/issuer to `Insight{category,type,severity,recommendation,…}` |
| G3 | CSV export | `GET …/report?format=csv` returns a flattened insight list; `Content-Disposition` attachment |
| G4 | Safe + versioned | No PEM in Markdown/CSV; JSON `report_version` bumped; markdown-cell escaping reused |

## Non-goals (enforced)

PDF, baseline/delta vs prior scan, SARIF, secret scanning, Vault policy audit,
HCP inventory push. (Per issue #24 "Out of scope".)

## Data sources (all already available)

- `st.GetScan(id)` — header + diagnostics (report v0).
- `st.ListCertificates({ScanID: id})` — per-scan certs (the compliance evaluator
  already uses this via `CertStore`). Each `store.Certificate` carries `Status`,
  `DaysUntilExpiry`, `NotAfter`, `ChainStatus`, `CertScope`, `ManagedStatus`,
  `KeyType`/`KeyBits`, `SignatureAlgorithm`, `HostnameMatchesSAN`, `IssuerDN`,
  `Owner`/`Team`/`Environment`, `FingerprintSHA256`, `SubjectCN`.
- Issuer trust is derived from the scan certs' `IssuerDN` + `ChainStatus` +
  `ManagedStatus` (no new store method; avoids the global `ListIssuers` which is
  not scan-scoped).

`BuildForScan`'s `ScanStore` interface already exposes `GetScan`,
`CountByManagedStatus`, and (via `compliance.CertStore`) `ListCertificates` — so
**no new store methods and no migration** are required.

## Design

### 1. Insight model (`internal/report/insight.go`)

```go
type Severity string // "info" | "low" | "medium" | "high" | "critical"

type Insight struct {
    Category       string            `json:"category"`        // certificate | issuer | governance | scan
    Type           string            `json:"type"`            // expired | expiring_soon | incomplete_chain | san_mismatch | shadow_cert | weak_key | ...
    Severity       Severity          `json:"severity"`
    Recommendation string            `json:"recommendation"`  // monitor_external | reconcile_vault | import_ca | catalog_import | fix_san | rescan
    SubjectCN      string            `json:"subject_cn,omitempty"`
    Fingerprint    string            `json:"fingerprint_sha256,omitempty"`
    IssuerDN       string            `json:"issuer_dn,omitempty"`
    Description    string            `json:"description"`
    Tags           []string          `json:"tags,omitempty"`
    Metadata       map[string]string `json:"metadata,omitempty"`
}
```

`ClassifyCertificate(store.Certificate) []Insight` — pure function implementing
the severity table from reporting-architecture.md (expired→high, expiring_soon
≤30d→medium, incomplete/untrusted chain→medium, san_mismatch→low, unmanaged
internal→low governance, weak key→ per crypto). Recommendation codes assigned
per condition. Deterministic ordering (severity desc, then CN).

### 2. Aggregates (`internal/report/aggregate.go`)

Pure functions over `[]store.Certificate`:
- `CertHealth` — counts by `status`; day-buckets (≤7, ≤30, ≤90, >90, expired).
- `ExpiryRisk` — expiring in 7/30/90; cross-tab expiry × `cert_scope`.
- `IssuerTrust` — group by `IssuerDN`: cert count, `is_ca` split, `chain_status`
  distribution, in-Vault? (`ManagedStatus`/`VaultIssuerRef`), import candidates.
- `ScopeGovernance` — `cert_scope` and `managed_status` counts; shadow narrative
  (reuses blind-spot); owner/team coverage.
- `Recommendations` — dedup + rank the insight recommendation codes into a
  prioritized action list grouped by lifecycle phase.

### 3. Extend `Document` + `BuildForScan`

Add typed sections (`CertHealth`, `ExpiryRisk`, `IssuerTrust`, `ScopeGovernance`,
`Insights []Insight`, `Recommendations []Recommendation`) to `Document`.
`BuildForScan` additionally calls `ListCertificates({ScanID})`, runs the
classifier + aggregators, and fills the new fields. Bump `ReportVersion`
(0.1.0 → **0.2.0**); JSON stays additive/back-compatible.

### 4. Renderers

- **Markdown** (`markdown.go`) — append the section-template order from
  reporting-architecture.md §Section template. Reuse `escapeCell`; **no PEM**.
- **JSON** (`json.go`) — unchanged mechanics (marshals the richer `Document`).
- **CSV** (`csv.go`, new) — `RenderCSV(doc) ([]byte, error)` flattening
  `Insights` to columns: `category,type,severity,recommendation,subject_cn,
  fingerprint_sha256,issuer_dn,days_until_expiry,cert_scope,managed_status,description`.
  Use `encoding/csv` (handles quoting/injection of commas/quotes). Guard against
  CSV formula injection by prefixing cells beginning with `= + - @` with `'`.

### 5. API (`internal/api/handlers_report.go`)

Add `format=csv` → `text/csv` with
`Content-Disposition: attachment; filename="scan-<id>-report.csv"`. Keep
`markdown` (default) and `json`. Unknown format → `400`. `404`/not-completed and
error mapping unchanged.

### 6. Dashboard (optional, minimal)

Add Markdown/JSON/CSV download links on the scan detail page
(`web/app/scans/[id]/page.tsx`) pointing at the existing report endpoint with the
`format` query param. No new API client logic beyond building the URL.

### 7. Docs

Update `docs/reporting-architecture.md` (mark v1.2 sections implemented) and
`README.md` (report formats).

## Security

- No PEM in Markdown or CSV (JSON already omits it? — verify; the `Document`
  never carried PEM, only counts/insights, so it stays out).
- Markdown table injection: reuse `escapeCell`. CSV formula injection: prefix
  risky leading chars. All cell values that originate from scanned endpoints
  (Subject CN, issuer DN) pass through these guards.

## Testing (TDD)

- `insight_test.go` — table-driven `ClassifyCertificate` across each severity
  row (expired, expiring_soon, incomplete chain, san mismatch, unmanaged
  internal, weak key, healthy → no insight).
- `aggregate_test.go` — `CertHealth`/`ExpiryRisk`/`IssuerTrust`/`ScopeGovernance`
  over a fixed cert slice; assert bucket counts and issuer grouping.
- `csv_test.go` — header + row count == len(insights); comma/quote in CN quoted;
  formula-injection cell prefixed.
- `markdown` — assert new section headings + a known insight row present.
- `handlers_report_test.go` — `format=csv` returns 200, `text/csv`,
  `Content-Disposition`; `format=bogus` → 400.
- `BuildForScan` — extend fake store to return certs; assert new sections
  populated.

## Verification gate

`go build ./...`, `go vet ./internal/...`, `go test ./...`,
`cd web && npm run build`, then PR + sub-agent review before squash-merge.
