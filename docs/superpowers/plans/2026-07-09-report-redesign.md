# Environment Report Redesign (Vault Radar style) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rebuild `/scans/[id]/report` as a Vault Radar-style report — a severity overview bar, one unified filterable findings table with severity badges, and a per-row drill-in — replacing the four flat stacked panels.

**Architecture:** A pure server-side normalizer (`lib/findings.ts`) folds the three existing data sources (report insights, shadow certs, scan CA issuers) into one `Finding[]` view-model. A single client component (`report-explorer.tsx`) owns filter state and renders the severity overview + coverage meter + toolbar + findings table + expandable detail rows, reusing the existing `CatalogImportButton` / `ImportCAButton` for row actions. The report page becomes a thin server component that builds findings and hands them to the explorer.

**Tech Stack:** Next.js 15 (App Router) + React 19 + TypeScript. Plain global CSS with HashiCorp Design System (HDS) tokens. Vitest + @testing-library/react for tests.

## Global Constraints

- **Issue #73**; branch `feature/73-report-redesign` (already created off `main`).
- **Spec:** `docs/superpowers/specs/2026-07-09-report-redesign-design.md`.
- **Light theme only.** The app has no dark theme; style exclusively with existing `--token-color-*` HDS variables from `web/styles/hds-tokens.css`. Do NOT add `prefers-color-scheme` or `data-theme`.
- **No new dependencies.** Use what `web/package.json` already has.
- **Reuse existing action components** verbatim: `CatalogImportButton` (Track in CLM) and `ImportCAButton` (Import CA to Vault). Do not reimplement their logic.
- **Preserve existing behavior:** the same items shown today (insights, shadow certs, CA issuers) must still appear and their actions must still work. This is a visual/structural redesign, not a data-model change to the backend.
- **All paths are relative to `web/`.** Run all commands from `/Users/djoo/Documents/Personal/Projects/CLM-discovery/web`.
- **Commit rule:** author is the git default (David Joo); no `Co-Authored-By` trailer.

### Key design decisions (locked)

1. **Findings are the concatenation of three kinds**, each tagged `kind: "insight" | "shadow" | "issuer"`. No dedup between an insight and the shadow cert it may describe — this matches today's report (Insights + shadow-cert sections already coexist). Dedup is explicitly out of scope for v1.
2. **Severity source:** insights use their backend `severity` directly. Shadow certs and issuers get a *derived* severity from expiry (rubric in Task 1). This is the rubric the user approved: shadow + near-expiry → Critical.
3. **No "endpoint" (IP:port) column.** The mockup showed IP:port, but `Certificate` exposes `subject_cn` / `serial_number` / `last_seen`, not IP:port (that lives on `Observation`). The table's secondary line uses `serial_number`; the drill-in shows issuer DN, fingerprint, serial, last-seen, scope, managed status. (A future enhancement can fetch observations for true endpoints.)
4. **No Active/Ignored/All status segment.** There is no "ignored/not-important" state in the data model. Replace that mockup control with a **kind filter** (All / Shadow certs / Insights / CA issuers), which maps to real data.
5. **Keep** the `PageHeader` + `ReportDownloadMenu` and the existing **Recommended actions** panel (real data) below the explorer. The explorer replaces the Summary + Insights + shadow-cert + CA-issuer panels.

---

## File Structure

- `web/lib/findings.ts` — **new.** Pure model: `Finding` type, `deriveShadowSeverity`, `deriveIssuerSeverity`, `buildFindings`, `severityCounts`, `coverageFromBlindSpot`, `findingSeverityBadgeClass`. No React, no I/O.
- `web/lib/findings.test.ts` — **new.** Unit tests for the above.
- `web/components/report-explorer.tsx` — **new.** Client component. Owns filter state; renders overview + coverage + toolbar + table + drill-in. Presentational sub-components (`SeverityOverview`, `FindingRow`) live in this file.
- `web/components/report-explorer.test.tsx` — **new.** Render/interaction tests.
- `web/app/scans/[id]/report/page.tsx` — **modify.** Build findings server-side; render `<ReportExplorer>`; drop the four old panels; keep header, download menu, recommendations.
- `web/app/globals.css` — **modify.** Add report-explorer styles (overview grid, sev-card, coverage meter, toolbar, chips, segment, findings table, severity badges, drill-in) using HDS tokens.

---

## Task 1: Findings model (`lib/findings.ts`)

**Files:**
- Create: `web/lib/findings.ts`
- Test: `web/lib/findings.test.ts`

**Interfaces:**
- Consumes: `Certificate`, `Issuer`, `ReportInsight`, `BlindSpotSummary` from `@/lib/api`; `selectShadowCerts`, `selectScanIssuers` from `@/lib/report`.
- Produces:
  - `type FindingSeverity = "critical" | "high" | "medium" | "low" | "info"`
  - `type FindingKind = "insight" | "shadow" | "issuer"`
  - `type Finding = { key: string; kind: FindingKind; severity: FindingSeverity; typeLabel: string; subject: string; secondary: string; vault: "shadow" | "managed" | "na"; days: number | null; description?: string; issuerDn?: string; fingerprint?: string; serial?: string; cert?: Certificate; issuer?: Issuer }`
  - `deriveShadowSeverity(cert: Certificate): FindingSeverity`
  - `deriveIssuerSeverity(issuer: Issuer): FindingSeverity`
  - `buildFindings(report: ReportDocument, certs: Certificate[], issuers: Issuer[]): Finding[]`
  - `severityCounts(findings: Finding[]): Record<FindingSeverity, number>`
  - `coverageFromBlindSpot(bs: BlindSpotSummary): { managed: number; shadow: number; discovered: number; pct: number }`
  - `findingSeverityBadgeClass(sev: FindingSeverity): string` → `"finding-sev finding-sev-critical"` etc.

- [ ] **Step 1: Write the failing test**

Create `web/lib/findings.test.ts`:

```ts
import { describe, it, expect } from "vitest";
import {
  deriveShadowSeverity,
  deriveIssuerSeverity,
  buildFindings,
  severityCounts,
  coverageFromBlindSpot,
  findingSeverityBadgeClass,
} from "./findings";
import type { Certificate, Issuer, ReportDocument } from "./api";

function cert(over: Partial<Certificate>): Certificate {
  return {
    id: "c", serial_number: "1", fingerprint_sha256: "f", subject_alt_names: [],
    issuer_dn: "CN=Test CA", not_before: "", not_after: "", days_until_expiry: 60,
    status: "valid", chain_status: "complete", hostname_matches_san: true,
    managed_status: "unmanaged", cert_scope: "external", last_seen: "2026-07-01T00:00:00Z",
    ...over,
  };
}
function issuer(over: Partial<Issuer>): Issuer {
  return {
    id: "i", fingerprint_sha256: "f", issuer_dn: "CN=Test CA", not_after: "",
    days_until_expiry: 100, status: "valid", is_ca: true, ...over,
  };
}
function report(over: Partial<ReportDocument> = {}): ReportDocument {
  return {
    report_version: "0.2.0", generated_at: "2026-07-09T00:00:00Z", scan_id: "s",
    scan_status: "completed",
    blind_spot: { vault_managed: 34, discovered: 50, shadow: 16, sc081_violations: 4 },
    cert_health: { total: 50, by_status: {}, expiry_buckets: { expired: 0, within_7d: 0, within_30d: 0, within_90d: 0, beyond_90d: 0 } },
    expiry_risk: { within_7d: 0, within_30d: 0, within_90d: 0 },
    scope_governance: { by_scope: {}, by_managed_status: {}, owner_coverage: { with_owner: 0, total: 0 } },
    insights: [], recommendations: [], ...over,
  };
}

describe("deriveShadowSeverity", () => {
  it("expired -> critical", () => {
    expect(deriveShadowSeverity(cert({ status: "expired", days_until_expiry: -1 }))).toBe("critical");
  });
  it("<=7 days -> critical", () => {
    expect(deriveShadowSeverity(cert({ days_until_expiry: 5 }))).toBe("critical");
  });
  it("<=30 days -> high", () => {
    expect(deriveShadowSeverity(cert({ days_until_expiry: 20 }))).toBe("high");
  });
  it("otherwise -> medium (unmanaged is inherently notable)", () => {
    expect(deriveShadowSeverity(cert({ days_until_expiry: 200 }))).toBe("medium");
  });
});

describe("deriveIssuerSeverity", () => {
  it("<=30 days -> high", () => {
    expect(deriveIssuerSeverity(issuer({ days_until_expiry: 10 }))).toBe("high");
  });
  it("otherwise -> low", () => {
    expect(deriveIssuerSeverity(issuer({ days_until_expiry: 300 }))).toBe("low");
  });
});

describe("buildFindings", () => {
  it("folds insights, shadow certs, and issuers into one list tagged by kind", () => {
    const certs = [
      cert({ id: "shadow1", subject_cn: "app.db", managed_status: "unmanaged", days_until_expiry: 3, issuer_dn: "CN=Seen CA" }),
      cert({ id: "managed1", managed_status: "managed_in_vault", issuer_dn: "CN=Seen CA" }),
    ];
    const issuers = [issuer({ id: "ca1", issuer_dn: "CN=Seen CA", is_ca: true, days_until_expiry: 300 })];
    const rep = report({
      insights: [{ category: "compliance", type: "sc081.expiry.critical", severity: "critical", recommendation: "renew", description: "Expiring", subject_cn: "api.pay" }],
    });
    const findings = buildFindings(rep, certs, issuers);
    const kinds = findings.map((f) => f.kind);
    expect(kinds).toContain("insight");
    expect(kinds).toContain("shadow");
    expect(kinds).toContain("issuer");
    // managed cert is NOT a shadow finding
    expect(findings.some((f) => f.kind === "shadow" && f.cert?.id === "managed1")).toBe(false);
    // shadow cert attaches its cert for the action; severity derived (3 days -> critical)
    const s = findings.find((f) => f.kind === "shadow" && f.cert?.id === "shadow1")!;
    expect(s.cert).toBeDefined();
    expect(s.severity).toBe("critical");
    expect(s.subject).toBe("app.db");
    // issuer attaches its issuer for the action
    const ca = findings.find((f) => f.kind === "issuer")!;
    expect(ca.issuer?.id).toBe("ca1");
  });

  it("gives every finding a unique key", () => {
    const certs = [cert({ id: "a", managed_status: "unmanaged" }), cert({ id: "b", managed_status: "unmanaged" })];
    const findings = buildFindings(report(), certs, []);
    const keys = findings.map((f) => f.key);
    expect(new Set(keys).size).toBe(keys.length);
  });
});

describe("severityCounts", () => {
  it("counts by severity including zeros", () => {
    const certs = [cert({ id: "a", managed_status: "unmanaged", days_until_expiry: 3 })]; // critical
    const counts = severityCounts(buildFindings(report(), certs, []));
    expect(counts.critical).toBe(1);
    expect(counts.info).toBe(0);
  });
});

describe("coverageFromBlindSpot", () => {
  it("computes managed percentage of discovered", () => {
    expect(coverageFromBlindSpot({ vault_managed: 34, discovered: 50, shadow: 16, sc081_violations: 4 }).pct).toBe(68);
  });
  it("is 0% when nothing was discovered", () => {
    expect(coverageFromBlindSpot({ vault_managed: 0, discovered: 0, shadow: 0, sc081_violations: 0 }).pct).toBe(0);
  });
});

describe("findingSeverityBadgeClass", () => {
  it("maps severity to a per-severity class", () => {
    expect(findingSeverityBadgeClass("critical")).toBe("finding-sev finding-sev-critical");
    expect(findingSeverityBadgeClass("info")).toBe("finding-sev finding-sev-info");
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npx vitest run lib/findings.test.ts`
Expected: FAIL — `Failed to resolve import "./findings"` / functions not defined.

- [ ] **Step 3: Write the minimal implementation**

Create `web/lib/findings.ts`:

```ts
import type { Certificate, Issuer, ReportInsight, BlindSpotSummary, ReportDocument } from "@/lib/api";
import { selectShadowCerts, selectScanIssuers } from "@/lib/report";

export type FindingSeverity = "critical" | "high" | "medium" | "low" | "info";
export type FindingKind = "insight" | "shadow" | "issuer";

export type Finding = {
  key: string;
  kind: FindingKind;
  severity: FindingSeverity;
  typeLabel: string;
  subject: string;
  secondary: string;
  vault: "shadow" | "managed" | "na";
  days: number | null;
  description?: string;
  issuerDn?: string;
  fingerprint?: string;
  serial?: string;
  cert?: Certificate;
  issuer?: Issuer;
};

// Shadow certs are unmanaged by definition; severity escalates with expiry proximity.
export function deriveShadowSeverity(cert: Certificate): FindingSeverity {
  if (cert.status === "expired" || cert.days_until_expiry < 0) return "critical";
  if (cert.days_until_expiry <= 7) return "critical";
  if (cert.days_until_expiry <= 30) return "high";
  return "medium";
}

// CA-import opportunities are lower urgency unless the CA itself is expiring.
export function deriveIssuerSeverity(issuer: Issuer): FindingSeverity {
  return issuer.days_until_expiry <= 30 ? "high" : "low";
}

// Turn a raw sc081.* / crypto.* insight type into a short human label.
function humanizeInsightType(type: string): string {
  const last = type.split(".").pop() ?? type;
  const words = last.replace(/[_-]/g, " ");
  return words.charAt(0).toUpperCase() + words.slice(1);
}

function insightToFinding(insight: ReportInsight, i: number): Finding {
  return {
    key: `insight-${insight.fingerprint_sha256 ?? insight.type}-${i}`,
    kind: "insight",
    severity: insight.severity,
    typeLabel: humanizeInsightType(insight.type),
    subject: insight.subject_cn || insight.issuer_dn || "—",
    secondary: insight.category,
    vault: "na",
    days: null,
    description: insight.description,
    issuerDn: insight.issuer_dn,
    fingerprint: insight.fingerprint_sha256,
  };
}

function shadowToFinding(cert: Certificate): Finding {
  return {
    key: `shadow-${cert.id}`,
    kind: "shadow",
    severity: deriveShadowSeverity(cert),
    typeLabel: "Shadow certificate",
    subject: cert.subject_cn || cert.serial_number,
    secondary: cert.serial_number,
    vault: cert.managed_status === "managed_in_vault" ? "managed" : "shadow",
    days: cert.days_until_expiry,
    issuerDn: cert.issuer_dn,
    fingerprint: cert.fingerprint_sha256,
    serial: cert.serial_number,
    cert,
  };
}

function issuerToFinding(iss: Issuer): Finding {
  return {
    key: `issuer-${iss.id}`,
    kind: "issuer",
    severity: deriveIssuerSeverity(iss),
    typeLabel: "CA issuer",
    subject: iss.subject_cn || iss.issuer_dn,
    secondary: iss.issuer_dn,
    vault: iss.vault_pki_mount ? "managed" : "na",
    days: iss.days_until_expiry,
    issuerDn: iss.issuer_dn,
    fingerprint: iss.fingerprint_sha256,
    issuer: iss,
  };
}

export function buildFindings(
  report: ReportDocument,
  certs: Certificate[],
  issuers: Issuer[]
): Finding[] {
  return [
    ...(report.insights ?? []).map(insightToFinding),
    ...selectShadowCerts(certs).map(shadowToFinding),
    ...selectScanIssuers(certs, issuers).map(issuerToFinding),
  ];
}

export function severityCounts(findings: Finding[]): Record<FindingSeverity, number> {
  const counts: Record<FindingSeverity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) counts[f.severity]++;
  return counts;
}

export function coverageFromBlindSpot(bs: BlindSpotSummary): {
  managed: number; shadow: number; discovered: number; pct: number;
} {
  const pct = bs.discovered > 0 ? Math.round((bs.vault_managed / bs.discovered) * 100) : 0;
  return { managed: bs.vault_managed, shadow: bs.shadow, discovered: bs.discovered, pct };
}

export function findingSeverityBadgeClass(sev: FindingSeverity): string {
  return `finding-sev finding-sev-${sev}`;
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `npx vitest run lib/findings.test.ts`
Expected: PASS (all describe blocks green).

- [ ] **Step 5: Commit**

```bash
git add web/lib/findings.ts web/lib/findings.test.ts
git commit -m "feat(web): findings view-model normalizer for the report redesign"
```

---

## Task 2: Report explorer component + styles (`components/report-explorer.tsx`)

**Files:**
- Create: `web/components/report-explorer.tsx`
- Test: `web/components/report-explorer.test.tsx`
- Modify: `web/app/globals.css` (append the report-explorer style block)

**Interfaces:**
- Consumes: `Finding`, `FindingSeverity`, `severityCounts`, `findingSeverityBadgeClass` from `@/lib/findings`; `CatalogImportButton` from `@/components/catalog-import-button`; `ImportCAButton` from `@/components/import-ca-button`; `Link` from `next/link`.
- Produces: `export default function ReportExplorer({ findings, coverage }: { findings: Finding[]; coverage: { managed: number; shadow: number; discovered: number; pct: number } })`

- [ ] **Step 1: Write the failing test**

Create `web/components/report-explorer.test.tsx`:

```tsx
import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { Finding } from "@/lib/findings";

// The row actions call the API + router; stub them so the explorer renders in isolation.
vi.mock("next/navigation", () => ({ useRouter: () => ({ refresh: vi.fn() }) }));
vi.mock("@/lib/api", async (orig) => ({ ...(await orig<typeof import("@/lib/api")>()), catalogImport: vi.fn(), importIssuer: vi.fn() }));

import ReportExplorer from "./report-explorer";

const F: Finding[] = [
  { key: "i1", kind: "insight", severity: "critical", typeLabel: "Expiry critical", subject: "api.pay", secondary: "compliance", vault: "na", days: null, description: "Expiring soon", fingerprint: "abc123" },
  { key: "s1", kind: "shadow", severity: "high", typeLabel: "Shadow certificate", subject: "legacy.vpn", secondary: "SER-1", vault: "shadow", days: 12, issuerDn: "CN=Legacy", fingerprint: "def456", serial: "SER-1",
    cert: { id: "s1", serial_number: "SER-1", fingerprint_sha256: "def456", subject_alt_names: [], issuer_dn: "CN=Legacy", not_before: "", not_after: "", days_until_expiry: 12, status: "valid", chain_status: "complete", hostname_matches_san: true, managed_status: "unmanaged", cert_scope: "external", last_seen: "2026-07-04T00:00:00Z" } },
  { key: "c1", kind: "issuer", severity: "low", typeLabel: "CA issuer", subject: "Acme CA", secondary: "CN=Acme CA", vault: "na", days: 300, issuerDn: "CN=Acme CA", fingerprint: "aa11",
    issuer: { id: "c1", fingerprint_sha256: "aa11", issuer_dn: "CN=Acme CA", not_after: "", days_until_expiry: 300, status: "valid", is_ca: true } },
];
const COVERAGE = { managed: 34, shadow: 16, discovered: 50, pct: 68 };

describe("ReportExplorer", () => {
  it("renders the coverage meter and every finding row", () => {
    render(<ReportExplorer findings={F} coverage={COVERAGE} />);
    expect(screen.getByText("68%")).toBeInTheDocument();
    expect(screen.getByText("api.pay")).toBeInTheDocument();
    expect(screen.getByText("legacy.vpn")).toBeInTheDocument();
    expect(screen.getByText("Acme CA")).toBeInTheDocument();
  });

  it("filters to a single severity when its chip is toggled", async () => {
    render(<ReportExplorer findings={F} coverage={COVERAGE} />);
    await userEvent.click(screen.getByRole("button", { name: /^Critical/ }));
    expect(screen.getByText("api.pay")).toBeInTheDocument();
    expect(screen.queryByText("legacy.vpn")).not.toBeInTheDocument();
  });

  it("filters by search over subject", async () => {
    render(<ReportExplorer findings={F} coverage={COVERAGE} />);
    await userEvent.type(screen.getByRole("searchbox"), "legacy");
    expect(screen.getByText("legacy.vpn")).toBeInTheDocument();
    expect(screen.queryByText("api.pay")).not.toBeInTheDocument();
  });

  it("reveals drill-in detail when a row is opened", async () => {
    render(<ReportExplorer findings={F} coverage={COVERAGE} />);
    await userEvent.click(screen.getByText("legacy.vpn"));
    expect(screen.getByText("CN=Legacy")).toBeInTheDocument(); // issuer DN in detail
    expect(screen.getByRole("button", { name: /Track in CLM/ })).toBeInTheDocument();
  });

  it("shows an empty state when filters match nothing", async () => {
    render(<ReportExplorer findings={F} coverage={COVERAGE} />);
    await userEvent.type(screen.getByRole("searchbox"), "zzzznope");
    expect(screen.getByText(/No findings match/i)).toBeInTheDocument();
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npx vitest run components/report-explorer.test.tsx`
Expected: FAIL — `Failed to resolve import "./report-explorer"`.

- [ ] **Step 3: Write the component**

Create `web/components/report-explorer.tsx`. It owns three pieces of filter state (`severities: Set`, `kind` string, `query` string) and renders overview → toolbar → table → drill-in. Reuse the two action components.

```tsx
"use client";

import Link from "next/link";
import { useMemo, useState } from "react";
import {
  severityCounts,
  findingSeverityBadgeClass,
  type Finding,
  type FindingSeverity,
} from "@/lib/findings";
import CatalogImportButton from "@/components/catalog-import-button";
import ImportCAButton from "@/components/import-ca-button";

const SEVERITY_ORDER: FindingSeverity[] = ["critical", "high", "medium", "low", "info"];
const SEVERITY_LABEL: Record<FindingSeverity, string> = {
  critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info",
};
const KIND_TABS = [
  { id: "all", label: "All" },
  { id: "shadow", label: "Shadow certs" },
  { id: "insight", label: "Insights" },
  { id: "issuer", label: "CA issuers" },
] as const;

type Coverage = { managed: number; shadow: number; discovered: number; pct: number };

export default function ReportExplorer({
  findings,
  coverage,
}: {
  findings: Finding[];
  coverage: Coverage;
}) {
  const [severities, setSeverities] = useState<Set<FindingSeverity>>(new Set());
  const [kind, setKind] = useState<string>("all");
  const [query, setQuery] = useState("");

  const counts = useMemo(() => severityCounts(findings), [findings]);

  const visible = useMemo(() => {
    const q = query.trim().toLowerCase();
    return findings.filter((f) => {
      if (severities.size && !severities.has(f.severity)) return false;
      if (kind !== "all" && f.kind !== kind) return false;
      if (q && !`${f.subject} ${f.secondary}`.toLowerCase().includes(q)) return false;
      return true;
    });
  }, [findings, severities, kind, query]);

  function toggleSeverity(sev: FindingSeverity) {
    setSeverities((prev) => {
      const next = new Set(prev);
      next.has(sev) ? next.delete(sev) : next.add(sev);
      return next;
    });
  }

  return (
    <div className="report-explorer">
      {/* Severity overview */}
      <div className="sev-overview">
        {SEVERITY_ORDER.map((sev) => (
          <button
            key={sev}
            type="button"
            className={`sev-card sev-${sev}${severities.has(sev) ? " active" : ""}`}
            onClick={() => toggleSeverity(sev)}
            aria-pressed={severities.has(sev)}
          >
            <span className="sev-card-n">{counts[sev]}</span>
            <span className="sev-card-lbl">{SEVERITY_LABEL[sev]}</span>
          </button>
        ))}
        <div className="coverage-card">
          <div className="coverage-top">
            <span className="coverage-pct">{coverage.pct}%</span>
            <span className="coverage-cap">Vault coverage</span>
          </div>
          <div className="coverage-meter">
            <span style={{ width: `${coverage.pct}%` }} />
          </div>
          <div className="coverage-sub">
            <b>{coverage.managed}</b> managed · <b>{coverage.shadow}</b> shadow of{" "}
            <b>{coverage.discovered}</b> on the wire
          </div>
        </div>
      </div>

      {/* Findings panel */}
      <section className="panel">
        <div className="explorer-toolbar">
          <h2>
            Findings <span className="muted">({visible.length})</span>
          </h2>
          <div className="explorer-toolbar-spacer" />
          <input
            type="search"
            className="explorer-search"
            placeholder="Search subject or serial…"
            aria-label="Search findings"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
          <div className="chip-row">
            {SEVERITY_ORDER.map((sev) => (
              <button
                key={sev}
                type="button"
                className={`filter-chip chip-${sev}${severities.has(sev) ? " on" : ""}`}
                onClick={() => toggleSeverity(sev)}
              >
                {SEVERITY_LABEL[sev]}
              </button>
            ))}
          </div>
          <div className="kind-seg">
            {KIND_TABS.map((t) => (
              <button
                key={t.id}
                type="button"
                className={kind === t.id ? "on" : ""}
                onClick={() => setKind(t.id)}
              >
                {t.label}
              </button>
            ))}
          </div>
        </div>

        <div className="data-table-wrap">
          {visible.length === 0 ? (
            <p className="muted" style={{ padding: "24px 20px", textAlign: "center" }}>
              No findings match the current filters.
            </p>
          ) : (
            <table className="data-table findings-table">
              <thead>
                <tr>
                  <th>Severity</th>
                  <th>Finding</th>
                  <th>Subject</th>
                  <th>Vault status</th>
                  <th>Days left</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {visible.map((f) => (
                  <FindingRow key={f.key} f={f} />
                ))}
              </tbody>
            </table>
          )}
        </div>
      </section>
    </div>
  );
}

function daysClass(days: number | null): string {
  if (days === null) return "";
  if (days < 0) return "days-neg";
  if (days <= 30) return "days-warn";
  return "";
}
function daysText(days: number | null): string {
  if (days === null) return "—";
  return days < 0 ? `${Math.abs(days)}d ago` : `${days}d`;
}

function FindingRow({ f }: { f: Finding }) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <tr
        className={`finding-row sev-row-${f.severity}${open ? " open" : ""}`}
        onClick={() => setOpen((v) => !v)}
        tabIndex={0}
        onKeyDown={(e) => {
          if (e.key === "Enter" || e.key === " ") {
            e.preventDefault();
            setOpen((v) => !v);
          }
        }}
      >
        <td className="sev-cell">
          <span className={findingSeverityBadgeClass(f.severity)}>{f.severity}</span>
        </td>
        <td>{f.typeLabel}</td>
        <td>
          <span className="finding-subject">{f.subject}</span>
          <span className="finding-secondary">{f.secondary}</span>
        </td>
        <td>
          {f.vault === "shadow" ? (
            <span className="vault-pip vault-shadow">Shadow</span>
          ) : f.vault === "managed" ? (
            <span className="vault-pip vault-managed">Managed</span>
          ) : (
            <span className="muted">—</span>
          )}
        </td>
        <td className={`tnum ${daysClass(f.days)}`}>{daysText(f.days)}</td>
        <td>
          <span className="row-caret" aria-hidden>{open ? "▾" : "▸"}</span>
        </td>
      </tr>
      {open && (
        <tr className="finding-detail">
          <td colSpan={6}>
            <div className="finding-detail-inner">
              {f.description && <p className="finding-detail-desc">{f.description}</p>}
              <div className="finding-detail-grid">
                {f.issuerDn && <Kv k="Issuer" v={f.issuerDn} />}
                {f.serial && <Kv k="Serial" v={f.serial} mono />}
                {f.fingerprint && <Kv k="Fingerprint (SHA-256)" v={f.fingerprint} mono />}
                {f.cert && <Kv k="Last seen" v={new Date(f.cert.last_seen).toLocaleString()} />}
                {f.cert && <Kv k="Scope" v={f.cert.cert_scope} />}
              </div>
              <div className="finding-detail-actions">
                {f.cert && <CatalogImportButton cert={f.cert} />}
                {f.issuer && <ImportCAButton issuer={f.issuer} />}
                {f.cert && (
                  <Link className="button button-secondary" href={`/certificates/${f.cert.id}`}>
                    View certificate
                  </Link>
                )}
              </div>
            </div>
          </td>
        </tr>
      )}
    </>
  );
}

function Kv({ k, v, mono = false }: { k: string; v: string; mono?: boolean }) {
  return (
    <div className="kv">
      <div className="kv-k">{k}</div>
      <div className={`kv-v${mono ? " mono" : ""}`}>{v}</div>
    </div>
  );
}
```

- [ ] **Step 4: Append the styles**

Append this block to the END of `web/app/globals.css` (all colors via HDS tokens):

```css
/* ===== Report explorer (redesign) ===== */
.report-explorer { display: flex; flex-direction: column; gap: 24px; }

.sev-overview { display: grid; grid-template-columns: repeat(5, 1fr) 1.6fr; gap: 12px; }
@media (max-width: 860px) { .sev-overview { grid-template-columns: repeat(3, 1fr); } }
@media (max-width: 520px) { .sev-overview { grid-template-columns: repeat(2, 1fr); } }

.sev-card {
  position: relative; overflow: hidden; text-align: left; cursor: pointer;
  padding: 13px 14px; border: 1px solid var(--token-color-border-faint);
  border-radius: var(--token-border-radius-small); background: var(--token-color-surface-primary);
}
.sev-card::before { content: ""; position: absolute; left: 0; top: 0; bottom: 0; width: 3px; background: var(--stripe); }
.sev-card.active { border-color: var(--stripe); }
.sev-card-n { display: block; font-size: 28px; font-weight: 700; color: var(--token-color-foreground-strong); line-height: 1; }
.sev-card-lbl { display: block; margin-top: 6px; font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: .05em; color: var(--sevfg); }
.sev-critical { --stripe: var(--token-color-palette-red-200); --sevfg: var(--token-color-palette-red-200); }
.sev-high { --stripe: #db6216; --sevfg: #b5470f; }
.sev-medium { --stripe: var(--token-color-palette-amber-200); --sevfg: var(--token-color-palette-amber-200); }
.sev-low { --stripe: var(--token-color-palette-blue-200); --sevfg: var(--token-color-palette-blue-200); }
.sev-info { --stripe: var(--token-color-foreground-faint); --sevfg: var(--token-color-foreground-faint); }

.coverage-card {
  display: flex; flex-direction: column; justify-content: center;
  padding: 13px 16px; border: 1px solid var(--token-color-border-faint);
  border-radius: var(--token-border-radius-small); background: var(--token-color-surface-primary);
}
.coverage-top { display: flex; align-items: baseline; justify-content: space-between; gap: 8px; }
.coverage-pct { font-size: 28px; font-weight: 700; color: var(--token-color-foreground-strong); line-height: 1; }
.coverage-cap { font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: .05em; color: var(--token-color-foreground-faint); }
.coverage-meter { height: 8px; border-radius: 5px; background: var(--token-color-surface-faint); border: 1px solid var(--token-color-border-faint); overflow: hidden; margin: 10px 0 8px; }
.coverage-meter > span { display: block; height: 100%; background: var(--token-color-palette-green-200); }
.coverage-sub { font-size: 12px; color: var(--token-color-foreground-faint); }
.coverage-sub b { color: var(--token-color-foreground-strong); }

.explorer-toolbar { display: flex; align-items: center; gap: 12px; padding: 13px 16px; border-bottom: 1px solid var(--token-color-border-faint); flex-wrap: wrap; }
.explorer-toolbar h2 { margin: 0; font-size: 14px; color: var(--token-color-foreground-strong); }
.explorer-toolbar-spacer { flex: 1; }
.explorer-search { height: 32px; width: 210px; max-width: 46vw; padding: 0 10px; border: 1px solid var(--token-color-border-primary); border-radius: var(--token-border-radius-small); background: var(--token-color-surface-faint); color: var(--token-color-foreground-strong); font-size: 13px; }

.chip-row { display: flex; gap: 6px; flex-wrap: wrap; }
.filter-chip { height: 28px; padding: 0 11px; border-radius: 20px; cursor: pointer; border: 1px solid var(--token-color-border-primary); background: var(--token-color-surface-primary); color: var(--token-color-foreground-primary); font-size: 12.5px; font-weight: 550; }
.filter-chip.on { background: var(--token-color-foreground-strong); border-color: var(--token-color-foreground-strong); color: var(--token-color-surface-primary); }

.kind-seg { display: inline-flex; border: 1px solid var(--token-color-border-primary); border-radius: var(--token-border-radius-small); overflow: hidden; }
.kind-seg button { height: 28px; padding: 0 12px; background: var(--token-color-surface-primary); border: 0; border-right: 1px solid var(--token-color-border-primary); color: var(--token-color-foreground-faint); font-size: 12.5px; font-weight: 550; cursor: pointer; }
.kind-seg button:last-child { border-right: 0; }
.kind-seg button.on { background: var(--token-color-surface-action); color: var(--token-color-foreground-action); }

.findings-table tbody tr.finding-row { cursor: pointer; }
.findings-table td.sev-cell { border-left: 3px solid transparent; }
.findings-table tr.sev-row-critical td.sev-cell { border-left-color: var(--token-color-palette-red-200); }
.findings-table tr.sev-row-high td.sev-cell { border-left-color: #db6216; }
.findings-table tr.sev-row-medium td.sev-cell { border-left-color: var(--token-color-palette-amber-200); }
.findings-table tr.sev-row-low td.sev-cell { border-left-color: var(--token-color-palette-blue-200); }
.findings-table tr.sev-row-info td.sev-cell { border-left-color: var(--token-color-border-strong); }

.finding-sev { display: inline-flex; align-items: center; height: 21px; padding: 0 8px; border-radius: 4px; font-size: 11px; font-weight: 650; text-transform: uppercase; letter-spacing: .03em; }
.finding-sev-critical { color: var(--token-color-palette-red-200); background: var(--token-color-surface-critical); }
.finding-sev-high { color: #b5470f; background: #fbede2; }
.finding-sev-medium { color: var(--token-color-palette-amber-200); background: var(--token-color-surface-warning); }
.finding-sev-low { color: var(--token-color-palette-blue-200); background: #e9f1fc; }
.finding-sev-info { color: var(--token-color-foreground-faint); background: var(--token-color-surface-faint); }

.finding-subject { display: block; color: var(--token-color-foreground-strong); font-weight: 550; }
.finding-secondary { display: block; font-family: var(--token-typography-code-100-font-family, monospace); font-size: 11.5px; color: var(--token-color-foreground-faint); }
.vault-pip { display: inline-flex; align-items: center; gap: 6px; font-size: 12.5px; }
.vault-pip::before { content: ""; width: 7px; height: 7px; border-radius: 50%; background: currentColor; }
.vault-shadow { color: var(--token-color-palette-red-200); }
.vault-managed { color: var(--token-color-palette-green-200); }
.days-neg { color: var(--token-color-palette-red-200); font-weight: 600; }
.days-warn { color: #b5470f; font-weight: 600; }
.row-caret { color: var(--token-color-foreground-faint); }

.finding-detail > td { padding: 0; background: var(--token-color-surface-faint); }
.finding-detail-inner { padding: 16px 20px; }
.finding-detail-desc { margin: 0 0 12px; color: var(--token-color-foreground-primary); font-size: 13px; }
.finding-detail-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px 24px; margin-bottom: 14px; }
.kv-k { font-size: 10.5px; text-transform: uppercase; letter-spacing: .05em; color: var(--token-color-foreground-faint); font-weight: 600; margin-bottom: 3px; }
.kv-v { font-size: 13px; color: var(--token-color-foreground-strong); }
.kv-v.mono { font-family: var(--token-typography-code-100-font-family, monospace); font-size: 12px; word-break: break-all; }
.finding-detail-actions { display: flex; gap: 8px; flex-wrap: wrap; align-items: flex-start; }
```

> **Implementer note:** The exact HDS token names above (`--token-color-surface-critical`, `--token-color-surface-action`, `--token-color-foreground-action`, `--token-border-radius-small`) must be verified against `web/styles/hds-tokens.css` before finalizing — grep the file and substitute the nearest existing token if any name is absent. A few literal hex values (the "high"/orange severity, `#e9f1fc`, `#fbede2`) are intentional because HDS has no dedicated "high" severity token; keep them.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `npx vitest run components/report-explorer.test.tsx`
Expected: PASS (all 5 tests green).

- [ ] **Step 6: Commit**

```bash
git add web/components/report-explorer.tsx web/components/report-explorer.test.tsx web/app/globals.css
git commit -m "feat(web): report explorer — severity overview, filterable findings, drill-in"
```

---

## Task 3: Wire the explorer into the report page

**Files:**
- Modify: `web/app/scans/[id]/report/page.tsx`

**Interfaces:**
- Consumes: `buildFindings`, `coverageFromBlindSpot` from `@/lib/findings`; `ReportExplorer` from `@/components/report-explorer`.

- [ ] **Step 1: Replace the four panels with the explorer**

In `web/app/scans/[id]/report/page.tsx`:

1. Add imports at the top:

```tsx
import ReportExplorer from "@/components/report-explorer";
import { buildFindings, coverageFromBlindSpot } from "@/lib/findings";
```

2. Remove the now-unused imports `CatalogImportButton`, `ImportCAButton`, `severityBadgeClass`, `statusBadgeClass`, `selectShadowCerts`, `selectScanIssuers` (the explorer + normalizer own these now). Keep `Link`, `PageHeader`, `ReportDownloadMenu`, and the `fetchReport`/`getScan`/`listScanCertificates`/`listIssuers` fetchers.

3. Replace the body computation `const shadowCerts = ...` / `const scanIssuers = ...` and the local `StatTile` helper with:

```tsx
const findings = buildFindings(report, certs, issuers);
const coverage = coverageFromBlindSpot(report.blind_spot);
```

4. Replace the four `<section className="panel">` blocks (Summary, Insights, shadow certs, issuers) with a single:

```tsx
<ReportExplorer findings={findings} coverage={coverage} />
```

Keep the `PageHeader` (with `ReportDownloadMenu`) and the `recommendations.length > 0` "Recommended actions" section. Delete the trailing local `StatTile` function.

- [ ] **Step 2: Typecheck and lint**

Run: `npx tsc --noEmit && npm run lint`
Expected: exit 0, no errors (no unused-import warnings).

- [ ] **Step 3: Run the full test suite**

Run: `npm test`
Expected: PASS — all suites, including the two new ones.

- [ ] **Step 4: Verify in the running app**

Start the stack and load a completed scan's report; confirm the overview counts, coverage meter, severity filtering, search, drill-in, and the Track-in-CLM / Import-CA actions all work. (Use the project's `verify` / `run` skill, or `NEXT_PUBLIC_API_URL=http://localhost:8080 npm run dev` against a running API.)

- [ ] **Step 5: Commit**

```bash
git add web/app/scans/[id]/report/page.tsx
git commit -m "feat(web): render the report page through the new explorer"
```

---

## Task 4: Docs, review, follow-up TODO, PR

- [ ] **Step 1: Update `progress.md`.** Move the "Report redesign" item from
  "In progress / next" to reflect it as implemented on `feature/73-report-redesign`
  (severity overview + unified findings explorer + drill-in, normalizer
  `lib/findings.ts`). Commit: `docs(#73): note report redesign in progress.md`.

- [ ] **Step 2: File the configurable-severity follow-up.** Per the spec's
  Future-work section (user request), create a GitHub issue to make the shadow/issuer
  severity thresholds in `lib/findings.ts` configurable rather than hard-coded:

  ```bash
  gh issue create --title "feat(web): make report severity rubric thresholds configurable" \
    --label enhancement \
    --body "Follow-up to #73. deriveShadowSeverity / deriveIssuerSeverity in web/lib/findings.ts hard-code the expiry thresholds (7/30 days). Make the baseline configurable (env/config or per-deployment policy) so operators can tune what counts as critical/high. Out of scope of #73 by agreement."
  ```

- [ ] **Step 3: Subagent code review.** Dispatch `pr-review-toolkit:code-reviewer`
  on `git diff main...HEAD -- web/`, focusing on: the findings normalizer's
  severity logic + key uniqueness, accessibility of the clickable rows and filter
  controls (keyboard, accessible names), and HDS-token correctness in the CSS.
  Address findings (fix + re-run tests) before opening the PR.

- [ ] **Step 4: Verify + open the PR.** Run `npx tsc --noEmit`, `npm test`,
  `npm run build`. Then:

  ```bash
  git push -u origin feature/73-report-redesign
  gh pr create --title "feat(#73): redesign the environment report (Vault Radar style)" --body "$(cat <<'EOF'
## Summary
- Rebuilds /scans/{id}/report as a severity overview + Vault-coverage meter + one filterable findings table (severity + kind filters, search) + per-row drill-in, replacing the four flat panels. Normalizer extracted to tested web/lib/findings.ts.

## Related issues
Fixes #73

## Superpowers
- Spec: docs/superpowers/specs/2026-07-09-report-redesign-design.md
- Plan: docs/superpowers/plans/2026-07-09-report-redesign.md

## Test plan
- [x] npx tsc --noEmit
- [x] npm test (new findings.test.ts + report-explorer.test.tsx)
- [x] cd web && npm run build
- [ ] Manual dashboard check on a completed scan (overview, filters, search, drill-in, Track-in-CLM / Import-CA)
- n/a go test/go build — web-only change

## Breaking changes
None.
EOF
)"
  ```

---

## Self-Review (completed against the approved mockup)

- **Severity overview bar** → Task 2 `.sev-overview` (5 cards + coverage meter). ✓
- **Unified filterable findings table** → Task 1 `buildFindings` + Task 2 table with severity chips, kind segment, search. ✓
- **Severity badges + risk emphasis** → Task 2 `finding-sev-*` badges + `sev-cell` left stripe + `days-neg/warn`. ✓
- **Detail drill-in** → Task 2 `FindingRow` expandable detail with issuer/serial/fingerprint/last-seen/scope + actions. ✓
- **Deviations from mockup (intentional, documented above):** no IP:port endpoint column (not in the data model); status segment replaced by a kind filter (no ignored state); light-only. ✓
- **Type consistency:** `Finding`, `FindingSeverity`, `coverage` shape, and helper names are identical across Task 1 (definition), Task 2 (consumer), and Task 3 (wiring). ✓
- **Placeholder scan:** every code step contains complete code; the one open item (exact HDS token names) is flagged with a concrete verification step, not left as "TBD". ✓
