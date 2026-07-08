# Report Viewer & Inline Actions Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the file-first "Download report" with a view-first `/scans/{id}/report` page that renders the environment report in the Vault UI, surfaces per-cert / per-issuer import actions, and clarifies the blind-spot card buttons with a help popover.

**Architecture:** Frontend-only (Next.js `web/`). The report page is a server component that fetches the existing JSON report + scan certs + issuers in parallel and delegates row actions to existing client buttons. Selection logic (which certs are "shadow", which issuers were seen in the scan) is extracted into pure helpers so it is unit-testable outside React. No backend/API changes.

**Tech Stack:** Next.js 15 (App Router, React 19), TypeScript, Vitest + Testing Library, existing HDS design tokens.

Issue: #68 · Spec: `docs/superpowers/specs/2026-07-09-report-viewer-and-inline-actions-design.md`

## Global Constraints

- **No backend changes** — consume only existing endpoints (`/scans/{id}/report?format=json|md|csv`, `/scans/{id}/certificates`, `/issuers`, `catalog-import`, `issuers/{id}/import`).
- **Design system:** reuse existing classes/components (`panel`, `stat-tile`, `data-table`, `button`, `badge`) and HDS `--token-color-*` variables; no hard-coded colors.
- **Reuse over reinvention:** row actions use the existing `CatalogImportButton` and `ImportCAButton`.
- **Shadow-cert definition:** a cert is shadow when `managed_status !== "managed_in_vault"` (already-`imported` certs remain listed, shown as "Tracked").
- **Verify commands:** `cd web && npm test`, `npm run build`; `go build ./...` (unaffected sanity check).

---

### Task 1: Reusable `HelpPopover` component — DONE (characterization tests pending in Task 4)

**Files:**
- Created: `web/components/help-popover.tsx`
- Styles: `web/app/globals.css` (`.help-popover*`, `.action-with-help`)

**Interfaces:**
- Produces: `HelpPopover({ label?: string, children: ReactNode })` — a `?` trigger that toggles a `role="tooltip"` panel; closes on Escape (refocuses trigger) and outside click; sets `aria-expanded` / `aria-controls`.

- [x] Component implemented and styled.
- [ ] Tests added in Task 4 (behavior gate before PR).

---

### Task 2: Report download menu + relocate catalog button — DONE

**Files:**
- Created: `web/components/report-download-menu.tsx`
- Renamed: `web/app/certificates/[id]/catalog-import-button.tsx` → `web/components/catalog-import-button.tsx`
- Modified: `web/app/certificates/[id]/page.tsx` (import path)

**Interfaces:**
- Produces: `ReportDownloadMenu({ scanId })` — dropdown calling `downloadReport(scanId, "markdown"|"csv"|"json")`.
- `CatalogImportButton` now importable from `@/components/catalog-import-button` (shared by cert detail + report page).

- [x] Done and building.

---

### Task 3: Extract report selection helpers (TDD) — TODO

Pull the "which rows to show" logic out of the server component into pure functions so it is testable without rendering. Refactor the page to consume them.

**Files:**
- Create: `web/lib/report.ts`
- Test: `web/lib/report.test.ts`
- Modify: `web/app/scans/[id]/report/page.tsx` (use the helpers)

**Interfaces:**
- Produces:
  - `selectShadowCerts(certs: Certificate[]): Certificate[]` — certs where `managed_status !== "managed_in_vault"`.
  - `selectScanIssuers(certs: Certificate[], issuers: Issuer[]): Issuer[]` — issuers where `is_ca` and `issuer_dn` appears among `certs`.
- Consumes: `Certificate`, `Issuer` from `@/lib/api`.

- [ ] **Step 1: Write the failing test**

```ts
// web/lib/report.test.ts
import { describe, it, expect } from "vitest";
import { selectShadowCerts, selectScanIssuers } from "./report";
import type { Certificate, Issuer } from "./api";

function cert(over: Partial<Certificate>): Certificate {
  return {
    id: "c", serial_number: "1", fingerprint_sha256: "f", subject_alt_names: [],
    issuer_dn: "CN=Test CA", not_before: "", not_after: "", days_until_expiry: 10,
    status: "valid", chain_status: "complete", hostname_matches_san: true,
    managed_status: "unmanaged", cert_scope: "external", last_seen: "", ...over,
  };
}
function issuer(over: Partial<Issuer>): Issuer {
  return {
    id: "i", fingerprint_sha256: "f", issuer_dn: "CN=Test CA", not_after: "",
    days_until_expiry: 100, status: "valid", is_ca: true, ...over,
  };
}

describe("selectShadowCerts", () => {
  it("includes unmanaged and imported, excludes managed_in_vault", () => {
    const certs = [
      cert({ id: "a", managed_status: "unmanaged" }),
      cert({ id: "b", managed_status: "imported" }),
      cert({ id: "c", managed_status: "managed_in_vault" }),
    ];
    expect(selectShadowCerts(certs).map((c) => c.id)).toEqual(["a", "b"]);
  });
});

describe("selectScanIssuers", () => {
  it("keeps CA issuers whose DN was seen in the scan", () => {
    const certs = [cert({ issuer_dn: "CN=Seen CA" })];
    const issuers = [
      issuer({ id: "seen", issuer_dn: "CN=Seen CA", is_ca: true }),
      issuer({ id: "unseen", issuer_dn: "CN=Other CA", is_ca: true }),
      issuer({ id: "leaf", issuer_dn: "CN=Seen CA", is_ca: false }),
    ];
    expect(selectScanIssuers(certs, issuers).map((i) => i.id)).toEqual(["seen"]);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd web && npx vitest run lib/report.test.ts`
Expected: FAIL — `Cannot find module './report'`.

- [ ] **Step 3: Write minimal implementation**

```ts
// web/lib/report.ts
import type { Certificate, Issuer } from "@/lib/api";

// selectShadowCerts returns certs on the wire but not matched to Vault PKI.
// Already-tracked (`imported`) certs are kept so tracking one does not remove it
// from the list; the action button renders a disabled "Tracked" state for those.
export function selectShadowCerts(certs: Certificate[]): Certificate[] {
  return certs.filter((c) => c.managed_status !== "managed_in_vault");
}

// selectScanIssuers returns CA issuers observed in this scan, matched to the
// global issuer list by DN (the only join available without a backend change).
export function selectScanIssuers(certs: Certificate[], issuers: Issuer[]): Issuer[] {
  const dns = new Set(certs.map((c) => c.issuer_dn));
  return issuers.filter((i) => i.is_ca && dns.has(i.issuer_dn));
}
```

- [ ] **Step 4: Refactor the page to use the helpers**

In `web/app/scans/[id]/report/page.tsx`, replace the inline `filter`/`Set` blocks with:

```tsx
import { selectShadowCerts, selectScanIssuers } from "@/lib/report";
// ...
const shadowCerts = selectShadowCerts(certs);
const scanIssuers = selectScanIssuers(certs, issuers);
```

- [ ] **Step 5: Run test + build**

Run: `cd web && npx vitest run lib/report.test.ts && npm run build`
Expected: tests PASS, build succeeds.

- [ ] **Step 6: Commit**

```bash
git add web/lib/report.ts web/lib/report.test.ts "web/app/scans/[id]/report/page.tsx"
git commit -m "refactor(#68): extract report row-selection helpers with tests"
```

---

### Task 4: `HelpPopover` behavior tests — TODO

**Files:**
- Test: `web/components/help-popover.test.tsx`

**Interfaces:**
- Consumes: `HelpPopover` from Task 1.

- [ ] **Step 1: Write the failing test**

```tsx
// web/components/help-popover.test.tsx
import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import HelpPopover from "./help-popover";

describe("HelpPopover", () => {
  it("is closed initially and opens on click", async () => {
    render(<HelpPopover label="Explain">Hello help</HelpPopover>);
    const trigger = screen.getByRole("button", { name: "Explain" });
    expect(trigger).toHaveAttribute("aria-expanded", "false");
    expect(screen.queryByRole("tooltip")).toBeNull();
    await userEvent.click(trigger);
    expect(trigger).toHaveAttribute("aria-expanded", "true");
    expect(screen.getByRole("tooltip")).toHaveTextContent("Hello help");
  });

  it("closes on Escape", async () => {
    render(<HelpPopover label="Explain">Hello help</HelpPopover>);
    const trigger = screen.getByRole("button", { name: "Explain" });
    await userEvent.click(trigger);
    await userEvent.keyboard("{Escape}");
    expect(screen.queryByRole("tooltip")).toBeNull();
  });

  it("closes on outside click", async () => {
    render(
      <div>
        <HelpPopover label="Explain">Hello help</HelpPopover>
        <button>outside</button>
      </div>
    );
    await userEvent.click(screen.getByRole("button", { name: "Explain" }));
    await userEvent.click(screen.getByRole("button", { name: "outside" }));
    expect(screen.queryByRole("tooltip")).toBeNull();
  });
});
```

- [ ] **Step 2: Run test to verify it passes** (component already exists)

Run: `cd web && npx vitest run components/help-popover.test.tsx`
Expected: PASS (3 tests). If any fail, fix `help-popover.tsx` to satisfy the behavior.

- [ ] **Step 3: Commit**

```bash
git add web/components/help-popover.test.tsx
git commit -m "test(#68): HelpPopover open/close behavior"
```

---

### Task 5: README dashboard docs for the report page — TODO

**Files:**
- Modify: `README.md` (Dashboard UI section)

- [ ] **Step 1: Add a short "Report viewer" note** under the Dashboard UI section describing: View report (view-first), Download menu (md/csv/json), and in-report import actions (Track in CLM per shadow cert, Import CA to Vault per issuer). Note this is additive to the section #67 also edits — resolve the README on rebase if #67 merges first.

- [ ] **Step 2: Verify markdown renders / lint clean, then commit**

```bash
git add README.md
git commit -m "docs(#68): document the report viewer page"
```

---

### Task 6: Full verification + subagent code review — TODO

- [ ] `cd web && npm test` → all suites pass.
- [ ] `cd web && npm run build` → build succeeds, `/scans/[id]/report` route present.
- [ ] `go build ./...` → unaffected sanity check.
- [ ] Dispatch the `pr-review-toolkit:code-reviewer` subagent on `git diff main...feature/68-report-viewer`; triage and fix findings (commit fixes).
- [ ] Manual smoke (when a stack is running): complete scan → View report → Download each format → Track in CLM flips a shadow row → Import CA reflects Vault state.

---

## Self-Review

**Spec coverage:** report page (Tasks 2–3, done+refactor), download menu (Task 2), in-report import both cert + CA (Task 3 wires existing buttons), blind-spot card relabel + View report + popovers (in the shipped feature commit; verified in Task 6 review), HelpPopover (Tasks 1, 4), docs (Task 5). All spec sections map to a task.

**Placeholder scan:** none — every code step shows the code; the one prose step (Task 5) is a doc edit.

**Type consistency:** helper signatures (`selectShadowCerts`, `selectScanIssuers`) match usage in the page refactor and the test fixtures; `Certificate`/`Issuer` come from `@/lib/api`.
