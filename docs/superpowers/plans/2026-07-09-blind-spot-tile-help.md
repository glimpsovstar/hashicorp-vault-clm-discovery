# Blind-spot Tile Help Popovers — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move the "?" help popovers off the two action controls and onto the `On wire`, `Shadow certs`, and `SC-081 violations` metric tiles on the Blind-spot reveal card.

**Architecture:** Extend the local `StatTile` helper in `blind-spot-card.tsx` with an optional `help?: ReactNode`; render a `HelpPopover` inside the tile label when provided. Remove the two existing `HelpPopover`s (and their `action-with-help` wrappers) from the "Show shadow certs" button and "View report" link. One CSS rule makes `.stat-tile-label` a flex row.

**Tech Stack:** Next.js 15 + React 19 + TypeScript. Vitest + @testing-library/react. Plain global CSS with HDS tokens.

## Global Constraints

- Issue #71; branch `fix/71-blind-spot-tile-help` (already created off `main`).
- Spec: `docs/superpowers/specs/2026-07-09-blind-spot-tile-help-design.md`.
- UI copy only — no API / data-model / scan-policy change (no `require-docs.mdc` trigger); still update `progress.md`.
- All commands run from `/Users/djoo/Documents/Personal/Projects/CLM-discovery/web`.
- Commit as David Joo, no `Co-Authored-By` trailer.

---

## Task 1: Move the help popovers to the metric tiles (test-first)

**Files:**
- Test: `web/components/blind-spot-card.test.tsx` (create)
- Modify: `web/components/blind-spot-card.tsx`
- Modify: `web/app/globals.css` (`.stat-tile-label`)

**Interfaces:**
- `StatTile` gains an optional prop: `help?: ReactNode`. Existing callers without `help` are unaffected.
- `HelpPopover` (existing) `label` prop is set to `What is “<label>”?` for tile popovers, so each tile's help trigger has a unique, queryable accessible name.

- [ ] **Step 1: Write the failing test**

Create `web/components/blind-spot-card.test.tsx`:

```tsx
import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";

// fetchBlindSpot runs in an effect on mount; stub the API module so the card
// renders in isolation. triggerReconcile is unused by these assertions.
vi.mock("@/lib/api", () => ({
  fetchBlindSpot: vi.fn().mockResolvedValue({
    vault_managed: 34, discovered: 50, shadow: 16, sc081_violations: 4,
  }),
  triggerReconcile: vi.fn(),
}));

import BlindSpotCard from "./blind-spot-card";

function renderCard() {
  return render(<BlindSpotCard scanId="s1" scanStatus="completed" />);
}

describe("BlindSpotCard help popovers", () => {
  it("puts a help popover on On wire, Shadow certs, and SC-081 violations", async () => {
    renderCard();
    // Flush the mount effect so any state settle happens inside act().
    expect(await screen.findByRole("button", { name: /What is .*On wire/ })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /What is .*Shadow certs/ })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /What is .*SC-081 violations/ })).toBeInTheDocument();
  });

  it("does not put a help popover on Vault managed", async () => {
    renderCard();
    await screen.findByRole("button", { name: /What is .*On wire/ });
    expect(screen.queryByRole("button", { name: /What is .*Vault managed/ })).toBeNull();
  });

  it("leaves Show shadow certs and View report as plain controls (no help popover)", async () => {
    renderCard();
    await screen.findByRole("button", { name: /What is .*On wire/ });
    expect(screen.getByRole("button", { name: /Show shadow certs/ })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /View report/ })).toBeInTheDocument();
    // The old popovers were labelled "What does Show shadow certs do?" / "What is the report?".
    expect(screen.queryByRole("button", { name: /What does Show shadow certs/ })).toBeNull();
    expect(screen.queryByRole("button", { name: /What is the report/ })).toBeNull();
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npx vitest run components/blind-spot-card.test.tsx`
Expected: FAIL — the tile help triggers don't exist yet (no button named `What is … On wire`), and the old `What does Show shadow certs do?` popover still exists.

- [ ] **Step 3: Implement — update `StatTile` and move the popovers**

In `web/components/blind-spot-card.tsx`:

1. Add `ReactNode` to the React import:

```tsx
import { useCallback, useEffect, useState, type ReactNode } from "react";
```

2. Add `help` to the three tiles (leave `Vault managed` unchanged):

```tsx
<div className="stat-grid">
  <StatTile label="Vault managed" value={summary?.vault_managed ?? "—"} />
  <StatTile
    label="On wire"
    value={summary?.discovered ?? "—"}
    help={
      <>
        Certificates observed live during this scan — every TLS endpoint
        that presented a certificate on the wire.
      </>
    }
  />
  <StatTile
    label="Shadow certs"
    value={summary?.shadow ?? "—"}
    help={
      <>
        On the wire but <strong>not issued by Vault</strong> — deployed yet
        unmanaged. These are your blind spots. Run <em>Show shadow certs</em>{" "}
        to refresh this count.
      </>
    }
  />
  <StatTile
    label="SC-081 violations"
    value={summary?.sc081_violations ?? "—"}
    help={
      <>
        Certificates that breach the <strong>SC-081</strong> compliance rules
        — expiry thresholds and excessive issued validity. Each is a finding
        that needs remediation.
      </>
    }
  />
</div>
```

3. Replace the `table-actions` block so the controls are plain (drop both `HelpPopover`s and the `action-with-help` spans):

```tsx
<div className="table-actions" style={{ marginTop: 16 }}>
  {vaultConfigured && (
    <button
      type="button"
      className="button button-primary"
      onClick={() => void handleReconcile()}
      disabled={reconciling}
    >
      {reconciling ? "Checking…" : "Show shadow certs"}
    </button>
  )}
  <Link className="button button-secondary" href={`/scans/${scanId}/report`}>
    View report
  </Link>
</div>
```

4. Update the `StatTile` helper to render the optional help node inside the label:

```tsx
function StatTile({
  label,
  value,
  help,
}: {
  label: string;
  value: number | string;
  help?: ReactNode;
}) {
  return (
    <div className="stat-tile">
      <div className="stat-tile-label">
        {label}
        {help && <HelpPopover label={`What is “${label}”?`}>{help}</HelpPopover>}
      </div>
      <div className="stat-tile-value">{value}</div>
    </div>
  );
}
```

(`HelpPopover` is already imported. The `action-with-help` CSS class becomes unused in this file — that is acceptable; it is a shared class and not removed here.)

- [ ] **Step 4: Add the CSS rule**

In `web/app/globals.css`, replace the `.stat-tile-label` rule with:

```css
.stat-tile-label {
  display: flex;
  align-items: center;
  gap: 2px;
  font-size: var(--token-typography-body-100-font-size);
  color: var(--token-color-foreground-faint);
  margin-bottom: 4px;
}
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `npx vitest run components/blind-spot-card.test.tsx`
Expected: PASS (all 3 tests green).

- [ ] **Step 6: Verify typecheck and full suite**

Run: `npx tsc --noEmit && npm test`
Expected: exit 0; all suites pass.

- [ ] **Step 7: Commit**

```bash
git add web/components/blind-spot-card.tsx web/components/blind-spot-card.test.tsx web/app/globals.css
git commit -m "fix(#71): move blind-spot help popovers onto the metric tiles"
```

---

## Task 2: Docs, verify, review, PR

- [ ] **Step 1: Update `progress.md`**

Add a one-line entry under the appropriate "Done"/recent section noting: "#71 — blind-spot help popovers moved onto the On wire / Shadow certs / SC-081 tiles." Commit:

```bash
git add progress.md
git commit -m "docs(#71): note blind-spot tile-help change in progress.md"
```

- [ ] **Step 2: Web build verification**

Run: `npm run build`
Expected: build succeeds. (No Go behavior changed, so `go test`/`go build` are not required by `require-tests.mdc` for this web-only change; run the web build as the relevant verification.)

- [ ] **Step 3: Subagent code review**

Dispatch `pr-review-toolkit:code-reviewer` on `git diff main...HEAD -- web/`. Focus: accessibility of the tile popovers (unique accessible names, keyboard/focus), no regression to the reconcile flow, copy accuracy. Address any findings (fix + re-run tests) before the PR.

- [ ] **Step 4: Open the PR**

```bash
git push -u origin fix/71-blind-spot-tile-help
gh pr create --title "fix(#71): move blind-spot help popovers onto the metric tiles" --body "$(cat <<'EOF'
## Summary
- Moves the "?" help popovers off the "Show shadow certs" / "View report" controls onto the On wire, Shadow certs, and SC-081 violations tiles.

## Related issues
Fixes #71

## Superpowers
- Spec: docs/superpowers/specs/2026-07-09-blind-spot-tile-help-design.md
- Plan: docs/superpowers/plans/2026-07-09-blind-spot-tile-help.md

## Test plan
- [x] npx tsc --noEmit
- [x] npm test (new blind-spot-card.test.tsx)
- [x] cd web && npm run build
- [ ] Manual dashboard check: open each of the three tile popovers on a completed scan

## Breaking changes
None.
EOF
)"
```

---

## Self-Review

- **Spec coverage:** every acceptance criterion in the spec maps to an assertion in Task 1's test (three tiles have popovers; Vault managed + action controls do not; inline layout via CSS) and to Task 2 (docs, verify, review). ✓
- **Placeholder scan:** all code steps contain complete code; no TBD/TODO. ✓
- **Type consistency:** `StatTile`'s new `help?: ReactNode` prop is used identically in the test expectations (accessible name `What is “<label>”?`) and the implementation. ✓
