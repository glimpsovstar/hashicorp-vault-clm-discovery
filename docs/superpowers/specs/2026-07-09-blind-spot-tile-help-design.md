# Blind-spot tile help popovers — Design Spec

- **Issue:** #71
- **Date:** 2026-07-09
- **Status:** Approved (design), pending spec review
- **Type:** Web UI / UX fix (no API, data-model, or scan-policy impact)

## Goal

On the scan **Blind-spot reveal** card, the "?" help popovers must sit on the
metrics they explain, not on the action controls. Each explainer belongs on the
number it describes.

## Problem

Today the two `HelpPopover`s live on the action controls:

- "Show shadow certs" button — has a popover.
- "View report" link — has a popover.

The four metric tiles (`Vault managed`, `On wire`, `Shadow certs`,
`SC-081 violations`) have none. This explains the wrong affordances: the metrics
are what a first-time viewer needs defined, while the buttons are
self-descriptive.

## Design

### Scope of change

Single file for behavior — [`web/components/blind-spot-card.tsx`](../../../web/components/blind-spot-card.tsx) —
plus one CSS rule in [`web/app/globals.css`](../../../web/app/globals.css).

### Component change

Extend the local `StatTile` helper to accept an optional `help` node:

```tsx
function StatTile({ label, value, help }: {
  label: string; value: number | string; help?: ReactNode;
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

Attach `help` copy to three tiles (NOT `Vault managed`):

- **On wire** — certificates observed live during this scan (every TLS endpoint
  that presented a certificate).
- **Shadow certs** — on the wire but not issued by Vault; deployed yet unmanaged
  (the blind spot). Mentions "Show shadow certs" refreshes the count.
- **SC-081 violations** — certificates that breach the SC-081 compliance rules
  (expiry thresholds and excessive issued validity).

Remove both `HelpPopover`s from the "Show shadow certs" button and the "View
report" link; drop the surrounding `action-with-help` wrapper spans so those
controls render as a plain `button` / `Link`.

### CSS change

Make `.stat-tile-label` a flex row so the label text and inline "?" trigger sit
on one line without awkward wrapping:

```css
.stat-tile-label {
  display: flex;
  align-items: center;
  gap: 2px;
  /* existing font-size / color / margin-bottom retained */
}
```

## Testing (test-first)

New test file `web/components/blind-spot-card.test.tsx`, written and failing
before the component change:

- Mock `@/lib/api` so `fetchBlindSpot` resolves a summary and `triggerReconcile`
  is a stub; render `<BlindSpotCard scanId="s1" scanStatus="completed" />`.
- Assert a help-popover trigger (`button` with `aria-label` starting `What is`)
  is present for each of the three tiles: `On wire`, `Shadow certs`,
  `SC-081 violations`.
- Assert the `Vault managed` tile has **no** help trigger.
- Assert the "Show shadow certs" button and "View report" link are present and
  have **no** adjacent help trigger.

The `HelpPopover` already has its own unit test
(`web/components/help-popover.test.tsx`); this spec does not retest it.

## Docs

- No `require-docs.mdc` trigger (UI copy only — no API / scan policy / deployment
  / data-model change).
- Update `progress.md` with a one-line entry for the change.

## Verification

- `npx tsc --noEmit`
- `npm test` (from `web/`)
- `npm run build` (from `web/`)
- Subagent code review (`pr-review-toolkit:code-reviewer`) on the branch diff
  before opening the PR.
- Manual: load a completed scan, open each of the three tile popovers, confirm
  copy renders and closes on Escape / outside click.

## Acceptance criteria

- [ ] `On wire`, `Shadow certs`, `SC-081 violations` tiles each render a
  `HelpPopover`.
- [ ] `Vault managed` tile and the two action controls render no popover.
- [ ] Tile label + "?" lay out inline.
- [ ] Typecheck, tests, and web build pass.

## Out of scope

- The identical stat tiles on the report page (`/scans/[id]/report`) — those are
  addressed by the separate report-redesign work, not here.
