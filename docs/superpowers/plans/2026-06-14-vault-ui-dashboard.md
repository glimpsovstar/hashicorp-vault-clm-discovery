# Vault-aligned dashboard UI — implementation plan

**Date:** 2026-06-14  
**Spec:** [2026-06-14-vault-ui-design.md](../specs/2026-06-14-vault-ui-design.md)

## Summary

Replace the generic dark dashboard with a Vault-style Helios shell: AppFrame layout, sidebar navigation, page headers, HDS tokens, and the official Flight Icons Vault mark.

## Tasks (completed)

1. **HDS token subset** — `web/styles/hds-tokens.css`
2. **App shell** — header, sidebar, main (`app-shell.tsx`, `sidebar-nav.tsx`)
3. **Page headers** — `page-header.tsx` on inventory, scans, issuers, cert detail
4. **Restyle pages** — panels, data tables, forms, semantic badges
5. **Official logo** — `vault-color-24.svg` from `@hashicorp/flight-icons` (same as Vault UI `@icon="vault"`)
6. **Docs** — spec, plan, README, architecture, demo-flow cross-links

## Test plan

- [ ] `cd web && npm run build`
- [ ] Docker Compose: dashboard loads at `:3000`
- [ ] Header shows gold Vault chevron (not generic shield)
- [ ] Sidebar active state on Inventory / Scans / Issuers
- [ ] Scan form + inventory filters still work against API

## Follow-ups (optional)

- Add `@hashicorp/flight-icons` npm dep instead of vendored SVG
- Help dropdown + icon-only header home link (closer to Vault frame.hbs)
- Collapsible sidebar at ~1080px (Vault responsive behavior)
