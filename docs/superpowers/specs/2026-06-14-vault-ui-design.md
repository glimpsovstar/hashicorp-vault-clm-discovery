# Vault-aligned dashboard UI

**Date:** 2026-06-14  
**Status:** Implemented  
**Related:** Issue/PR for UI reskin (demo SDLC)

## Goal

Reskin the CLM Discovery Next.js dashboard so it follows HashiCorp Vault’s **Helios (HDS) AppFrame** layout and visual language — without pulling in Ember or the full HDS component library.

This is a **companion product UI**, not Vault itself: we mirror Vault’s shell (header, sidebar, page headers, tables) while keeping CLM-specific routes (inventory, scans, issuers).

## Vault references (source of truth)

| Vault artifact | Purpose |
|----------------|---------|
| [sidebar/frame.hbs](https://github.com/hashicorp/vault/blob/main/ui/lib/core/addon/components/sidebar/frame.hbs) | `Hds::AppFrame`, `Hds::AppHeader`, `Hds::AppSideNav` |
| [sidebar/nav/cluster.hbs](https://github.com/hashicorp/vault/blob/main/ui/lib/core/addon/components/sidebar/nav/cluster.hbs) | Sidebar section titles + nav links |
| [page/header.hbs](https://github.com/hashicorp/vault/blob/main/ui/lib/core/addon/components/page/header.hbs) | Page title, breadcrumbs, actions |
| [Helios colors](https://helios.hashicorp.design/foundations/colors) | Semantic tokens (foreground, surface, borders) |
| [@hashicorp/flight-icons](https://helios.hashicorp.design/icons/library) `vault-color-24` | Official Vault product mark in the app header |

Vault’s header home control uses `Hds::AppHeader::HomeLink` with `@icon="vault"` (Flight Icons vault mark, gold `#FFCF25` in color variant). We ship the same SVG under `web/public/icons/vault-color-24.svg` (MPL-2.0, attributed in file).

## CLM mapping

| Vault pattern | CLM implementation |
|---------------|-------------------|
| AppFrame (header + sidebar + main) | `web/components/app-shell.tsx` + `.app-frame` in `globals.css` |
| AppHeader + Documentation link | Top bar in `app-shell.tsx` |
| AppSideNav | `web/components/sidebar-nav.tsx` — **CLM Discovery** → Inventory, Scans, Issuers |
| PageHeader | `web/components/page-header.tsx` on each route |
| HDS tokens | `web/styles/hds-tokens.css` (subset) |
| Primary buttons | `.button-primary` (Vault blue `#1060ff`) |
| Status badges | `statusBadgeClass()` in `web/lib/api.ts` |

## Files touched

```
web/styles/hds-tokens.css
web/public/icons/vault-color-24.svg
web/components/app-shell.tsx
web/components/sidebar-nav.tsx
web/components/page-header.tsx
web/components/vault-logo.tsx
web/app/globals.css
web/app/layout.tsx
web/app/page.tsx
web/app/scans/page.tsx
web/app/scans/scan-form.tsx
web/app/issuers/page.tsx
web/app/certificates/[id]/page.tsx
web/app/certificates/[id]/enrichment-form.tsx
web/lib/api.ts          # statusBadgeClass
```

## Out of scope

- Vault Web REPL / console panel
- Namespace picker, user menu, help dropdown (full Vault utility chrome)
- `@hashicorp/design-system-components` (Ember-only)
- Pixel-perfect parity with every HDS component

## Verification

```bash
cd web && npm run build
docker compose -f deploy/docker-compose.yml up --build
open http://localhost:3000
```

Confirm: light theme, left sidebar, gold Vault chevron logo in header, blue primary buttons.

## Documentation index

- **This spec:** design intent and Vault references
- **Plan:** [2026-06-14-vault-ui-dashboard.md](../plans/2026-06-14-vault-ui-dashboard.md)
- **Architecture:** [docs/architecture.md](../../architecture.md) — Web dashboard section
- **Demo:** [docs/demo-flow.md](../../demo-flow.md) — UI callout for live demos
