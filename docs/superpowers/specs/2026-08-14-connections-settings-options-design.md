# Connections Settings UX — dynamic Vault/AAP options — design

**Status:** Implemented (branch `feature/91-connections-options`)  
**Date:** 2026-08-14  
**Parent:** [Connections Settings](2026-08-13-connections-settings-design.md)  
**Issues:** [#91](https://github.com/glimpsovstar/hashicorp-vault-clm-discovery/issues/91), [#92](https://github.com/glimpsovstar/hashicorp-vault-clm-discovery/issues/92)  
**Plan:** [2026-08-14-connections-settings-options.md](../plans/2026-08-14-connections-settings-options.md)

---

## Goal

Operators configure Vault deployment, AAP renew kind, and default PKI mount with human labels and **dropdowns populated from the live Vault/AAP connection** (resolved Settings overlay or env). Env var names are unchanged.

## Locked decisions

- **Approach A:** new read-only options APIs; UI selects; persist mount **path** and template **name** + `renew_workflow` bool (same data model as today).
- Env keys stay `AAP_DEFAULT_MOUNT`, `AAP_RENEW_TEMPLATE`, `AAP_RENEW_WORKFLOW`, etc.
- Free-text fallback when the options list is empty or the peer is unreachable (operator can still type a path/name).
- No numeric AAP template IDs in Settings storage.
- No browser calls to Vault/AAP; no `NEXT_PUBLIC` secrets.
- No job launch on list/test.
- Radio CSS fix for Vault Deployment (oversized radios).
- Human UI labels (not raw env names) on the AAP card fields we touch.

## Problem (as shipped)

1. Vault Deployment radios inherit full-width text-input CSS.
2. AAP renew kind is a checkbox labeled `AAP_RENEW_WORKFLOW`.
3. `AAP_DEFAULT_MOUNT` looks like an AAP resource; it is the default **Vault PKI mount path** for Mode C renewals when the cert/request has no mount.

## UI

| Control | Label | Behavior |
|---------|-------|----------|
| Vault deployment | Deployment | Compact radios: Self-managed / HCP Dedicated |
| AAP renew kind | Renew with | Radios: **Job template** / **Workflow** → sets `renew_workflow` |
| AAP template | Template name | `<select>` of names from options API for the selected kind; free-text fallback |
| Default mount | **Default Vault PKI mount** | `<select>` of PKI mount paths from Vault; help text below; free-text fallback |

Help for mount: *Used when a certificate renew does not already set a mount. Passed to AAP as the Vault PKI path (not an AAP resource id).*

Load options when the Connections page loads (or on “Refresh options”) using the **currently saved/resolved** connection — not unsaved form drafts (avoids probing with half-edited secrets). If Save just succeeded, reload options after save.

## API

Auth: same as Settings GET — `platform_admin` or `remediator`. No secrets in responses.

### `GET /api/v1/settings/connections/options/vault-pki-mounts`

Uses `settings.Resolve` → Vault client → `ListPKIMounts`.

```json
{ "items": ["pki/", "pki-int/"] }
```

If Vault not configured: `200` with `items: []` and optional `detail`. Peer errors: `502` with non-secret detail (or `200` empty + detail — prefer **502** when configured but list fails so the UI can show an error and fall back to text).

### `GET /api/v1/settings/connections/options/aap-templates?kind=job|workflow`

`kind=job` → list job templates; `kind=workflow` → list workflow job templates. Paginate Controller results server-side (cap e.g. 200 names) and return:

```json
{ "kind": "job", "items": [{ "id": 7, "name": "CLM - Issue Certificate" }] }
```

`id` is for display/debug only; Settings still **stores `name`**. Invalid `kind` → 400. AAP not configured → empty items. List must not launch jobs.

BFF: proxy these under same-origin `/api/v1/...` (existing catch-all).

## Building blocks

- `internal/vault`: existing `ListPKIMounts`
- `internal/aap`: add `ListJobTemplates` / `ListWorkflowJobTemplates` (paginated `GET /api/v2/job_templates/` and `workflow_job_templates/`)
- `internal/settings.Resolve` for credentials (same as Test)

## Acceptance criteria

- [ ] Vault Deployment radios are compact (not full-width text-input size).
- [ ] Renew kind is Job template vs Workflow radios; maps to `renew_workflow`.
- [ ] Mount field labeled **Default Vault PKI mount** with help text; env name unchanged.
- [ ] Mount `<select>` filled from Vault PKI mounts when Vault is reachable; free-text if empty/error.
- [ ] Template `<select>` filled from AAP for the selected kind; free-text if empty/error.
- [ ] Options APIs never return tokens/secrets; never launch AAP jobs.
- [ ] Vitest + Go tests (httptest) cover options handlers and form behavior.
- [ ] README / architecture / Connections docs updated (labels + options endpoints).

## Out of scope

- Renaming env vars
- Storing AAP template numeric IDs as SoR
- OIDC / BFF session (#89)
- Hot-reload of runtime renewer from Settings overlay (still process env at start for renew — document honestly)

## Test plan

- [ ] `go test ./internal/aap/ ./internal/api/ ./internal/vault/`
- [ ] `go test ./...` && `go build ./...`
- [ ] `cd web && npm test && npm run build`
- [ ] Manual: compose with Vault+AAP → Settings dropdowns populate; Save persists name/path
