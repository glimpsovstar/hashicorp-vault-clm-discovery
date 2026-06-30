# Demo flow — Vault CLM Discovery

Operator steps for live demos (Docker Compose on a laptop).

## Prerequisites

- Docker Desktop running
- Repo cloned; org Cursor rules installed ([`cursor-org-rules`](https://github.com/glimpsovstar/cursor-org-rules))
- Optional for blind-spot POV: a reachable Vault with PKI (`VAULT_ADDR`, `VAULT_TOKEN` in compose env)

## Start or rebuild stack

After pulling changes that include migrations or API/UI updates, rebuild so Postgres migrations and images are current:

```bash
docker compose -f deploy/docker-compose.yml up --build -d
```

| Service | URL |
|---------|-----|
| Dashboard | http://localhost:3000 (Vault-style Helios UI — gold Vault logo, sidebar nav) |
| API health | http://localhost:8080/api/v1/health |

### Vault reconcile (Phase 1 POV)

Add to `deploy/docker-compose.yml` API service environment (or `.env`):

```yaml
VAULT_ADDR: https://your-vault.example.com
VAULT_TOKEN: s.xxx
# Optional: auto-reconcile when scan completes
RECONCILE_ON_SCAN_COMPLETE: "false"
```

See [README § Environment variables](../README.md#environment-variables) for `VAULT_NAMESPACE` and auth options.

## Reset between demos (optional)

Delete stale scans and inventory from the UI so the next run is clean:

1. **Scans** — use **Delete** on old scan rows (or leave them for history)
2. **Inventory** / **Issuers** — **Delete** on individual rows as needed

Equivalent API: `DELETE /api/v1/scans/{id}`, `DELETE /api/v1/certificates/{id}`, `DELETE /api/v1/issuers/{id}`.

Add `docker compose ... down -v` only when you need a full database wipe.

## POV demo script (under 2 minutes)

**Narrative:** *Vault sees N. We found M. Here are K SC-081 violations.*

| Step | Action | Talking point |
|------|--------|---------------|
| 1 | `docker compose -f deploy/docker-compose.yml up --build -d` | Stack: API + Postgres + dashboard |
| 2 | Set `VAULT_ADDR` + token in compose env (if not already) | Read-only PKI reconcile — no Vault writes |
| 3 | **Scans** → hostnames from README → consent → **Start scan** | Network truth vs Vault telemetry |
| 4 | Open scan detail → **Reconcile with Vault** on blind-spot card | Fingerprints matched; Vault column updates |
| 5 | Blind-spot card: Vault managed / On wire / Shadow / SC-081 | **N** vs **M** vs shadow count |
| 6 | **Download report** (Markdown) | Audit artifact for compliance review |

### Demo scan (hostnames)

1. Open **Scans**
2. Hostnames: `coffeesnob.withdevo.net,aap.david-joo.sbx.hashidemos.io`
3. Ports: `443`
4. Check consent → **Start scan**
5. Wait for status `completed` (table auto-refreshes while running)
6. Click **View results** on the scan row → `/scans/{id}` shows:
   - **Blind-spot reveal** card (four metrics + reconcile + report download)
   - Scan diagnostics and discovered certificates
7. Click **Reconcile with Vault** (requires `VAULT_ADDR`) — refresh metrics; inventory **Vault** column shows **Connected** for matched certs
8. Click **Download report** — Markdown with executive summary, blind-spot, SC-081, PCI, algorithm inventory, diagnostics
9. Open **Inventory** — verify governance columns:
   - **Vault** — Connected after reconcile (or Not connected without Vault)
   - **Imported** — Not imported
   - **Scope** — External for public CA certs (e.g. Let's Encrypt)
   - **Expiry** — Active / Expired badges from lifecycle `status`

From scan detail, **Filter inventory** links to `/?scan_id={id}`.

**Inventory toolbar:** **Reconcile with Vault** runs estate-wide PKI correlation without opening scan detail.

If `aap.david-joo.sbx.hashidemos.io` is unreachable from your network, omit it; coffee alone is enough for the demo.

### API equivalents

```bash
# Blind-spot summary for a scan
curl -s http://localhost:8080/api/v1/scans/{id}/blindspot | jq

# Reconcile
curl -s -X POST http://localhost:8080/api/v1/reconcile | jq

# Download report
curl -s "http://localhost:8080/api/v1/scans/{id}/report?format=markdown" -o report.md
```

## SDLC demo (Cursor value)

1. Show GitHub **Issue #27** (Phase 1 blind-spot reveal), prior issues #1–#3, **#5** (Vault UI), **#10** (scan persistence), **#12** (governance), **#14** (observability)
2. Show merged **PRs** and [Phase 1 implementation plan](superpowers/plans/2026-06-30-phase-1-blind-spot-reveal-demo.md)
3. Show **`.cursor/rules/`** + org rules in Cursor Settings
4. Show **`.prompts-history.md`** — prompt → spec → issue → PR arc

## Tear down

```bash
docker compose -f deploy/docker-compose.yml down
```

Add `-v` to reset PostgreSQL volume.

## Related docs

- [Blind-spot reveal design](superpowers/specs/2026-06-30-blind-spot-reveal-design.md)
- [Compliance standards packs](superpowers/specs/2026-06-30-compliance-standards-packs-design.md)
- [Reporting architecture](reporting-architecture.md)
- [Program context](program-context.md)
