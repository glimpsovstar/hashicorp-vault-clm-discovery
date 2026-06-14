# Demo flow — Vault CLM Discovery

Operator steps for live demos (Docker Compose on a laptop).

## Prerequisites

- Docker Desktop running
- Repo cloned; org Cursor rules installed ([`cursor-org-rules`](https://github.com/glimpsovstar/cursor-org-rules))

## Start or rebuild stack

After pulling changes that include migrations or API/UI updates, rebuild so Postgres migrations and images are current:

```bash
docker compose -f deploy/docker-compose.yml up --build -d
```

| Service | URL |
|---------|-----|
| Dashboard | http://localhost:3000 (Vault-style Helios UI — gold Vault logo, sidebar nav) |
| API health | http://localhost:8080/api/v1/health |

## Reset between demos (optional)

Delete stale scans and inventory from the UI so the next run is clean:

1. **Scans** — use **Delete** on old scan rows (or leave them for history)
2. **Inventory** / **Issuers** — **Delete** on individual rows as needed

Equivalent API: `DELETE /api/v1/scans/{id}`, `DELETE /api/v1/certificates/{id}`, `DELETE /api/v1/issuers/{id}`.

Add `docker compose ... down -v` only when you need a full database wipe.

## Demo scan (hostnames)

1. Open **Scans**
2. Hostnames: `coffeesnob.withdevo.net,aap.david-joo.sbx.hashidemos.io`
3. Ports: `443`
4. Check consent → **Start scan**
5. Wait for status `completed` (table auto-refreshes while running)
6. Click **View results** on the scan row → `/scans/{id}` shows discovered certificates and diagnostics
7. Open **Inventory** — verify governance columns:
   - **Vault** — Not connected (until v1.1 reconciliation)
   - **Imported** — Not imported
   - **Scope** — External for public CA certs (e.g. Let's Encrypt)
   - **Expiry** — Active / Expired badges from lifecycle `status`

From scan detail, **Filter inventory** links to `/?scan_id={id}`.

If `aap.david-joo.sbx.hashidemos.io` is unreachable from your network, omit it; coffee alone is enough for the demo.

## SDLC demo (Cursor value)

1. Show GitHub **Issues** #1–#3, **#5** (Vault UI), **#10** (scan persistence + delete/detail), **#12** (governance columns), **#14** (observability)
2. Show merged **PRs** [#4](https://github.com/glimpsovstar/hashicorp-vault-clm-discovery/pull/4) (v1), [#6](https://github.com/glimpsovstar/hashicorp-vault-clm-discovery/pull/6) (Vault UI), [#11](https://github.com/glimpsovstar/hashicorp-vault-clm-discovery/pull/11) (inventory fix + delete), [#13](https://github.com/glimpsovstar/hashicorp-vault-clm-discovery/pull/13) (governance columns)
3. Show **`.cursor/rules/`** + org rules in Cursor Settings
4. Show **`.prompts-history.md`** — prompt → spec → issue → PR arc

## Tear down

```bash
docker compose -f deploy/docker-compose.yml down
```

Add `-v` to reset PostgreSQL volume.
