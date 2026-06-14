# Demo flow — Vault CLM Discovery

Operator steps for live demos (Docker Compose on a laptop).

## Prerequisites

- Docker Desktop running
- Repo cloned; org Cursor rules installed ([`cursor-org-rules`](https://github.com/glimpsovstar/cursor-org-rules))

## Start stack

```bash
docker compose -f deploy/docker-compose.yml up --build -d
```

| Service | URL |
|---------|-----|
| Dashboard | http://localhost:3000 |
| API health | http://localhost:8080/api/v1/health |

## Demo scan (hostnames)

1. Open **Scans**
2. Hostnames: `coffeesnob.withdevo.net,aap.david-joo.sbx.hashicorp.io`
3. Ports: `443`
4. Check consent → **Start scan**
5. Refresh → **Inventory** shows certificates with observations

If `aap.david-joo.sbx.hashicorp.io` does not resolve, connect VPN or omit it; coffee alone is enough for the demo.

## SDLC demo (Cursor value)

1. Show GitHub **Issues** #1–#3 and linked specs under `docs/superpowers/specs/`
2. Show open **PR** with test plan checklist
3. Show **`.cursor/rules/`** + org rules in Cursor Settings
4. Show **`.prompts-history.md`** — prompt → spec → issue → PR arc

## Tear down

```bash
docker compose -f deploy/docker-compose.yml down
```

Add `-v` to reset PostgreSQL volume.
