# Vault CLM Discovery v1 — Implementation Plan

**Spec:** [2026-06-14-vault-clm-discovery-v1-design.md](../specs/2026-06-14-vault-clm-discovery-v1-design.md)  
**Issue:** #1  

## Tasks

1. Bootstrap repo — Go module, migrations, LICENSE, CI
2. `internal/cert`, `internal/scanner`, `internal/lifecycle`
3. `internal/store` — PostgreSQL repositories
4. `internal/api` — Chi REST + scan worker
5. `cmd/clm-discovery`, `cmd/clm-scan`
6. `web/` — Next.js dashboard
7. `deploy/docker-compose.yml`
8. README + architecture + data-model docs
9. Verify: `go test ./...`, `npm run build`, Docker Compose

## Branch

`feature/1-vault-clm-discovery-v1`

## Verification commands

```bash
go test ./...
go build ./...
cd web && npm run build
docker compose -f deploy/docker-compose.yml up --build -d
curl -s http://localhost:8080/api/v1/health
```
