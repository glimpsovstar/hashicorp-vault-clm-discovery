# Docker dashboard deployment fixes — Design Spec

**Status:** Approved  
**Date:** 2026-06-14  
**Issue:** #3  

## Problem

Dashboard shows "Application error" under Docker Compose:

1. Next.js SSR fetches `localhost:8080` inside `web` container → API unreachable
2. API returns `"items": null` for empty lists → UI `.map()` crash
3. Web Dockerfile copies missing `public/` directory
4. Go module version mismatch breaks API image build

## Solution

| Fix | Change |
|-----|--------|
| SSR API URL | `API_INTERNAL_URL=http://api:8080` in compose; dual URL in `web/lib/api.ts` |
| Null slices | Go store returns `[]` not `null`; UI defensive `?? []` |
| public/ | `web/public/.gitkeep` + Dockerfile `mkdir -p public` |
| Go version | Pin `go 1.22` + compatible deps |

## Acceptance criteria

- [ ] `curl http://localhost:3000/` returns 200
- [ ] Empty inventory renders without error
- [ ] `docker compose ... build` succeeds for api and web

## Test plan

```bash
docker compose -f deploy/docker-compose.yml up --build -d
curl -s -o /dev/null -w "%{http_code}" http://localhost:3000/
curl -s http://localhost:8080/api/v1/certificates
```
