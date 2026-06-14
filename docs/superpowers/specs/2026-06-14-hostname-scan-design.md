# Hostname TLS discovery — Design Spec

**Status:** Approved  
**Date:** 2026-06-14  
**Issue:** #2  

## Problem

Demo targets (`coffeesnob.withdevo.net`, `aap.david-joo.sbx.hashidemos.io`) are **hostnames**, not CIDR ranges. Scanning resolved IPs without correct **SNI** returns wrong certificates on shared hosting (Vercel, ALB).

## Solution

- API accepts `hostnames[]` alongside `cidrs[]` (at least one required)
- Resolve each hostname → IPv4 targets with `Hostname` set for TLS SNI
- Store hostnames on scan record (`scans.hostnames`)
- Dashboard scan form: hostnames field (primary for HTTPS demos)

## Acceptance criteria

- [ ] `POST /api/v1/scans` accepts `hostnames`
- [ ] TLS ClientHello uses hostname as SNI
- [ ] Observations record correct `sni` and `hostname_matches_san`
- [ ] Migration adds `scans.hostnames`
- [ ] Dashboard + CLI support hostnames
- [ ] Tests for `ExpandHostnames`, `ExpandScanTargets`

## Test plan

```bash
go test ./internal/scanner/...
curl -X POST .../scans -d '{"hostnames":["coffeesnob.withdevo.net"],"ports":[443],"consent":true}'
```

Manual: scan demo hostnames; inventory shows expected CN/SAN.

## Out of scope

- IPv6-only targets
- Custom SNI override map (future)
