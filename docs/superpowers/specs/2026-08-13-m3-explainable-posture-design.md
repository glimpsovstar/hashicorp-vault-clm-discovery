# M3 — Explainable posture and policy — design

**Status:** Draft  
**Date:** 2026-08-13  
**Parent:** [GCM closed-loop roadmap](2026-08-13-gcm-closed-loop-roadmap-design.md)  
**Plan:** [2026-08-13-m3-explainable-posture.md](../plans/2026-08-13-m3-explainable-posture.md)  
**Depends on:** M1 for waiver actors

---

## Problem

Six scoring paths exist and disagree. `certificates.risk_score` is schema-only (DEFAULT 0); nothing writes it. SC-081/PCI/crypto and report insights are **on-read**. The report UI uses a third rubric (`web/lib/findings.ts`). Pack UAT is locked to SC-081 ≤14/≤60.

## Goal

Keep compliance **packs unchanged**. Persist their output as findings. Derive `risk_score` as an **explainable max** of non-waived findings. One 5-level severity at the finding/UI boundary.

## Locked rubric

| Layer | Windows |
|-------|---------|
| **Operational / shadow / report buckets** | expired or ≤7 → **critical**; ≤30 → **high**; else → **medium** (unmanaged floor) |
| **SC-081 pack** | ≤14 critical, ≤60 warning; internal+non-prod expiry → info (not counted); validity always critical |
| **Rejected** | &lt;14 high / &lt;30 medium / else low — collapses critical and collides with SC-081 |

Map pack `warning` → 5-level `high` (or `medium` for PCI hygiene) **once** at persist. UI never sees `warning`.

## Model

```
packs + ops classifiers → findings (upsert cert+rule_id)
                         → waivers suppress count/score, not hide
                         → risk_score = max(non-waived), plus risk_reasons[]
```

- Versioned **operational** policy (7/30 windows, weights). Pack logic stays in Go.
- Re-eval on scan complete and enrichment PATCH.
- PQC: cheap tag `classic|hybrid|pqc|unknown` at parse; optional `info` finding. **No PQ issuance.**

## Acceptance criteria

- [ ] Cert with non-waived critical finding has `risk_score` in the critical band; GET returns `risk_reasons`.
- [ ] SC-081/PCI/crypto rule IDs and UAT matrix unchanged.
- [ ] Second eval upserts; no duplicate open findings for `cert_id+rule_id`.
- [ ] Waiver removes finding from violation count and score; expired waiver restores.
- [ ] Policy vN+1 does not mutate historical finding rows.
- [ ] PQC tag set at parse; no Vault PQC write.
- [ ] Dashboard `Certificate` includes `risk_score`; inventory can sort/filter.
- [ ] `go test ./...` and `go test -tags uat ./internal/uat/...` stay green.

## Out of scope

OPA/YAML authoring, replacing packs with one classifier, PQ/hybrid issuance, client-only rubric remaining as source of truth.
