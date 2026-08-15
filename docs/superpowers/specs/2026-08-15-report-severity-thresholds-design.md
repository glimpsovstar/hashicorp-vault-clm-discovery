# Report severity rubric thresholds — design

**Status:** Approved for implementation (issue #74 AC)  
**Date:** 2026-08-15  
**Issue:** [#74](https://github.com/glimpsovstar/hashicorp-vault-clm-discovery/issues/74)  
**Follow-up to:** #73 (hard-coded v1 rubric)

## Problem

`deriveShadowSeverity` / `deriveIssuerSeverity` hard-code expiry day cutoffs (7 / 30). Operators need per-deployment policy without changing code.

## Goal

Source shadow/issuer severity day thresholds from env/config with defaults that preserve current behavior.

## Design

1. **Defaults (unchanged):** shadow expired or ≤7d → critical; ≤30d → high; else medium. Issuer ≤30d → high; else low.
2. **Config surface:** Next.js server env (report page is SSR), not `NEXT_PUBLIC_*`:
   - `CLM_REPORT_SHADOW_CRITICAL_DAYS` (default `7`)
   - `CLM_REPORT_SHADOW_HIGH_DAYS` (default `30`)
   - `CLM_REPORT_ISSUER_HIGH_DAYS` (default `30`)
3. **API:** `SeverityThresholds` + `DEFAULT_SEVERITY_THRESHOLDS` + `resolveSeverityThresholds(env)` + optional `thresholds` arg on derive/build helpers.
4. **Invalid env:** non-integer, empty, or negative → fall back to that field’s default. If critical > high after resolve, clamp critical to high.
5. **Out of scope:** SC-081 pack ceilings (≤14/≤60); persisted finding severity; UI to edit thresholds.

## Success

Unit tests cover defaults and configured paths; README documents the three vars.
