## Problem

Six scoring paths exist and disagree. `certificates.risk_score` is schema-only (DEFAULT 0); nothing writes it. SC-081/PCI/crypto and report insights are **on-read**. A prior &lt;14-high / &lt;30-medium / else-low request is rejected (collapses critical, collides with SC-081).

## Proposed solution

Keep compliance **packs unchanged**. Persist pack+ops output as findings. `risk_score = max(non-waived)` plus `risk_reasons[]`. Operational rubric stays ≤7 critical / ≤30 high. SC-081 keeps ≤14/≤60. Waivers suppress count/score, not hide. Cheap PQC inventory tag at parse. No PQ issuance.

## Acceptance criteria

- [ ] Findings upsert on `cert_id+rule_id`; recompute `risk_score` on scan complete and enrichment PATCH.
- [ ] UI never sees pack `warning`; mapped once at persist.
- [ ] Waiver CRUD with expiry; honored in counts/score.
- [ ] GET cert includes `risk_score` + `risk_reasons`.
- [ ] PQC tag `classic|hybrid|pqc|unknown`; inventory count.
- [ ] UAT expiry matrix still green.

## Test plan

- [ ] `go test ./...`
- [ ] `go test -tags uat ./internal/uat/...`
- [ ] Web tests for filter/sort on persisted findings
- [ ] Confirm SC-081/PCI/crypto rule IDs unchanged

## Superpowers spec

`docs/superpowers/specs/2026-08-13-m3-explainable-posture-design.md`

Plan: `docs/superpowers/plans/2026-08-13-m3-explainable-posture.md`

Depends on: M1 for waiver actors.

## Out of scope

Rewriting pack ceilings, changing UAT expiry windows, PQ issuance, LLM severity.
