# Design: Choose wizard — recommend the next lifecycle action (#38)

- **Issue:** #38 (lifecycle Choose phase, parent #20)
- **Status:** Design gate — awaiting approval before implementation
- **Builds on:** scope classification, reconcile (#23/#32), import (#25 A/B/D)

## Goal

Given a discovered certificate's signals, recommend the single next **Choose**
action and route the operator to the existing CTA. Read-only; no migration.

## Design

### Pure recommendation (`internal/lifecycle/choose.go`)

`internal/lifecycle` must not import `store` (store imports lifecycle → cycle),
so the recommender takes primitives:

```go
type ChooseInput struct {
    CertScope     string // internal | external
    ManagedStatus string // unmanaged | managed_in_vault | imported
    ChainStatus   string // complete | incomplete | self_signed | untrusted_root
    IsCA          bool
}

type ChooseResult struct {
    Code      string `json:"code"`      // already_managed | fix_chain | import_ca | monitor_external | reconcile_vault | catalog_tracked
    Title     string `json:"title"`
    Rationale string `json:"rationale"`
    CTA       string `json:"cta"`       // suggested action label
}

func ChooseRecommendation(in ChooseInput) ChooseResult
```

Decision order (maps the Choose decision tree):

1. `managed_in_vault` → **already_managed** (no action).
2. chain `incomplete`/`untrusted_root` → **fix_chain** (import intermediate/root, rescan).
3. `IsCA` && unmanaged → **import_ca** (Import CA to Vault).
4. `external` && unmanaged leaf → **monitor_external** (Track in CLM / leave on public CA).
5. `internal` && unmanaged leaf → **reconcile_vault** (likely Vault-issued; reconcile).
6. `imported` → **catalog_tracked** (tracked in CLM; reconcile to confirm).
7. default → **monitor_external**.

### API

`GET /api/v1/certificates/{id}/choose` → loads the cert via `resources.GetCertificate`,
maps fields to `ChooseInput`, returns `ChooseResult`. 404 if unknown; 500 on error.

### UI

Cert detail page adds a "Recommended next step" panel (read-only) showing
`title` + `rationale` and, when actionable, the matching existing control
(Track in CLM button, Import CA link, or a reconcile note).

## Testing (TDD)

- `choose_test.go` — table-driven over each decision-order row.
- API handler test — 404 / 500 / success via `fakeResourceStore`.

## Verification gate

`go build/vet/test ./...`, `cd web && npm run build`, PR + sub-agent review.
