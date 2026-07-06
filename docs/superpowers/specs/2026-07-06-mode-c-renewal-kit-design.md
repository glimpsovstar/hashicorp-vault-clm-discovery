# Design: Mode C automation — renewal kit generator (#44)

- **Issue:** #44 (lifecycle Mode C; follows the import spec's Mode C reference)
- **Status:** Implemented.

## Goal

Operationalize Mode C (reissue & deploy) within CLM's boundaries: CLM does **not**
issue or deploy certificates (Vault PKI issues; vault-agent/AAP deploy). Instead
CLM **generates the operator-runnable deploy artifacts** for an expiring cert and
a chosen Vault PKI role, then verifies the result via a later rescan + reconcile.

## Design

### Generator (`internal/renewal/kit.go`)

Pure text generation (no I/O, no secrets embedded):

```go
type Target string // "agent" | "aap"
type KitInput struct { CommonName, Mount, Role, Service string }
type Artifact struct { Filename, Language, Content string }
func Generate(target Target, in KitInput) ([]Artifact, error)
```

- **agent** → `vault-agent.hcl`: `auto_auth` (AppRole placeholder) + two `template`
  stanzas rendering cert(+chain) and key from `{mount}/issue/{role}` with an
  optional reload `command`.
- **aap** → `reissue-playbook.yml`: `community.hashi_vault.vault_write` to
  `{mount}/issue/{role}`, write cert/key, optional service reload.
- `validate` rejects empty/traversal `mount`/`role` and empty CN.

### API

`GET /api/v1/certificates/{id}/renewal-kit?target=agent|aap&role=<r>&mount=<m>&service=<s>`
— loads the cert (CN from `subject_cn`), generates, returns `{target, artifacts}`.
400 on invalid input, 404 unknown cert.

### UI

Cert detail "Renewal kit (Mode C)" panel: pick target + role/mount/service, generate,
view/copy the rendered artifact.

## Security

- No secrets in artifacts: Vault Agent uses auto-auth; AAP uses a Vault lookup.
- `mount`/`role` validated (no dot-segments/leading slash) before templating.

## Testing (TDD)

- `kit_test.go`: agent + aap content assertions; reload omitted without a service;
  validation errors (bad target, empty role, traversal mount, empty CN).
- Handler test: 400/404/success; route-registration guard extended.

## Verification gate

`go build/vet/test ./...`, `cd web && npm run build`, PR + sub-agent review.
