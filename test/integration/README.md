# Vault integration validation (Terraform-provisioned)

End-to-end validation of the **mode B CA-import** flow (issue #25) against a
**real** Vault, with the Vault (and, for scenario 1, the whole stack) provisioned
by Terraform. Two scenarios:

| # | Vault | Provisioning | Secrets | CI |
|---|-------|--------------|---------|----|
| 1 | Local Vault **dev mode** (Docker) | `kreuzwerker/docker` + `hashicorp/vault` + `hashicorp/tls` | none | **yes** |
| 2 | **Existing** HCP Vault cluster | `hashicorp/hcp` + `hashicorp/vault` | HCP creds via env / gitignored tfvars | opt-in |

The flow both scenarios validate: **scan a self-signed endpoint → discover the CA
issuer → import the CA into a Vault PKI mount (`POST /issuers/{id}/import`) →
verify the CA is readable in Vault and the CLM issuer row records
`vault_issuer_ref`/`vault_pki_mount`.** This is the automated equivalent of
clicking **Import CA to Vault** in the dashboard.

> Scenario 1 asserts the **import result**, not a leaf `reconcile → managed_in_vault`
> match: reconcile lists Vault-*issued* certs, and an imported CA does not make an
> externally-issued leaf appear there.

## Scenario 1 — local (default, CI)

Requires `terraform`, `docker`, `go`, `curl`. No secrets.

```bash
sh test/integration/run-integration.sh
```

Host ports `8080` (API), `8200` (Vault), and `8443` (nginx) must be free (all
configurable via the `local` module variables; Postgres is network-internal).

`run-integration.sh` is the whole test in one step: `terraform apply` stands up
Postgres, a one-shot migrate, the CLM API, a Vault dev server (PKI mount +
least-privilege import policy), and an nginx endpoint serving a TF-generated
CA+leaf chain; it waits for the API to be healthy, runs the build-tagged Go
driver (`//go:build integration`), then **always** `terraform destroy`s the stack.

The Go driver alone (`go test -tags integration ./test/integration/...`) skips
unless the `INTEGRATION_*` env vars are set by the script.

## Scenario 2 — HCP (opt-in)

Configures a PKI mount + import policy on an **existing** HCP Vault cluster (does
not create a cluster). Credentials never committed.

```bash
# Source your HCP env (sets VAULT_ADDR, VAULT_NAMESPACE=admin, VAULT_TOKEN,
# and HCP_CLIENT_ID/SECRET/PROJECT_ID):
#   e.g. `hcpvenv`
cd test/integration/terraform/hcp
cp terraform.tfvars.example terraform.tfvars   # fill vault_addr/token (gitignored)
terraform init
terraform apply
```

Then point the CLM app at the HCP cluster (`VAULT_ADDR`, `VAULT_NAMESPACE=admin`,
`VAULT_TOKEN` for read, plus `VAULT_IMPORT_TOKEN` or import AppRole — `VAULT_TOKEN`
alone returns 503 on import) and run the same scan → import → verify against
`mount=pki-clm-int`. Auth the API with `CLM_INSECURE_NO_AUTH=true` or a Bearer
from `CLM_STATIC_TOKENS`.

## Required Vault policy (mode B)

Both scenarios provision the least-privilege import policy (see
`docs/superpowers/specs/2026-07-06-vault-import-workflow-design.md` §Required
Vault policy): `create/update` on `<mount>/issuers/import/bundle`, plus the
read-only reconcile paths.

## Auth (M1)

Scenario 1 sets `CLM_INSECURE_NO_AUTH=true` on the app container so the Go driver can keep POSTing scans/import without Bearer. Prefer that hatch for this harness; alternatively set `CLM_STATIC_TOKENS` and send `Authorization: Bearer` from `test/integration/integration_test.go`.

**Import identity.** The app also sets `VAULT_IMPORT_TOKEN` to the Vault dev root (same value as `VAULT_TOKEN` here, but a distinct env). After M1, `VAULT_TOKEN` alone returns **503** on `POST /issuers/{id}/import`. Scenario 2 (HCP) must set `VAULT_IMPORT_TOKEN` or import AppRole on the CLM process the same way.

Consent remains intent after RBAC: this driver sends `consent:true` and relies on the hatch (or a sufficiently privileged Bearer) rather than treating consent as AuthN.

## Security notes

- Local Vault is **dev mode** (root token, in-memory) — local/CI only, never expose.
- No secrets are committed: `.gitignore` covers `.terraform*`, `*.tfstate*`, and
  `test/integration/terraform/**/terraform.tfvars`. HCP creds come from the
  environment.
