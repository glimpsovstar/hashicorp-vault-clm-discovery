# Configure a PKI mount + least-privilege import policy on the EXISTING HCP Vault
# cluster (the lane does not create a cluster). CLM points at var.vault_addr with
# namespace var.vault_namespace to run the same scan -> import -> verify flow.

resource "vault_mount" "pki" {
  path        = var.pki_mount
  type        = "pki"
  description = "CLM integration PKI mount (HCP)"

  max_lease_ttl_seconds = 315360000 # 10y
}

resource "vault_policy" "clm_import" {
  name   = "clm-import"
  policy = <<-EOT
    path "${var.pki_mount}/issuers/import/bundle" { capabilities = ["create", "update"] }
    path "${var.pki_mount}/issuer/*"              { capabilities = ["read"] }
    path "sys/mounts"                             { capabilities = ["read"] }
    path "${var.pki_mount}/certs"                 { capabilities = ["list"] }
    path "${var.pki_mount}/cert/*"                { capabilities = ["read"] }
  EOT
}
