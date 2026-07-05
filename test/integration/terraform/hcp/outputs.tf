output "pki_mount" {
  value       = vault_mount.pki.path
  description = "PKI mount configured on the HCP cluster."
}

output "vault_addr" {
  value       = var.vault_addr
  description = "HCP Vault address the CLM app / driver should target."
}

output "vault_namespace" {
  value       = var.vault_namespace
  description = "HCP Vault namespace (admin)."
}
