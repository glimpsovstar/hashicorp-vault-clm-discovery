output "app_url" {
  value       = "http://127.0.0.1:${var.app_host_port}"
  description = "CLM API base URL for the driver."
}

output "vault_addr" {
  value       = "http://127.0.0.1:${var.vault_host_port}"
  description = "Vault dev address (host)."
}

output "vault_token" {
  value       = var.vault_dev_root_token
  sensitive   = true
  description = "Vault dev root token."
}

output "pki_mount" {
  value       = var.pki_mount
  description = "PKI mount the CA is imported into."
}

output "scan_target" {
  value       = "nginx"
  description = "Docker DNS name the app scans on port 443 (in-network)."
}

output "ca_common_name" {
  value       = "CLM Integration Root CA"
  description = "Subject CN of the CA issuer the driver imports."
}
