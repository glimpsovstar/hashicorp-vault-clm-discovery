variable "vault_addr" {
  type        = string
  description = "HCP Vault cluster public address (e.g. from the `hcpvenv` alias)."
}

variable "vault_namespace" {
  type        = string
  default     = "admin"
  description = "HCP Vault namespace (HCP uses `admin`)."
}

variable "vault_token" {
  type        = string
  sensitive   = true
  description = "Vault token for the HCP cluster (never commit; source from env / gitignored tfvars)."
}

variable "pki_mount" {
  type        = string
  default     = "pki-clm-int"
  description = "PKI mount path to configure on the HCP cluster for CLM import tests."
}
