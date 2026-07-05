variable "vault_dev_root_token" {
  type        = string
  default     = "root"
  description = "Dev-mode Vault root token (local only; ephemeral)."
}

variable "vault_host_port" {
  type        = number
  default     = 8200
  description = "Host port mapped to the Vault dev container."
}

variable "app_host_port" {
  type        = number
  default     = 8080
  description = "Host port mapped to the CLM API container."
}

variable "nginx_host_port" {
  type        = number
  default     = 8443
  description = "Host port mapped to the self-signed nginx endpoint (:443 in-container)."
}

variable "pki_mount" {
  type        = string
  default     = "pki"
  description = "Vault PKI mount path the CA is imported into."
}

variable "network_name" {
  type        = string
  default     = "clm-integration"
  description = "Docker network name for the integration stack."
}

variable "app_image" {
  type        = string
  default     = "clm-discovery-int:latest"
  description = "Pre-built CLM API image tag (built by run-integration.sh)."
}
