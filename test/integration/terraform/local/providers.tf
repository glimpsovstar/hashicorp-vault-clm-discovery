terraform {
  required_version = ">= 1.6"
  required_providers {
    docker = {
      source  = "kreuzwerker/docker"
      version = "~> 3.0"
    }
    vault = {
      source  = "hashicorp/vault"
      version = "~> 4.0"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
    null = {
      source  = "hashicorp/null"
      version = "~> 3.2"
    }
  }
}

provider "docker" {}

# Points at the Vault dev container once it is up. The null_resource in vault.tf
# gates the vault provider's first use on Vault becoming ready.
provider "vault" {
  address          = "http://127.0.0.1:${var.vault_host_port}"
  token            = var.vault_dev_root_token
  skip_child_token = true
}
