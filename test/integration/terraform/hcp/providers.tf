terraform {
  required_version = ">= 1.6"
  required_providers {
    vault = {
      source  = "hashicorp/vault"
      version = "~> 4.0"
    }
    hcp = {
      source  = "hashicorp/hcp"
      version = "~> 0.90"
    }
  }
}

# The hcp provider authenticates from the environment
# (HCP_CLIENT_ID / HCP_CLIENT_SECRET / HCP_PROJECT_ID). It is declared so the
# lane can be extended to manage the cluster; PKI config below uses the vault
# provider against the existing cluster.
provider "hcp" {}

provider "vault" {
  address          = var.vault_addr
  namespace        = var.vault_namespace
  token            = var.vault_token
  skip_child_token = true
}
