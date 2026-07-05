# --- Vault (dev mode) ---------------------------------------------------------

resource "docker_image" "vault" {
  name = "hashicorp/vault:1.17"
}

resource "docker_container" "vault" {
  name  = "clm-int-vault"
  image = docker_image.vault.image_id

  networks_advanced {
    name    = docker_network.clm.name
    aliases = ["vault"]
  }

  env = [
    "VAULT_DEV_ROOT_TOKEN_ID=${var.vault_dev_root_token}",
    "VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200",
  ]

  capabilities {
    add = ["IPC_LOCK"]
  }

  ports {
    internal = 8200
    external = var.vault_host_port
  }
}

# Gate the vault provider's first API call on the dev server being reachable.
resource "null_resource" "vault_ready" {
  depends_on = [docker_container.vault]

  provisioner "local-exec" {
    interpreter = ["/bin/sh", "-c"]
    command     = "for i in $(seq 1 30); do curl -sf http://127.0.0.1:${var.vault_host_port}/v1/sys/health >/dev/null 2>&1 && exit 0; sleep 1; done; echo 'vault not ready' >&2; exit 1"
  }
}

# Empty PKI mount the discovered CA will be imported into (mode B target).
resource "vault_mount" "pki" {
  depends_on  = [null_resource.vault_ready]
  path        = var.pki_mount
  type        = "pki"
  description = "CLM integration PKI mount"

  max_lease_ttl_seconds = 315360000 # 10y
}

# Read-write PKI policy documented for mode B (dev root already has root caps;
# this exists so the harness mirrors a least-privilege production token).
resource "vault_policy" "clm_import" {
  depends_on = [null_resource.vault_ready]
  name       = "clm-import"
  policy     = <<-EOT
    path "${var.pki_mount}/issuers/import/bundle" { capabilities = ["create", "update"] }
    path "${var.pki_mount}/issuer/*"              { capabilities = ["read"] }
    path "sys/mounts"                             { capabilities = ["read"] }
    path "${var.pki_mount}/certs"                 { capabilities = ["list"] }
    path "${var.pki_mount}/cert/*"                { capabilities = ["read"] }
  EOT
}
