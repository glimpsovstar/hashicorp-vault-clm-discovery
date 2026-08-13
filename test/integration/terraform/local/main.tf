locals {
  # Repo root relative to this module (local -> terraform -> integration -> test -> root).
  repo_root = abspath("${path.module}/../../../..")
  pg_dsn    = "postgres://clm:clm@postgres:5432/clm?sslmode=disable"
}

resource "docker_network" "clm" {
  name = var.network_name
}

# --- PostgreSQL ---------------------------------------------------------------

resource "docker_image" "postgres" {
  name = "postgres:16-alpine"
}

resource "docker_container" "postgres" {
  name  = "clm-int-postgres"
  image = docker_image.postgres.image_id

  networks_advanced {
    name    = docker_network.clm.name
    aliases = ["postgres"]
  }

  env = [
    "POSTGRES_USER=clm",
    "POSTGRES_PASSWORD=clm",
    "POSTGRES_DB=clm",
  ]

  healthcheck {
    test     = ["CMD-SHELL", "pg_isready -U clm -d clm"]
    interval = "2s"
    timeout  = "3s"
    retries  = 30
  }
}

# --- Schema migrations (one-shot, blocking) ----------------------------------

# Run golang-migrate to completion before the app is created. A docker_container
# with must_run=false is not reliably started, so we drive a one-shot `docker run`
# via local-exec that retries until Postgres is ready and migrations apply.
resource "null_resource" "migrate" {
  depends_on = [docker_container.postgres]

  provisioner "local-exec" {
    interpreter = ["/bin/sh", "-c"]
    command     = <<-EOT
      for i in $(seq 1 30); do
        docker run --rm --network ${docker_network.clm.name} \
          -v ${local.repo_root}/migrations:/migrations:ro \
          migrate/migrate:v4.17.1 -path /migrations -database '${local.pg_dsn}' up && exit 0
        sleep 2
      done
      echo 'migrations failed' >&2; exit 1
    EOT
  }
}

# --- CLM API ------------------------------------------------------------------

# The image is built by run-integration.sh (docker CLI) before apply; the docker
# provider's own build tars the whole repo and is flaky, so we reference the
# pre-built tag here.
data "docker_image" "app" {
  name = var.app_image
}

resource "docker_container" "app" {
  name  = "clm-int-app"
  image = data.docker_image.app.id

  networks_advanced {
    name    = docker_network.clm.name
    aliases = ["app"]
  }

  env = [
    "DATABASE_URL=${local.pg_dsn}",
    "ALLOW_PRIVATE_RANGES=true",
    "LOG_LEVEL=info",
    # Hatch so the Go driver can keep calling the API without Bearer.
    # Alternative: CLM_STATIC_TOKENS + Authorization on every request.
    "CLM_INSECURE_NO_AUTH=true",
    "VAULT_ADDR=http://vault:8200",
    "VAULT_TOKEN=${var.vault_dev_root_token}",
    # Split import identity — VAULT_TOKEN alone returns 503 on CA import.
    "VAULT_IMPORT_TOKEN=${var.vault_dev_root_token}",
  ]

  ports {
    internal = 8080
    external = var.app_host_port
  }

  # The app may boot before migrate finishes; restart until the schema exists.
  restart = "on-failure"

  healthcheck {
    test     = ["CMD-SHELL", "wget -qO- http://127.0.0.1:8080/api/v1/health 2>/dev/null | grep -q ok || exit 1"]
    interval = "2s"
    timeout  = "3s"
    retries  = 30
  }

  depends_on = [docker_container.postgres, null_resource.migrate, docker_container.vault]
}
