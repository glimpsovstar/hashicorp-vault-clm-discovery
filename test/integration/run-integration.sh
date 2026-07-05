#!/usr/bin/env sh
# Scenario 1 (local, CI): Terraform-provisions the whole stack (postgres, migrate,
# CLM app, Vault dev + PKI, self-signed nginx), runs the build-tagged Go driver
# that scans -> imports the CA into Vault (mode B) -> verifies, then ALWAYS tears
# the stack down. Exit code is the test result, so it is CI/PR-safe.
#
# Requires: terraform, docker, go, curl. No secrets.
set -eu

HERE="$(cd "$(dirname "$0")" && pwd)"
TF_DIR="$HERE/terraform/local"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"

cleanup() {
  echo "==> tearing down integration stack"
  terraform -chdir="$TF_DIR" destroy -auto-approve >/dev/null 2>&1 || true
}
trap 'exit 130' INT TERM
trap cleanup EXIT

echo "==> building CLM API image"
docker build -t clm-discovery-int:latest -f "$REPO_ROOT/deploy/Dockerfile.api" "$REPO_ROOT"

echo "==> terraform init + apply (postgres, migrate, app, vault, nginx)"
terraform -chdir="$TF_DIR" init -input=false >/dev/null
terraform -chdir="$TF_DIR" apply -auto-approve -input=false

APP_URL="$(terraform -chdir="$TF_DIR" output -raw app_url)"
VAULT_ADDR="$(terraform -chdir="$TF_DIR" output -raw vault_addr)"
VAULT_TOKEN="$(terraform -chdir="$TF_DIR" output -raw vault_token)"
PKI_MOUNT="$(terraform -chdir="$TF_DIR" output -raw pki_mount)"
CA_CN="$(terraform -chdir="$TF_DIR" output -raw ca_common_name)"
SCAN_TARGET="$(terraform -chdir="$TF_DIR" output -raw scan_target)"

echo "==> waiting for the CLM API to become healthy at $APP_URL"
i=1
until curl -sf "$APP_URL/api/v1/health" >/dev/null 2>&1; do
  i=$((i + 1))
  if [ "$i" -gt 60 ]; then
    echo "app did not become healthy in time" >&2
    exit 1
  fi
  sleep 2
done

echo "==> running integration driver"
if INTEGRATION_APP_URL="$APP_URL" \
  INTEGRATION_VAULT_ADDR="$VAULT_ADDR" \
  INTEGRATION_VAULT_TOKEN="$VAULT_TOKEN" \
  INTEGRATION_PKI_MOUNT="$PKI_MOUNT" \
  INTEGRATION_CA_CN="$CA_CN" \
  INTEGRATION_SCAN_TARGET="$SCAN_TARGET" \
  go test -tags integration -count=1 "$REPO_ROOT/test/integration/..." -run TestIntegration -v; then
  rc=0
else
  rc=$?
fi

echo "==> integration finished (exit $rc)"
exit "$rc"
