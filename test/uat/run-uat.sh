#!/usr/bin/env sh
# Self-contained UAT runner: builds + starts the stack, waits for health, runs
# the assertion driver, and ALWAYS tears the stack down afterward (including on
# failure or Ctrl-C). Exit code is the driver's result, so this is CI/PR-safe.
#
# Usage:
#   sh test/uat/run-uat.sh                 # default profile (self-signed matrix)
#   COMPOSE_PROFILES=vault sh test/uat/run-uat.sh   # also bring up the vault profile
#
# The `letsencrypt` profile is intentionally NOT run here (needs a public domain
# + reachable :80); run it manually per test/uat/README.md.
set -u

cd "$(dirname "$0")"
COMPOSE="docker compose -f docker-compose.uat.yml"
API="${API:-http://localhost:8080}"

cleanup() {
	echo "==> tearing down UAT stack"
	$COMPOSE down -v --remove-orphans >/dev/null 2>&1 || true
}
# Clean up on interrupt/terminate as well as the normal exit path below.
trap 'cleanup' INT TERM

echo "==> ensuring a clean slate (isolate from any leftover stack/state)"
$COMPOSE down -v --remove-orphans >/dev/null 2>&1 || true

echo "==> building + starting UAT stack (waiting for ALL services healthy)"
# --wait blocks until postgres, the app, and every nginx endpoint report
# healthy (and the one-shot gen-certs/migrate complete). This gates the scan on
# real endpoint readiness, so it never races past a not-yet-listening endpoint.
if ! $COMPOSE up -d --build --force-recreate --wait --wait-timeout 180; then
	echo "stack did not become healthy in time"
	cleanup
	exit 1
fi

echo "==> running driver"
API="$API" sh driver.sh
rc=$?

cleanup
echo "==> UAT finished (exit $rc)"
exit "$rc"
