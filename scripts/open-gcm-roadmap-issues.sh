#!/usr/bin/env bash
# Create umbrella + M1–M5 GitHub issues from docs/superpowers/issues/*.md
# Requires: gh authenticated to github.com (not only github.ibm.com).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
REPO="${REPO:-glimpsovstar/hashicorp-vault-clm-discovery}"
cd "$ROOT"

if ! GH_HOST=github.com gh auth status -h github.com >/dev/null 2>&1; then
  echo "gh is not logged in to github.com. Run: gh auth login -h github.com" >&2
  exit 1
fi

create() {
  local title="$1" body="$2" label="$3"
  GH_HOST=github.com gh issue create -R "$REPO" --title "$title" --body-file "$body" --label "$label"
}

umbrella="$(create "GCM closed-loop roadmap (M1–M5)" \
  "$ROOT/docs/superpowers/issues/umbrella-gcm-closed-loop.md" \
  feature)"
echo "Umbrella: $umbrella"

# Extract issue number from URL (…/issues/N)
num="${umbrella##*/}"

create "M1: Secure the control plane (auth/RBAC/audit/AppRole)" \
  "$ROOT/docs/superpowers/issues/m1-control-plane-security.md" feature
create "M2: Durable lifecycle jobs + wire verification" \
  "$ROOT/docs/superpowers/issues/m2-durable-lifecycle-jobs.md" feature
create "M4: Durable Postgres scan queue (SKIP LOCKED)" \
  "$ROOT/docs/superpowers/issues/m4-durable-scan-queue.md" feature
create "M3: Explainable posture (findings, risk_score, waivers, PQC tags)" \
  "$ROOT/docs/superpowers/issues/m3-explainable-posture.md" feature
create "M5: Broader integrations (events, revoke-via-AAP, ITSM, cloud collectors)" \
  "$ROOT/docs/superpowers/issues/m5-broader-integrations.md" feature

echo "Link children to umbrella #$num in GitHub, then update the tracker with issue numbers."
echo "Umbrella #$num"
