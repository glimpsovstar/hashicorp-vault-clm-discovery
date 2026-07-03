#!/usr/bin/env sh
# UAT driver: triggers a scan against the docker-compose UAT stack and
# asserts the expiry/validity compliance matrix + shadow-cert blind spot.
#
# Runs from the HOST (not inside the app container). It only needs to reach
# the API at ${API:-http://localhost:8080}; the app container (inside the
# compose network) resolves the uat-<id> service hostnames via Docker's
# internal DNS when it performs the scan.
#
# Scan targets are Docker Compose SERVICE NAMES (uat-<id>), since that's what
# the app's net.LookupIP-based resolver can actually resolve inside the
# compose network. Compliance findings and certificates, however, are keyed
# by the certificate Subject CN, which the cert generator sets to
# "<id>.uat.test" (see test/uat/gen-certs/main.go). So every assertion below
# maps id -> service name "uat-<id>" (for scanning) and id -> CN
# "<id>.uat.test" (for matching findings/certs).
set -eu

API="${API:-http://localhost:8080}"
PORT=443
IDS="expired exp-7 exp-14 exp-15 exp-30 exp-45 exp-60 exp-61 valid-99 valid-400"

# Expected sc081 expiry rule per id ("" = none) and prod severity.
expiry_rule() { case "$1" in
  expired) echo "sc081.expiry.expired";; exp-7|exp-14) echo "sc081.expiry.critical";;
  exp-15|exp-30|exp-45|exp-60) echo "sc081.expiry.warning";; *) echo "";; esac; }
prod_sev() { case "$1" in
  expired|exp-7|exp-14) echo critical;; exp-15|exp-30|exp-45|exp-60) echo warning;; *) echo "";; esac; }
expect_validity() { [ "$1" = "valid-400" ]; }

# Docker Compose service name for a given id (used as the scan hostname).
service_name() { echo "uat-$1"; }
# Certificate Subject CN for a given id (used to match findings/certs).
cn_for() { echo "$1.uat.test"; }

hostnames_json() {
  first=1
  for id in $IDS; do
    if [ "$first" = 1 ]; then first=0; else printf ','; fi
    printf '"%s"' "$(service_name "$id")"
  done
}

echo "==> triggering scan"
SCAN=$(curl -fsS -X POST "$API/api/v1/scans" -H 'Content-Type: application/json' \
  -d "{\"hostnames\":[$(hostnames_json)],\"ports\":[$PORT],\"consent\":true}")
SID=$(echo "$SCAN" | jq -r .id)
[ -n "$SID" ] && [ "$SID" != "null" ] || { echo "FAIL: scan creation did not return an id (response: $SCAN)"; exit 1; }

echo "==> waiting for scan $SID"
ST=""
i=1
while [ "$i" -le 60 ]; do
  ST=$(curl -fsS "$API/api/v1/scans/$SID" | jq -r .status)
  [ "$ST" = completed ] && break
  [ "$ST" = failed ] && { echo "FAIL: scan $SID failed"; exit 1; }
  sleep 2
  i=$((i + 1))
done
[ "$ST" = completed ] || { echo "FAIL: scan $SID did not complete within timeout (last status: $ST)"; exit 1; }

COMP=$(curl -fsS "$API/api/v1/scans/$SID/compliance")

fail=0

# find a cert id in inventory by subject CN
cert_id_for() {
  cn=$(cn_for "$1")
  curl -fsS "$API/api/v1/scans/$SID/certificates" \
    | jq -r --arg cn "$cn" '.items[] | select(.subject_cn==$cn) | .id'
}
# severity of the sc081 expiry finding for a subject CN in the compliance doc
sev_for() {
  cn=$(cn_for "$1")
  echo "$COMP" | jq -r --arg cn "$cn" \
    '[.findings[] | select(.pack=="sc081" and (.rule_id|startswith("sc081.expiry")) and .subject_cn==$cn)][0].severity // ""'
}
rule_for() {
  cn=$(cn_for "$1")
  echo "$COMP" | jq -r --arg cn "$cn" \
    '[.findings[] | select(.pack=="sc081" and (.rule_id|startswith("sc081.expiry")) and .subject_cn==$cn)][0].rule_id // ""'
}
validity_sev() {
  cn=$(cn_for "$1")
  echo "$COMP" | jq -r --arg cn "$cn" \
    '[.findings[] | select(.pack=="sc081" and (.rule_id|startswith("sc081.validity")) and .subject_cn==$cn)][0].severity // ""'
}

echo "==> asserting as-discovered (internal) severities"
for id in $IDS; do
  want_rule=$(expiry_rule "$id"); got_rule=$(rule_for "$id"); got_sev=$(sev_for "$id")
  if [ -n "$want_rule" ]; then
    [ "$got_rule" = "$want_rule" ] || { echo "FAIL $id: expiry rule got='$got_rule' want='$want_rule'"; fail=1; }
    [ "$got_sev" = "info" ] || { echo "FAIL $id: internal severity got='$got_sev' want='info'"; fail=1; }
  else
    [ -z "$got_rule" ] || { echo "FAIL $id: unexpected expiry finding '$got_rule'"; fail=1; }
  fi
  if expect_validity "$id"; then
    [ "$(validity_sev "$id")" = "critical" ] || { echo "FAIL $id: expected critical validity finding"; fail=1; }
  fi
done

echo "==> enriching expiry certs to prod and re-checking full severity"
for id in $IDS; do
  ws=$(prod_sev "$id"); [ -n "$ws" ] || continue
  cid=$(cert_id_for "$id"); [ -n "$cid" ] || { echo "FAIL $id: cert not found for PATCH"; fail=1; continue; }
  curl -fsS -X PATCH "$API/api/v1/certificates/$cid" -H 'Content-Type: application/json' \
    -d '{"environment":"prod"}' >/dev/null
done
COMP=$(curl -fsS "$API/api/v1/scans/$SID/compliance")
for id in $IDS; do
  ws=$(prod_sev "$id"); [ -n "$ws" ] || continue
  gs=$(sev_for "$id")
  [ "$gs" = "$ws" ] || { echo "FAIL $id: prod severity got='$gs' want='$ws'"; fail=1; }
done

echo "==> asserting shadow certs in blind-spot"
BS=$(curl -fsS "$API/api/v1/scans/$SID/blindspot")
[ "$(echo "$BS" | jq -r .vault_managed)" = "0" ] || { echo "FAIL: expected vault_managed=0, got $(echo "$BS" | jq -r .vault_managed)"; fail=1; }
[ "$(echo "$BS" | jq -r .shadow)" -ge 1 ] || { echo "FAIL: expected shadow>=1, got $(echo "$BS" | jq -r .shadow)"; fail=1; }

[ "$fail" = 0 ] && echo "UAT PASS" || { echo "UAT FAIL"; exit 1; }
