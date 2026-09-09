#!/usr/bin/env bash
# Full API drill battery. Boots a fresh server per drill with the env
# that drill expects, runs it, tears down. Used locally and by the
# api-drills CI workflow.
#
# Requirements:
#   - Postgres reachable at $DATABASE_URL (default av/av@localhost:5433/avdb,
#     already migrated: npx prisma migrate deploy)
#   - $PG_CONTAINER: a docker container name whose psql can reach that DB
#     (drills seed/inspect rows via docker exec)
#   - PG_USER/PG_DB matching the DATABASE_URL role/db (default av/avdb)
#
# Usage: server/scripts/run-drill-battery.sh [drill-name ...]
set -u
cd "$(dirname "$0")/.."

export APP_BASE_URL=${APP_BASE_URL:-http://127.0.0.1:8988}
export ALLOWED_ORIGINS=${ALLOWED_ORIGINS:-http://127.0.0.1:8988}
export PG_CONTAINER=${PG_CONTAINER:-server-db-1}
export PG_USER=${PG_USER:-av}
export PG_DB=${PG_DB:-avdb}
AVURL=${DATABASE_URL:-postgresql://av:av@localhost:5433/avdb}

PASS=0
FAIL=0
FAILED_NAMES=""

run_drill() {
  local name=$1 port=$2; shift 2
  local pidfile
  pidfile=$(mktemp)
  ( export PORT=$port API_PUBLIC_URL="http://127.0.0.1:$port" DATABASE_URL="$AVURL" "$@"
    node node_modules/.bin/tsx src/index.ts > "/tmp/drill-$name.log" 2>&1 & echo $! > "$pidfile" )
  local up=0
  for _ in $(seq 1 60); do curl -sf -o /dev/null "http://127.0.0.1:$port/healthz" && { up=1; break; }; sleep 1; done
  local rc=1 out=""
  if [[ $up == 1 ]]; then
    # 87xx drills read BASE, 43xx/44xx drills read API_BASE; export both.
    out=$(BASE="http://127.0.0.1:$port" API_BASE="http://127.0.0.1:$port" IDP_PORT=20498 node "scripts/$name.mjs" 2>&1); rc=$?
  else
    out="server for $name never became healthy; log tail:"$'\n'"$(tail -5 "/tmp/drill-$name.log")"
  fi
  kill "$(cat "$pidfile")" 2>/dev/null
  rm -f "$pidfile"
  sleep 1
  if [[ $rc == 0 ]]; then
    PASS=$((PASS+1)); echo "PASS  $name"
  else
    FAIL=$((FAIL+1)); FAILED_NAMES="$FAILED_NAMES $name"
    # Full output, not a tail: the drills print their failing check
    # exactly once, usually well above the last 20 lines (cleanup logs
    # sit between), so a truncated echo makes CI flakes undiagnosable.
    echo "FAIL  $name (rc=$rc)"; echo "$out"
  fi
}

# name|port[|extra-env...] — | because env values carry URLs with colons
ALL_DRILLS=(
  "apikey-drill|20745"
  "apikey-hardening|20745"
  "invite-drill|20445"
  "invite-hardening|20446"
  "ip-allowlist-drill|20750"
  "retention-drill|20749|DISABLE_RETENTION_SWEEPER=true"
  "saml-drill|20440"
  "saml-hardening|20441"
  "webauthn-drill|20443"
  "webauthn-hardening|20444"
  "webhook-drill|20747|ALLOW_INTERNAL_WEBHOOK_TARGETS=true|WEBHOOK_SWEEPER_INTERVAL_MS=1000"
  "webhook-hardening|20748|ALLOW_INTERNAL_WEBHOOK_TARGETS=true|WEBHOOK_SWEEPER_INTERVAL_MS=1000"
  "webhook-adapter-drill|20752|ALLOW_INTERNAL_WEBHOOK_TARGETS=true|WEBHOOK_SWEEPER_INTERVAL_MS=1000"
  "oidc-drill|20499|OIDC_ISSUER_URL=http://127.0.0.1:20498|OIDC_CLIENT_ID=av-console|OIDC_CLIENT_SECRET=drill-secret-123|OIDC_DISPLAY_NAME=Keycloak"
)

selected=("$@")
for spec in "${ALL_DRILLS[@]}"; do
  IFS='|' read -r -a parts <<< "$spec"
  name=${parts[0]}; port=${parts[1]}
  if [[ ${#selected[@]} -gt 0 ]]; then
    keep=0
    for s in "${selected[@]}"; do [[ $s == "$name" ]] && keep=1; done
    [[ $keep == 0 ]] && continue
  fi
  extra=()
  for ((i = 2; i < ${#parts[@]}; i++)); do extra+=("${parts[$i]}"); done
  run_drill "$name" "$port" "${extra[@]+"${extra[@]}"}"
done

echo
echo "battery: $PASS passed, $FAIL failed${FAILED_NAMES:+ —$FAILED_NAMES}"
[[ $FAIL == 0 ]]
