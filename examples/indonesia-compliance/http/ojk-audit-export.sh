#!/usr/bin/env bash
# OJK Audit Export
#
# Demonstrates the OJK compliance audit export endpoint.
# Returns audit data formatted for OJK regulatory reporting.
#
# Prerequisites:
#   docker compose -f docker-compose.yml -f docker-compose.enterprise.yml up -d
#   export AXONFLOW_CLIENT_ID=your-client-id
#   export AXONFLOW_CLIENT_SECRET=your-client-secret

set -euo pipefail


# --- internal-service proxy auth (#3068) ------------------------------------
# The orchestrator requires an HMAC-signed X-Axonflow-Proxy-Auth token on every
# non-exempt route. This minter is INLINE on purpose: this example ships to
# users who do not have the enterprise repo checked out (release tarball,
# community distribution), so it must not depend on `git rev-parse` succeeding
# or on any file outside this directory.
#
# Token format is fixed by platform/shared/serviceauth/serviceauth.go:
#   AXON-INTERNAL-<unix_ts>-<first 16 hex chars of
#                            HMAC-SHA256(secret, "orchestrator-internal:<unix_ts>")>
# A token is valid for 5 minutes (serviceauth.DefaultClockSkew), so mint one
# per request rather than once at the top of a long-running script.
axonflow_proxy_token() {
  local secret="${AXONFLOW_INTERNAL_SERVICE_SECRET:-}"
  if [ -z "$secret" ]; then
    # The docker compose quickstart in the Prerequisites above starts the
    # orchestrator with this default. Against any other deployment you must
    # export the real secret or every call below returns 403.
    secret="localdev-internal-service-secret-change-me"
  fi
  local ts sig
  ts=$(date +%s)
  # openssl prints "SHA2-256(stdin)= <hex>" or "(stdin)= <hex>" depending on
  # version; take the last field either way. printf (not echo) so that no
  # trailing newline enters the MAC.
  sig=$(printf 'orchestrator-internal:%s' "$ts" \
        | openssl dgst -sha256 -hmac "$secret" -hex \
        | awk '{print $NF}' \
        | cut -c1-16)
  printf 'AXON-INTERNAL-%s-%s' "$ts" "$sig"
}

# orch_curl runs curl with a freshly-minted proxy-auth header prepended.
# All arguments are passed through to curl unchanged.
orch_curl() {
  local token
  token=$(axonflow_proxy_token) || return 1
  curl -H "X-Axonflow-Proxy-Auth: ${token}" "$@"
}

# Announced once here rather than on every call: if the deployment you are
# pointing at was started with a different secret, every request below returns
# 403 and this is the first place to look.
if [ -z "${AXONFLOW_INTERNAL_SERVICE_SECRET:-}" ]; then
  echo "[axonflow] AXONFLOW_INTERNAL_SERVICE_SECRET is unset — using the docker compose default." >&2
  echo "[axonflow] Export the secret your deployment was started with, or these calls will return 403." >&2
fi
# ----------------------------------------------------------------------------

ORCH_URL="${AXONFLOW_ORCHESTRATOR_URL:-http://localhost:8081}"
CLIENT_ID="${AXONFLOW_CLIENT_ID:?must be set}"
CLIENT_SECRET="${AXONFLOW_CLIENT_SECRET:?must be set}"
AUTH="Basic $(echo -n "${CLIENT_ID}:${CLIENT_SECRET}" | base64)"

echo "=== OJK Audit Export ==="
echo

echo "[1/3] Export audit data (OJK_BI_COMBINED framework)"
orch_curl -s --max-time 10 -X POST "${ORCH_URL}/api/v1/ojk/audit/export" \
  -H "Authorization: ${AUTH}" \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: ${CLIENT_ID}" \
  -d '{
    "start_date": "2025-01-01",
    "end_date": "2025-12-31",
    "format": "json",
    "framework": "OJK_BI_COMBINED"
  }' | python3 -c "
import json,sys
d = json.load(sys.stdin)
export_id = d.get('export_id', '')
status = d.get('status', '')
print(f'  export_id={export_id[:8]}...')
print(f'  status={status}')
print(f'  framework={d.get(\"framework\",\"\")}')
print(f'  total_records={d.get(\"summary\",{}).get(\"total_records\",0)}')
assert export_id, 'Missing export_id'
assert status == 'completed', f'Expected completed, got {status}'
print('  PASS')
"

echo
echo "[2/3] Check compliance readiness"
orch_curl -s --max-time 10 -X GET "${ORCH_URL}/api/v1/ojk/audit/readiness" \
  -H "Authorization: ${AUTH}" \
  -H "X-Tenant-ID: ${CLIENT_ID}" | python3 -c "
import json,sys
d = json.load(sys.stdin)
score = d.get('score', 0)
ready = d.get('ready', False)
checks = d.get('checks', [])
print(f'  score={score} ready={ready}')
for c in checks:
    print(f'  [{c[\"status\"]}] {c[\"name\"]}: {c[\"details\"][:60]}')
assert score > 0, 'Score should be positive'
print('  PASS')
"

echo
echo "[3/3] Dashboard overview"
orch_curl -s --max-time 10 -X GET "${ORCH_URL}/api/v1/ojk/dashboard" \
  -H "Authorization: ${AUTH}" \
  -H "X-Tenant-ID: ${CLIENT_ID}" | python3 -c "
import json,sys
d = json.load(sys.stdin)
print(f'  compliance_score={d.get(\"compliance_score\",0)}')
print(f'  active_policies={d.get(\"active_policies\",0)}')
print(f'  retention_status={d.get(\"retention_status\",\"\")}')
print(f'  breach_notifications={d.get(\"breach_notifications\",0)}')
print('  PASS')
"

echo
echo "=== All assertions passed ==="
