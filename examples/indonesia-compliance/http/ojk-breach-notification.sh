#!/usr/bin/env bash
# OJK Breach Notification (UU PDP Art. 46)
#
# Demonstrates the UU PDP Art. 46 breach notification endpoint.
# Generates a breach report with the legally required fields:
# - data_types_involved
# - discovery_timestamp
# - remediation_steps
# - notification_deadline (auto-calculated: discovery + 72 hours)
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

echo "=== UU PDP Art. 46 Breach Notification ==="
echo

echo "[1/2] Submit breach notification"
orch_curl -s --max-time 10 -X POST "${ORCH_URL}/api/v1/ojk/breach/notify" \
  -H "Authorization: ${AUTH}" \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: ${CLIENT_ID}" \
  -d '{
    "incident_timestamp": "2026-05-20T10:00:00Z",
    "discovery_time": "2026-05-20T12:00:00Z",
    "data_subjects_affected": 500,
    "data_types_involved": ["NIK", "NPWP", "phone_numbers"],
    "description": "Unauthorized access to customer PII via compromised API key",
    "remediation_steps": [
      "Revoked compromised API key",
      "Rotated all secrets",
      "Notified affected users via SMS and email"
    ]
  }' | python3 -c "
import json,sys
d = json.load(sys.stdin)
breach_id = d.get('id', '')
deadline = d.get('notification_deadline', '')
authority = d.get('notified_authority', '')
status = d.get('status', '')
data_types = d.get('data_types_involved', [])
remediation = d.get('remediation_steps', [])

print(f'  id={breach_id[:8]}...')
print(f'  notification_deadline={deadline}')
print(f'  notified_authority={authority}')
print(f'  status={status}')
print(f'  data_types={data_types}')
print(f'  remediation_steps={len(remediation)} steps')

assert breach_id, 'Missing breach id'
assert deadline, 'Missing notification_deadline (Art. 46 requires 72h)'
assert authority == 'MOCDA', f'Expected MOCDA, got {authority}'
assert len(data_types) > 0, 'data_types_involved must not be empty'
assert len(remediation) > 0, 'remediation_steps must not be empty'
print('  PASS — All Art. 46 required fields present')
"

echo
echo "[2/2] Verify retention compliance"
orch_curl -s --max-time 10 -X GET "${ORCH_URL}/api/v1/ojk/audit/retention" \
  -H "Authorization: ${AUTH}" \
  -H "X-Tenant-ID: ${CLIENT_ID}" | python3 -c "
import json,sys
d = json.load(sys.stdin)
status = d.get('compliance_status', '')
days = d.get('retention_days', 0)
min_days = d.get('min_retention_days', 0)
print(f'  compliance_status={status}')
print(f'  retention_days={days} (minimum={min_days})')
assert status == 'compliant', f'Expected compliant, got {status}'
assert days >= min_days, f'Retention {days} below minimum {min_days}'
print('  PASS')
"

echo
echo "=== All assertions passed ==="
