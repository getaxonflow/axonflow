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

ORCH_URL="${AXONFLOW_ORCHESTRATOR_URL:-http://localhost:8081}"
CLIENT_ID="${AXONFLOW_CLIENT_ID:?must be set}"
CLIENT_SECRET="${AXONFLOW_CLIENT_SECRET:?must be set}"
AUTH="Basic $(echo -n "${CLIENT_ID}:${CLIENT_SECRET}" | base64)"

echo "=== OJK Audit Export ==="
echo

echo "[1/3] Export audit data (OJK_BI_COMBINED framework)"
curl -s --max-time 10 -X POST "${ORCH_URL}/api/v1/ojk/audit/export" \
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
curl -s --max-time 10 -X GET "${ORCH_URL}/api/v1/ojk/audit/readiness" \
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
curl -s --max-time 10 -X GET "${ORCH_URL}/api/v1/ojk/dashboard" \
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
