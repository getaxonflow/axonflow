#!/usr/bin/env bash
# Decision Mode + Indonesia PII Detection
#
# Demonstrates Decision Mode deny/allow verdicts for Indonesian PII patterns.
# Tests NIK (National ID), NPWP (Tax ID), and clean requests.
#
# Prerequisites:
#   docker compose -f docker-compose.yml -f docker-compose.enterprise.yml up -d
#   export AXONFLOW_CLIENT_ID=your-client-id
#   export AXONFLOW_CLIENT_SECRET=your-client-secret
#   export PII_ACTION=block  # Required for deny verdicts

set -euo pipefail

AGENT_URL="${AXONFLOW_AGENT_URL:-http://localhost:8080}"
CLIENT_ID="${AXONFLOW_CLIENT_ID:?must be set}"
CLIENT_SECRET="${AXONFLOW_CLIENT_SECRET:?must be set}"
AUTH="Basic $(echo -n "${CLIENT_ID}:${CLIENT_SECRET}" | base64)"

decide() {
  local query="$1"
  curl -s --max-time 10 -X POST "${AGENT_URL}/api/v1/decide" \
    -H "Authorization: ${AUTH}" \
    -H "Content-Type: application/json" \
    -d "{
      \"stage\": \"llm\",
      \"caller_identity\": {\"gateway_id\": \"example\", \"tenant_id\": \"${CLIENT_ID}\"},
      \"target\": {\"type\": \"llm\", \"model\": \"gpt-4o\", \"provider\": \"openai\"},
      \"query\": \"${query}\"
    }"
}

echo "=== Decision Mode: Indonesia PII Detection ==="
echo

echo "[1/3] NIK detection (expect: deny)"
decide "Customer NIK is 3174042506780001" | python3 -c "
import json,sys
d = json.load(sys.stdin)
verdict = d['verdict']
policies = d.get('evaluated_policies', [])
reasons = d.get('reasons', [])
print(f'  verdict={verdict} policies={policies}')
print(f'  reasons={reasons}')
assert verdict == 'deny', f'Expected deny, got {verdict}'
assert 'indonesia_pii_protection' in policies, f'Expected indonesia_pii_protection in {policies}'
print('  PASS')
"

echo
echo "[2/3] NPWP legacy detection (expect: deny)"
decide "Tax NPWP is 01.234.567.8-901.234" | python3 -c "
import json,sys
d = json.load(sys.stdin)
verdict = d['verdict']
print(f'  verdict={verdict} policies={d.get(\"evaluated_policies\",[])}')
assert verdict == 'deny', f'Expected deny, got {verdict}'
print('  PASS')
"

echo
echo "[3/3] Clean request (expect: allow)"
decide "What is Jakarta weather?" | python3 -c "
import json,sys
d = json.load(sys.stdin)
verdict = d['verdict']
print(f'  verdict={verdict}')
assert verdict == 'allow', f'Expected allow, got {verdict}'
print('  PASS')
"

echo
echo "=== All assertions passed ==="
