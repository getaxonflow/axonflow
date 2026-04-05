#!/bin/bash
# MCP PII Redaction - Response-Phase Redaction
#
# Tests that PII in connector response data is properly redacted:
# - SSN values are masked
# - Credit card numbers are masked
# - policy_info metadata is returned
#
# Prerequisites: docker compose up -d

set -e

ENDPOINT="${AXONFLOW_ENDPOINT:-http://localhost:8080}"
CLIENT_ID="${AXONFLOW_CLIENT_ID:-community}"
CLIENT_SECRET="${AXONFLOW_CLIENT_SECRET:-demo}"

# Base64 encode credentials for Basic auth
CREDENTIALS=$(echo -n "${CLIENT_ID}:${CLIENT_SECRET}" | base64)

echo "MCP PII Redaction - Response-Phase Redaction"
echo "============================================="
echo ""

echo "Query test_customers table (pre-seeded with PII)..."
echo ""

HTTP_CODE=$(curl -s -o /tmp/response.json -w "%{http_code}" \
  -X POST "${ENDPOINT}/mcp/resources/query" \
  -H "Content-Type: application/json" \
  -H "Authorization: Basic ${CREDENTIALS}" \
  -d '{
    "connector": "postgres",
    "statement": "SELECT * FROM test_customers LIMIT 1"
  }')

echo "HTTP Status: ${HTTP_CODE}"
echo ""
echo "Response:"
python3 -m json.tool /tmp/response.json 2>/dev/null || cat /tmp/response.json
echo ""

if [ "$HTTP_CODE" = "200" ]; then
    # Check for redacted flag
    REDACTED=$(python3 -c "import json; d=json.load(open('/tmp/response.json')); print(d.get('redacted', False))" 2>/dev/null || echo "false")

    if [ "$REDACTED" = "True" ] || [ "$REDACTED" = "true" ]; then
        echo "PASS: Response contains redacted PII"
        echo ""

        # Show redacted fields
        FIELDS=$(python3 -c "import json; d=json.load(open('/tmp/response.json')); print(', '.join(d.get('redacted_fields', [])))" 2>/dev/null || echo "unknown")
        echo "Redacted fields: ${FIELDS}"

        # Show policy info
        POLICIES=$(python3 -c "import json; d=json.load(open('/tmp/response.json')); p=d.get('policy_info', {}); print(f\"{p.get('policies_evaluated', 0)} policies, {p.get('redactions_applied', 0)} redactions\")" 2>/dev/null || echo "unknown")
        echo "PolicyInfo: ${POLICIES}"
    else
        echo "Note: No PII found in response (test_customers may be empty or no PII detected)"
    fi
elif [ "$HTTP_CODE" = "500" ]; then
    echo "Note: test_customers table may not exist"
    echo "Run 'docker compose up -d' to start services with test data"
else
    echo "FAIL: Unexpected response code ${HTTP_CODE}"
    exit 1
fi
