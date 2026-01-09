#!/bin/bash
# MCP Policy Enforcement - Response Redaction Example
#
# Demonstrates PII redaction at the RESPONSE phase.
# When connector data contains PII (SSN, credit cards, etc.),
# the policy engine redacts those fields.
#
# Prerequisites: docker compose up -d

set -e

ENDPOINT="${AXONFLOW_ENDPOINT:-http://localhost:8080}"
CLIENT_ID="${AXONFLOW_CLIENT_ID:-demo}"
CLIENT_SECRET="${AXONFLOW_CLIENT_SECRET:-demo}"

echo "MCP Policy Enforcement - Response Redaction"
echo "============================================"
echo ""
echo "Querying data that may contain PII..."
echo ""

# Base64 encode credentials for Basic auth
CREDENTIALS=$(echo -n "${CLIENT_ID}:${CLIENT_SECRET}" | base64)

# Query customer records - if PII exists, it will be redacted
curl -s -X POST "${ENDPOINT}/mcp/resources/query" \
  -H "Content-Type: application/json" \
  -H "Authorization: Basic ${CREDENTIALS}" \
  -d '{
    "connector": "postgres",
    "statement": "SELECT name, ssn, credit_card FROM customer_records LIMIT 1"
  }' | python3 -m json.tool 2>/dev/null || echo "Response parsing failed"

echo ""
echo "Response Analysis"
echo "-----------------"
echo ""
echo "If the response contains:"
echo '  "redacted": true'
echo '  "redacted_fields": ["data.rows[0].ssn", ...]'
echo ""
echo "Then PII was detected and redacted at the RESPONSE phase."
echo ""
echo "The policy_info object shows:"
echo "  - policies_evaluated: Number of policies checked"
echo "  - redactions_applied: Number of fields redacted"
echo "  - processing_time_ms: Policy evaluation time"
echo "  - matched_policies: Which policies triggered"
