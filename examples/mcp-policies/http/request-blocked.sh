#!/bin/bash
# MCP Policy Enforcement - Request Blocked Example
#
# Demonstrates SQLi pattern blocking at the REQUEST phase.
# The query contains a DROP TABLE statement which triggers security-sqli policy.
#
# Prerequisites: docker compose up -d

set -e

ENDPOINT="${AXONFLOW_ENDPOINT:-http://localhost:8080}"
CLIENT_ID="${AXONFLOW_CLIENT_ID:-community}"
CLIENT_SECRET="${AXONFLOW_CLIENT_SECRET:-demo}"

echo "MCP Policy Enforcement - Request Blocked"
echo "=========================================="
echo ""
echo "Sending SQLi pattern to MCP endpoint..."
echo ""

# Base64 encode credentials for Basic auth
CREDENTIALS=$(echo -n "${CLIENT_ID}:${CLIENT_SECRET}" | base64)

# This should return 403 Forbidden
HTTP_CODE=$(curl -s -o /tmp/response.json -w "%{http_code}" \
  -X POST "${ENDPOINT}/mcp/resources/query" \
  -H "Content-Type: application/json" \
  -H "Authorization: Basic ${CREDENTIALS}" \
  -d '{
    "connector": "postgres",
    "statement": "SELECT * FROM users WHERE id = 1; DROP TABLE users; --"
  }')

echo "HTTP Status Code: ${HTTP_CODE}"
echo ""
echo "Response:"
cat /tmp/response.json | python3 -m json.tool 2>/dev/null || cat /tmp/response.json
echo ""

if [ "$HTTP_CODE" = "403" ] || [ "$HTTP_CODE" = "400" ]; then
    echo ""
    echo "PASS: Request was blocked as expected (HTTP ${HTTP_CODE})"
    echo ""
    echo "The security-sqli policy detected the DROP TABLE pattern"
    echo "and blocked the request at the REQUEST phase."
else
    echo ""
    echo "FAIL: Expected HTTP 403, got ${HTTP_CODE}"
    exit 1
fi
