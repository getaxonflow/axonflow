#!/bin/bash
# Exfiltration Detection Example: Row Limit Exceeded
#
# This example demonstrates exfiltration blocking when row limit is exceeded.
#
# IMPORTANT: This test requires docker-compose to be started with a low row limit:
#   MCP_MAX_ROWS_PER_QUERY=5 docker-compose up -d --build
#
# The script will:
# 1. Create test data (20 rows) using /mcp/tools/execute
# 2. Attempt to query all rows (should be blocked at 5) using /mcp/resources/query
# 3. Verify the block response
# 4. Clean up test data

set -e

AGENT_URL="${AXONFLOW_AGENT_URL:-http://localhost:8080}"
# user_token: validated as JWT in eval/enterprise; any string in community.
# Read from AXONFLOW_USER_TOKEN env (setup-e2e-testing.sh writes it).
USER_TOKEN="${AXONFLOW_USER_TOKEN:-demo-user}"
CONNECTOR="${MCP_CONNECTOR:-postgres}"

# Auth: include Basic auth if credentials are set
CURL_AUTH=()
if [ -n "${AXONFLOW_CLIENT_ID:-}" ] && [ -n "${AXONFLOW_CLIENT_SECRET:-}" ]; then
  CURL_AUTH=(-u "${AXONFLOW_CLIENT_ID}:${AXONFLOW_CLIENT_SECRET}")
fi
acurl() { curl "${CURL_AUTH[@]}" "$@"; }

echo "=== Exfiltration Detection: Row Limit Exceeded ==="
echo ""
echo "NOTE: This test requires MCP_MAX_ROWS_PER_QUERY=5"
echo "      Run: MCP_MAX_ROWS_PER_QUERY=5 docker-compose up -d --build"
echo ""

# Step 1: Create test table with 20 rows using execute endpoint
echo "Step 1: Creating test data (20 rows)..."

# Drop if exists first
acurl -s -X POST "${AGENT_URL}/mcp/tools/execute" \
  -H "Content-Type: application/json" \
  -d "{
    \"connector\": \"${CONNECTOR}\",
    \"operation\": \"ddl\",
    \"action\": \"DROP\",
    \"statement\": \"DROP TABLE IF EXISTS exfil_limit_test\",
    \"user_token\": \"${USER_TOKEN}\"
  }" > /dev/null 2>&1 || true

# Create table
acurl -s -X POST "${AGENT_URL}/mcp/tools/execute" \
  -H "Content-Type: application/json" \
  -d "{
    \"connector\": \"${CONNECTOR}\",
    \"operation\": \"ddl\",
    \"action\": \"CREATE\",
    \"statement\": \"CREATE TABLE exfil_limit_test (id SERIAL PRIMARY KEY, data VARCHAR(100))\",
    \"user_token\": \"${USER_TOKEN}\"
  }" > /dev/null 2>&1 || true

# Insert 20 rows
acurl -s -X POST "${AGENT_URL}/mcp/tools/execute" \
  -H "Content-Type: application/json" \
  -d "{
    \"connector\": \"${CONNECTOR}\",
    \"operation\": \"insert\",
    \"action\": \"INSERT\",
    \"statement\": \"INSERT INTO exfil_limit_test (data) SELECT 'Row ' || i FROM generate_series(1, 20) AS i\",
    \"user_token\": \"${USER_TOKEN}\"
  }" > /dev/null 2>&1 || true

echo "✓ Created 20 test rows"
echo ""

# Step 2: Attempt query that exceeds limit using query endpoint
echo "Step 2: Querying all rows (expecting block if limit is 5)..."
echo ""

response=$(acurl -s -w "\n%{http_code}" -X POST "${AGENT_URL}/mcp/resources/query" \
  -H "Content-Type: application/json" \
  -d "{
    \"connector\": \"${CONNECTOR}\",
    \"statement\": \"SELECT * FROM exfil_limit_test\",
    \"user_token\": \"${USER_TOKEN}\"
  }")

http_code=$(echo "$response" | tail -n1)
body=$(echo "$response" | sed '$d')

echo "HTTP Status: $http_code"
echo ""

# Step 3: Analyze response
echo "=== Response Analysis ==="
echo ""

if [ "$http_code" = "403" ]; then
    echo "✓ Query BLOCKED (HTTP 403) - Exfiltration limit exceeded!"
    echo ""
    echo "Block reason:"
    echo "$body" | jq -r '.error // .block_reason // "Unknown"'
    echo ""
    echo "Limit details:"
    echo "$body" | jq '{limit_type, actual_value, limit_value}'
elif [ "$http_code" = "200" ]; then
    echo "Response (HTTP 200):"
    echo "$body" | jq .

    exfil_check=$(echo "$body" | jq '.policy_info.exfiltration_check // empty')
    if [ -n "$exfil_check" ] && [ "$exfil_check" != "null" ]; then
        within_limits=$(echo "$exfil_check" | jq -r '.within_limits // true')
        rows=$(echo "$exfil_check" | jq -r '.rows_returned // 0')
        row_limit=$(echo "$exfil_check" | jq -r '.row_limit // 10000')

        echo ""
        if [ "$within_limits" = "true" ]; then
            echo "ℹ Query succeeded - $rows rows returned (limit: $row_limit)"
            echo ""
            echo "  To test blocking, restart with lower limit:"
            echo "  MCP_MAX_ROWS_PER_QUERY=5 docker-compose up -d --build"
        fi
    else
        echo ""
        echo "ℹ exfiltration_check not present (feature may not be enabled)"
    fi
else
    echo "Unexpected HTTP status: $http_code"
    echo "$body" | jq . 2>/dev/null || echo "$body"
fi

# Step 4: Cleanup using execute endpoint
echo ""
echo "Step 4: Cleaning up test data..."
acurl -s -X POST "${AGENT_URL}/mcp/tools/execute" \
  -H "Content-Type: application/json" \
  -d "{
    \"connector\": \"${CONNECTOR}\",
    \"operation\": \"ddl\",
    \"action\": \"DROP\",
    \"statement\": \"DROP TABLE IF EXISTS exfil_limit_test\",
    \"user_token\": \"${USER_TOKEN}\"
  }" > /dev/null 2>&1 || true
echo "✓ Cleanup complete"

echo ""
echo "=== Test Complete ==="
