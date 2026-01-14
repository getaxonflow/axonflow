#!/bin/bash
# Exfiltration Detection Example: Query Within Limits
#
# This example demonstrates exfiltration detection by:
# 1. Creating test data (using /mcp/tools/execute)
# 2. Running a query within limits (using /mcp/resources/query)
# 3. Verifying exfiltration_check in response
# 4. Cleaning up test data
#
# Prerequisites:
#   - Docker Compose running: docker-compose up -d
#   - Agent healthy: curl http://localhost:8080/health

set -e

AGENT_URL="${AXONFLOW_AGENT_URL:-http://localhost:8080}"
CONNECTOR="${MCP_CONNECTOR:-postgres}"

echo "=== Exfiltration Detection: Query Within Limits ==="
echo ""

# Step 1: Create test table with sample data using execute endpoint
echo "Step 1: Creating test data..."

# Create table
curl -s -X POST "${AGENT_URL}/mcp/tools/execute" \
  -H "Content-Type: application/json" \
  -d "{
    \"connector\": \"${CONNECTOR}\",
    \"operation\": \"ddl\",
    \"action\": \"CREATE\",
    \"statement\": \"CREATE TABLE IF NOT EXISTS exfiltration_test (id SERIAL PRIMARY KEY, name VARCHAR(100), email VARCHAR(100))\",
    \"user_token\": \"test-setup\"
  }" > /dev/null 2>&1 || true

# Insert test data
curl -s -X POST "${AGENT_URL}/mcp/tools/execute" \
  -H "Content-Type: application/json" \
  -d "{
    \"connector\": \"${CONNECTOR}\",
    \"operation\": \"insert\",
    \"action\": \"INSERT\",
    \"statement\": \"INSERT INTO exfiltration_test (name, email) SELECT 'User ' || i, 'user' || i || '@example.com' FROM generate_series(1, 100) AS i ON CONFLICT DO NOTHING\",
    \"user_token\": \"test-setup\"
  }" > /dev/null 2>&1 || true

echo "✓ Test data ready"
echo ""

# Step 2: Query within limits using query endpoint
echo "Step 2: Querying data (LIMIT 10, well within default 10,000 row limit)..."
echo ""

response=$(curl -s -X POST "${AGENT_URL}/mcp/resources/query" \
  -H "Content-Type: application/json" \
  -d "{
    \"connector\": \"${CONNECTOR}\",
    \"statement\": \"SELECT id, name, email FROM exfiltration_test LIMIT 10\",
    \"user_token\": \"analyst-user\"
  }")

echo "Response:"
echo "$response" | jq .

echo ""
echo "=== Exfiltration Check Analysis ==="

# Check if exfiltration_check is present
exfil_check=$(echo "$response" | jq '.policy_info.exfiltration_check // empty')

if [ -n "$exfil_check" ] && [ "$exfil_check" != "null" ]; then
    echo "✓ exfiltration_check present in response"
    echo ""
    echo "$exfil_check" | jq .

    within_limits=$(echo "$exfil_check" | jq -r '.within_limits // true')
    rows=$(echo "$exfil_check" | jq -r '.rows_returned // 0')
    row_limit=$(echo "$exfil_check" | jq -r '.row_limit // 0')

    echo ""
    if [ "$within_limits" = "true" ]; then
        echo "✓ Query within limits: $rows rows returned (limit: $row_limit)"
    else
        echo "✗ Unexpected: Query exceeded limits"
    fi
else
    echo "ℹ exfiltration_check not present (feature may not be enabled)"
    echo ""
    echo "  To enable exfiltration detection, rebuild with worktree-exfiltration branch"
    echo "  or wait for v3.2.0 release."
fi

# Step 3: Cleanup using execute endpoint
echo ""
echo "Step 3: Cleaning up test data..."
curl -s -X POST "${AGENT_URL}/mcp/tools/execute" \
  -H "Content-Type: application/json" \
  -d "{
    \"connector\": \"${CONNECTOR}\",
    \"operation\": \"ddl\",
    \"action\": \"DROP\",
    \"statement\": \"DROP TABLE IF EXISTS exfiltration_test\",
    \"user_token\": \"test-cleanup\"
  }" > /dev/null 2>&1 || true
echo "✓ Cleanup complete"

echo ""
echo "=== Test Complete ==="
