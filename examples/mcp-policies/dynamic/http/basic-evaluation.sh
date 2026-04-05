#!/bin/bash
# Dynamic Policy Evaluation Example: Basic Usage
#
# This example demonstrates dynamic policy evaluation by:
# 1. Creating a test dynamic policy
# 2. Running an MCP query to trigger evaluation
# 3. Verifying dynamic_policy_info in response
# 4. Cleaning up the test policy
#
# Prerequisites:
#   - Docker Compose running: docker-compose up -d
#   - MCP_DYNAMIC_POLICIES_ENABLED=true (check docker-compose.yml)

set -e

AGENT_URL="${AXONFLOW_AGENT_URL:-http://localhost:8080}"
CONNECTOR="${MCP_CONNECTOR:-postgres}"
TENANT_ID="${AXONFLOW_TENANT_ID:-community}"

echo "=== Dynamic Policy Evaluation Example ==="
echo ""

# Step 1: Create a test dynamic policy
echo "Step 1: Creating test dynamic policy..."

policy_response=$(curl -s -X POST "${AGENT_URL}/api/v1/dynamic-policies" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "test-mcp-policy",
    "description": "Test policy for MCP dynamic evaluation demo",
    "enabled": true,
    "type": "content",
    "category": "dynamic-test",
    "conditions": [
      {"field": "connector", "operator": "equals", "value": "postgres"}
    ],
    "actions": [
      {"type": "log", "config": {"message": "Test policy - logging query"}}
    ],
    "priority": 100
  }')

policy_id=$(echo "$policy_response" | jq -r '.policy.id // .id // .policy_id // empty')

if [ -n "$policy_id" ] && [ "$policy_id" != "null" ]; then
    echo "✓ Created policy: $policy_id"
else
    echo "ℹ Could not create policy (may already exist or API unavailable)"
    echo "  Response: $policy_response"
    policy_id=""
fi
echo ""

# Step 2: Create test data using execute endpoint (write operations)
echo "Step 2: Creating test data..."
curl -s -X POST "${AGENT_URL}/mcp/tools/execute" \
  -H "Content-Type: application/json" \
  -d "{
    \"connector\": \"${CONNECTOR}\",
    \"operation\": \"ddl\",
    \"action\": \"CREATE\",
    \"statement\": \"CREATE TABLE IF NOT EXISTS dynamic_policy_test (id SERIAL PRIMARY KEY, value VARCHAR(50))\",
    \"user_token\": \"test-setup\"
  }" > /dev/null 2>&1 || true

curl -s -X POST "${AGENT_URL}/mcp/tools/execute" \
  -H "Content-Type: application/json" \
  -d "{
    \"connector\": \"${CONNECTOR}\",
    \"operation\": \"insert\",
    \"action\": \"INSERT\",
    \"statement\": \"INSERT INTO dynamic_policy_test (value) VALUES ('test1'), ('test2'), ('test3') ON CONFLICT DO NOTHING\",
    \"user_token\": \"test-setup\"
  }" > /dev/null 2>&1 || true
echo "✓ Test data ready"
echo ""

# Step 3: Query with dynamic policy evaluation using query endpoint (read operations)
echo "Step 3: Querying with dynamic policy evaluation..."
echo ""

response=$(curl -s -X POST "${AGENT_URL}/mcp/resources/query" \
  -H "Content-Type: application/json" \
  -d "{
    \"connector\": \"${CONNECTOR}\",
    \"statement\": \"SELECT * FROM dynamic_policy_test LIMIT 5\",
    \"user_token\": \"analyst-user\"
  }")

echo "Response:"
echo "$response" | jq .

echo ""
echo "=== Dynamic Policy Info Analysis ==="

dynamic_info=$(echo "$response" | jq '.policy_info.dynamic_policy_info // empty')

if [ -n "$dynamic_info" ] && [ "$dynamic_info" != "null" ]; then
    echo "✓ dynamic_policy_info present in response"
    echo ""
    echo "$dynamic_info" | jq .

    orchestrator_reachable=$(echo "$dynamic_info" | jq -r '.orchestrator_reachable // false')
    policies_evaluated=$(echo "$dynamic_info" | jq -r '.policies_evaluated // 0')

    echo ""
    if [ "$orchestrator_reachable" = "true" ]; then
        echo "✓ Orchestrator is REACHABLE"
        echo "  Policies evaluated: $policies_evaluated"

        matched=$(echo "$dynamic_info" | jq '.matched_policies | length // 0')
        if [ "$matched" != "0" ] && [ "$matched" != "null" ]; then
            echo "  Policies matched: $matched"
            echo ""
            echo "Matched policies:"
            echo "$dynamic_info" | jq '.matched_policies'
        fi
    else
        echo "⚠ Orchestrator not reachable"
    fi
else
    echo "ℹ dynamic_policy_info not present"
    echo ""
    echo "  Ensure MCP_DYNAMIC_POLICIES_ENABLED=true in docker-compose.yml"
    echo "  and restart: docker-compose up -d --build"
fi

# Step 4: Cleanup
echo ""
echo "Step 4: Cleaning up..."

# Delete test policy
if [ -n "$policy_id" ]; then
    curl -s -X DELETE "${AGENT_URL}/api/v1/dynamic-policies/${policy_id}" \
      > /dev/null 2>&1 || true
    echo "✓ Deleted test policy"
fi

# Delete test table using execute endpoint
curl -s -X POST "${AGENT_URL}/mcp/tools/execute" \
  -H "Content-Type: application/json" \
  -d "{
    \"connector\": \"${CONNECTOR}\",
    \"operation\": \"ddl\",
    \"action\": \"DROP\",
    \"statement\": \"DROP TABLE IF EXISTS dynamic_policy_test\",
    \"user_token\": \"test-cleanup\"
  }" > /dev/null 2>&1 || true
echo "✓ Deleted test data"

echo ""
echo "=== Test Complete ==="
