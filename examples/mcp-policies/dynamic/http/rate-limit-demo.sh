#!/bin/bash
# Dynamic Policy Evaluation Example: Rate Limiting
#
# This example demonstrates rate limiting through dynamic policies by:
# 1. Creating a rate limit policy (3 requests per minute)
# 2. Sending requests to trigger the limit
# 3. Verifying rate limit blocking
# 4. Cleaning up the test policy
#
# Prerequisites:
#   - Docker Compose running: docker-compose up -d
#   - MCP_DYNAMIC_POLICIES_ENABLED=true

set -e

AGENT_URL="${AXONFLOW_AGENT_URL:-http://localhost:8080}"
# user_token: validated as JWT in eval/enterprise; any string in community.
# Read from AXONFLOW_USER_TOKEN env (setup-e2e-testing.sh writes it).
USER_TOKEN="${AXONFLOW_USER_TOKEN:-demo-user}"
CONNECTOR="${MCP_CONNECTOR:-postgres}"
TENANT_ID="${AXONFLOW_TENANT_ID:-community}"
REQUEST_COUNT="${1:-5}"

# Auth: include Basic auth if credentials are set
CURL_AUTH=()
if [ -n "${AXONFLOW_CLIENT_ID:-}" ] && [ -n "${AXONFLOW_CLIENT_SECRET:-}" ]; then
  CURL_AUTH=(-u "${AXONFLOW_CLIENT_ID}:${AXONFLOW_CLIENT_SECRET}")
fi
acurl() { curl "${CURL_AUTH[@]}" "$@"; }

echo "=== Dynamic Policy: Rate Limit Demo ==="
echo ""

# Step 1: Create rate limit policy
echo "Step 1: Creating rate limit policy (3 requests/minute)..."

policy_response=$(acurl -s -X POST "${AGENT_URL}/api/v1/dynamic-policies" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "test-rate-limit",
    "description": "Test rate limit - 3 requests per minute",
    "enabled": true,
    "type": "user",
    "category": "dynamic-rate-limit",
    "conditions": [
      {"field": "connector", "operator": "equals", "value": "postgres"},
      {"field": "user.id", "operator": "equals", "value": "rate-test-user"}
    ],
    "actions": [
      {"type": "block", "config": {"reason": "Rate limit exceeded: 3 requests per minute"}}
    ],
    "priority": 50
  }')

policy_id=$(echo "$policy_response" | jq -r '.policy.id // .id // .policy_id // empty')

if [ -n "$policy_id" ] && [ "$policy_id" != "null" ]; then
    echo "✓ Created rate limit policy: $policy_id"
else
    echo "ℹ Could not create policy (may already exist or API unavailable)"
    echo "  Response: $policy_response"
    policy_id=""
fi
echo ""

# Step 2: Send rapid requests
echo "Step 2: Sending $REQUEST_COUNT rapid requests..."
echo ""

blocked_count=0
success_count=0

for i in $(seq 1 $REQUEST_COUNT); do
    response=$(acurl -s -w "\n%{http_code}" -X POST "${AGENT_URL}/mcp/resources/query" \
      -H "Content-Type: application/json" \
      -d "{
        \"connector\": \"${CONNECTOR}\",
        \"statement\": \"SELECT 1 as test\",
        \"user_token\": \"${USER_TOKEN}\"
      }")

    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | sed '$d')

    if [ "$http_code" = "429" ] || [ "$http_code" = "403" ]; then
        blocked_count=$((blocked_count + 1))
        echo "Request $i: BLOCKED (HTTP $http_code)"

        # Show block reason on first block
        if [ "$blocked_count" = "1" ]; then
            echo ""
            echo "  Block reason: $(echo "$body" | jq -r '.block_reason // .error // "Unknown"')"
            echo ""
        fi
    else
        success_count=$((success_count + 1))
        echo "Request $i: SUCCESS (HTTP $http_code)"
    fi
done

echo ""
echo "=== Results ==="
echo "Successful requests: $success_count"
echo "Blocked requests: $blocked_count"

if [ "$blocked_count" -gt 0 ]; then
    echo ""
    echo "✓ Rate limiting is working!"
else
    echo ""
    echo "ℹ No requests were blocked."
    echo ""
    echo "  Possible reasons:"
    echo "  - MCP_DYNAMIC_POLICIES_ENABLED=false (check docker-compose.yml)"
    echo "  - Rate limit policy not created successfully"
    echo "  - Rate limit window has different implementation"
    echo ""
    echo "  Check Orchestrator logs: docker logs axonflow-orchestrator"
fi

# Step 3: Cleanup
echo ""
echo "Step 3: Cleaning up..."

if [ -n "$policy_id" ]; then
    acurl -s -X DELETE "${AGENT_URL}/api/v1/dynamic-policies/${policy_id}" \
      > /dev/null 2>&1 || true
    echo "✓ Deleted rate limit policy"
else
    # Try to delete by name
    acurl -s -X DELETE "${AGENT_URL}/api/v1/dynamic-policies/test-rate-limit" \
      > /dev/null 2>&1 || true
fi

echo ""
echo "=== Test Complete ==="
