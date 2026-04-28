#!/bin/bash
# Execution Cost Validation - HTTP/cURL Example
#
# Validates that a MAP plan can be generated AND executed end-to-end, and that
# the cost-estimation endpoint returns a non-zero figure for the stored plan.
#
# What this script proves:
#   1. POST /api/request (request_type=multi-agent-plan) generates and stores a plan
#   2. POST /api/request (request_type=execute-plan) executes the stored plan
#      and returns substantive LLM output
#   3. GET /api/v1/plans/{id}/cost returns a non-zero estimated cost
#
# Why two scripts in this directory:
#   - cost-estimation.sh covers the cost-estimation API surface (estimate + plan/cost)
#     in isolation, without execution.
#   - execution-cost-validation.sh additionally exercises the *execute* path so a
#     regression in plan storage / execute routing surfaces here even if estimate
#     still works.
#
# Usage:
#   docker compose up -d  # Start AxonFlow
#   cd examples/cost-estimation/http
#   ./execution-cost-validation.sh
#
# Environment:
#   AXONFLOW_AGENT_URL or AXONFLOW_ENDPOINT - Agent URL (default: http://localhost:8080)
#   AXONFLOW_CLIENT_ID     - Client ID (default: community)
#   AXONFLOW_CLIENT_SECRET - Client secret (default: empty for community mode)
#   AXONFLOW_USER_TOKEN    - User token for plan ops (default: $CLIENT_ID)

set -e

cleanup() {
    rm -f /tmp/axonflow_exec_cost_plan.json /tmp/axonflow_exec_cost_execute.json /tmp/axonflow_exec_cost_cost.json
}
trap cleanup EXIT

AGENT_URL="${AXONFLOW_AGENT_URL:-${AXONFLOW_ENDPOINT:-http://localhost:8080}}"
CLIENT_ID="${AXONFLOW_CLIENT_ID:-community}"
CLIENT_SECRET="${AXONFLOW_CLIENT_SECRET:-}"
AUTH_B64=$(printf '%s:%s' "$CLIENT_ID" "$CLIENT_SECRET" | base64)
USER_TOKEN="${AXONFLOW_USER_TOKEN:-$CLIENT_ID}"

echo "=============================================="
echo "Execution Cost Validation - HTTP/cURL Example"
echo "=============================================="
echo "Agent URL: $AGENT_URL"
echo ""

PASS=0
FAIL=0

check_result() {
    local test_name="$1"
    local condition="$2"
    if [ "$condition" = "true" ]; then
        echo "   PASS: $test_name"
        PASS=$((PASS + 1))
    else
        echo "   FAIL: $test_name"
        FAIL=$((FAIL + 1))
    fi
}

# ========================================
# 1. HEALTH CHECK
# ========================================
echo "1. Health Check..."
HEALTH_RESPONSE=$(curl -s --max-time 15 "${AGENT_URL}/health" || echo '{"error":"connection failed"}')
HEALTH_STATUS=$(echo "$HEALTH_RESPONSE" | jq -r '.status // empty' 2>/dev/null || echo "")
check_result "Health check returns status (got '$HEALTH_STATUS')" "$([ -n "$HEALTH_STATUS" ] && echo true || echo false)"
echo ""

# ========================================
# 2. GENERATE MAP PLAN
# ========================================
echo "2. Generate MAP plan via POST /api/request (request_type=multi-agent-plan)..."

GENERATE_BODY=$(cat <<EOF
{
    "query": "Brief 3-step plan to summarize a technical document",
    "domain": "generic",
    "user_token": "$USER_TOKEN",
    "client_id": "$CLIENT_ID",
    "request_type": "multi-agent-plan"
}
EOF
)

GEN_HTTP_CODE=$(curl -s -o /tmp/axonflow_exec_cost_plan.json -w "%{http_code}" \
    --max-time 30 \
    -X POST "${AGENT_URL}/api/request" \
    -H "Content-Type: application/json" \
    -H "Authorization: Basic $AUTH_B64" \
    -d "$GENERATE_BODY" || echo "000")

GEN_RESPONSE=$(cat /tmp/axonflow_exec_cost_plan.json 2>/dev/null || echo "{}")
echo "   HTTP Status: $GEN_HTTP_CODE"

PLAN_ID=$(echo "$GEN_RESPONSE" | jq -r '.plan_id // empty' 2>/dev/null || echo "")
check_result "Plan generated (HTTP $GEN_HTTP_CODE)" "$([ "$GEN_HTTP_CODE" = "200" ] && echo true || echo false)"
check_result "Plan ID is present" "$([ -n "$PLAN_ID" ] && echo true || echo false)"
echo "   Plan ID: ${PLAN_ID:-<none>}"

if [ -z "$PLAN_ID" ]; then
    echo ""
    echo "   Cannot continue without a plan_id."
    echo "   Generate response: $GEN_RESPONSE"
    echo ""
    echo "=============================================="
    echo "Execution Cost Validation - Summary"
    echo "=============================================="
    echo "Passed: $PASS"
    echo "Failed: $FAIL"
    echo ""
    echo "$FAIL assertion(s) FAILED"
    exit 1
fi
echo ""

# ========================================
# 3. EXECUTE THE STORED PLAN
# ========================================
echo "3. Execute the stored plan via POST /api/request (request_type=execute-plan)..."

EXEC_BODY=$(cat <<EOF
{
    "query": "",
    "client_id": "$CLIENT_ID",
    "user_token": "$USER_TOKEN",
    "request_type": "execute-plan",
    "context": {"plan_id": "$PLAN_ID"}
}
EOF
)

EXEC_HTTP_CODE=$(curl -s -o /tmp/axonflow_exec_cost_execute.json -w "%{http_code}" \
    --max-time 120 \
    -X POST "${AGENT_URL}/api/request" \
    -H "Content-Type: application/json" \
    -H "Authorization: Basic $AUTH_B64" \
    -d "$EXEC_BODY" || echo "000")

EXEC_RESPONSE=$(cat /tmp/axonflow_exec_cost_execute.json 2>/dev/null || echo "{}")
echo "   HTTP Status: $EXEC_HTTP_CODE"

EXEC_SUCCESS=$(echo "$EXEC_RESPONSE" | jq -r '.success // false' 2>/dev/null || echo "false")
RESULT_LEN=$(echo "$EXEC_RESPONSE" | jq -r '.result // "" | length' 2>/dev/null || echo "0")

check_result "Execute returns 200 (got $EXEC_HTTP_CODE)" "$([ "$EXEC_HTTP_CODE" = "200" ] && echo true || echo false)"
check_result "Execute success=true" "$([ "$EXEC_SUCCESS" = "true" ] && echo true || echo false)"
check_result "Result has substantive content (>100 chars, got $RESULT_LEN)" "$([ "$RESULT_LEN" -gt 100 ] 2>/dev/null && echo true || echo false)"
echo ""

# ========================================
# 4. VALIDATE COST FOR THE PLAN
# ========================================
echo "4. GET /api/v1/plans/${PLAN_ID}/cost - Validate cost is non-zero..."

COST_HTTP_CODE=$(curl -s -o /tmp/axonflow_exec_cost_cost.json -w "%{http_code}" \
    --max-time 15 \
    -H "Authorization: Basic $AUTH_B64" \
    "${AGENT_URL}/api/v1/plans/${PLAN_ID}/cost" || echo "000")

COST_RESPONSE=$(cat /tmp/axonflow_exec_cost_cost.json 2>/dev/null || echo "{}")
echo "   HTTP Status: $COST_HTTP_CODE"

ESTIMATED_COST=$(echo "$COST_RESPONSE" | jq -r '.estimated_cost_usd // 0' 2>/dev/null || echo "0")
echo "   Estimated Cost USD: $ESTIMATED_COST"

check_result "Cost endpoint returns 200" "$([ "$COST_HTTP_CODE" = "200" ] && echo true || echo false)"
COST_NONZERO=$(echo "$ESTIMATED_COST" | awk '{print ($1 > 0) ? "true" : "false"}')
check_result "estimated_cost_usd > 0 (got $ESTIMATED_COST)" "$COST_NONZERO"
echo ""

# ========================================
# SUMMARY
# ========================================
echo "=============================================="
echo "Execution Cost Validation - Summary"
echo "=============================================="
echo "Passed: $PASS"
echo "Failed: $FAIL"
echo ""

if [ "$FAIL" -gt 0 ]; then
    echo "$FAIL assertion(s) FAILED"
    exit 1
else
    echo "All assertions passed!"
    exit 0
fi
