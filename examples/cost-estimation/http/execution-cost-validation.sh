#!/bin/bash
# Execution Cost Validation - HTTP/cURL Example
#
# Validates that ACTUAL execution costs are non-zero after workflow execution.
# This tests the end-to-end cost pipeline:
#   recordStepSnapshot() -> ReplaySnapshotInput.CostUSD -> DB -> API -> UI
#
# The existing cost-estimation.sh tests pre-execution estimates only.
# This script verifies that post-execution costs are populated correctly.
#
# Usage:
#   docker compose up -d  # Start AxonFlow
#   cd examples/cost-estimation/http
#   ./execution-cost-validation.sh
#
# Environment:
#   AXONFLOW_AGENT_URL or AXONFLOW_ENDPOINT - Agent URL (default: http://localhost:8080)
#   AXONFLOW_AGENT_URL        - Agent URL (default: http://localhost:8080)
#   AXONFLOW_CLIENT_ID     - Client ID (default: demo-org)
#   AXONFLOW_CLIENT_SECRET - Client secret (optional for community mode)
#   AXONFLOW_USER_TOKEN    - JWT token for MAP operations (optional)

set -e

cleanup() {
    rm -f /tmp/axonflow_exec_cost_plan.json /tmp/axonflow_exec_cost_detail.json /tmp/axonflow_exec_cost_steps.json
}
trap cleanup EXIT

AGENT_URL="${AXONFLOW_AGENT_URL:-${AXONFLOW_ENDPOINT:-http://localhost:8080}}"
CLIENT_ID="${AXONFLOW_CLIENT_ID:-community}"
CLIENT_SECRET="${AXONFLOW_CLIENT_SECRET:-}"
USER_TOKEN="${AXONFLOW_USER_TOKEN:-$CLIENT_ID}"

echo "=============================================="
echo "Execution Cost Validation - HTTP/cURL Example"
echo "=============================================="
echo "Agent URL:        $AGENT_URL"
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
echo "   Response: $HEALTH_RESPONSE"

HEALTH_STATUS=$(echo "$HEALTH_RESPONSE" | jq -r '.status // empty' 2>/dev/null || echo "")
check_result "Health check returns status" "$([ -n "$HEALTH_STATUS" ] && echo true || echo false)"
echo ""

# ========================================
# 2. SUBMIT MAP PLAN
# ========================================
echo "2. Submit MAP plan via POST /api/request..."

PLAN_BODY=$(cat <<EOF
{
    "query": "Analyze the key benefits of cloud computing and provide a brief summary",
    "domain": "generic",
    "user_token": "$USER_TOKEN",
    "request_type": "multi-agent-plan"
}
EOF
)

PLAN_HTTP_CODE=$(curl -s -o /tmp/axonflow_exec_cost_plan.json -w "%{http_code}" \
    --max-time 30 \
    -X POST "${AGENT_URL}/api/request" \
    -H "Content-Type: application/json" \
    -H "Authorization: Basic $AUTH_B64" \
    -d "$PLAN_BODY" || echo "000")

PLAN_RESPONSE=$(cat /tmp/axonflow_exec_cost_plan.json 2>/dev/null || echo "{}")
echo "   HTTP Status: $PLAN_HTTP_CODE"

REQUEST_ID=$(echo "$PLAN_RESPONSE" | jq -r '.request_id // .id // empty' 2>/dev/null || echo "")
if [ -z "$REQUEST_ID" ]; then
    # Try plan_id for MAP plans
    REQUEST_ID=$(echo "$PLAN_RESPONSE" | jq -r '.plan_id // empty' 2>/dev/null || echo "")
fi

PLAN_OK="false"
if [ "$PLAN_HTTP_CODE" = "200" ] || [ "$PLAN_HTTP_CODE" = "201" ]; then
    PLAN_OK="true"
fi
check_result "Plan submitted successfully (HTTP $PLAN_HTTP_CODE)" "$PLAN_OK"
echo "   Request/Plan ID: ${REQUEST_ID:-none}"
echo ""

# ========================================
# 3. WAIT FOR EXECUTION TO COMPLETE
# ========================================
echo "3. Waiting for execution to complete (polling executions endpoint)..."

EXECUTION_ID=""
MAX_WAIT=60
WAITED=0
POLL_INTERVAL=5

while [ $WAITED -lt $MAX_WAIT ]; do
    EXEC_LIST=$(curl -s --max-time 10 "${AGENT_URL}/api/v1/executions?limit=5" 2>/dev/null || echo '{"executions":[]}')

    # Prefer matching our REQUEST_ID, fall back to any completed execution.
    # The executions API returns request_id as the primary identifier.
    if [ -n "$REQUEST_ID" ]; then
        EXECUTION_ID=$(echo "$EXEC_LIST" | jq -r --arg rid "$REQUEST_ID" \
            '[.executions[] | select(.status == "completed" and .request_id == $rid)] | first | .request_id // empty' 2>/dev/null)
    fi
    if [ -z "$EXECUTION_ID" ]; then
        EXECUTION_ID=$(echo "$EXEC_LIST" | jq -r \
            '[.executions[] | select(.status == "completed")] | first | .request_id // empty' 2>/dev/null)
    fi

    if [ -n "$EXECUTION_ID" ]; then
        echo "   Found completed execution: $EXECUTION_ID (after ${WAITED}s)"
        break
    fi

    echo "   Waiting... (${WAITED}s / ${MAX_WAIT}s)"
    sleep $POLL_INTERVAL
    WAITED=$((WAITED + POLL_INTERVAL))
done

check_result "Found completed execution within ${MAX_WAIT}s" "$([ -n "$EXECUTION_ID" ] && echo true || echo false)"
echo ""

if [ -z "$EXECUTION_ID" ]; then
    echo "No completed execution found. Cannot validate costs."
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

# ========================================
# 4. VALIDATE EXECUTION COST
# ========================================
echo "4. GET /api/v1/executions/${EXECUTION_ID} - Validate total cost..."

DETAIL_HTTP_CODE=$(curl -s -o /tmp/axonflow_exec_cost_detail.json -w "%{http_code}" \
    --max-time 15 \
    "${AGENT_URL}/api/v1/executions/${EXECUTION_ID}" || echo "000")

DETAIL_RESPONSE=$(cat /tmp/axonflow_exec_cost_detail.json 2>/dev/null || echo "{}")
echo "   HTTP Status: $DETAIL_HTTP_CODE"

check_result "Execution detail returns 200" "$([ "$DETAIL_HTTP_CODE" = "200" ] && echo true || echo false)"

# Detail response is {"summary": {...}, "steps": [...]}
TOTAL_COST=$(echo "$DETAIL_RESPONSE" | jq -r '.summary.total_cost_usd // .total_cost_usd // "0"' 2>/dev/null || echo "0")
TOTAL_TOKENS=$(echo "$DETAIL_RESPONSE" | jq -r '.summary.total_tokens // .total_tokens // "0"' 2>/dev/null || echo "0")

echo "   Total Cost USD: $TOTAL_COST"
echo "   Total Tokens:   $TOTAL_TOKENS"

COST_NONZERO=$(echo "$TOTAL_COST" | awk '{print ($1 > 0) ? "true" : "false"}')
check_result "total_cost_usd > 0 (got $TOTAL_COST)" "$COST_NONZERO"

TOKENS_NONZERO=$(echo "$TOTAL_TOKENS" | awk '{print ($1 > 0) ? "true" : "false"}')
check_result "total_tokens > 0 (got $TOTAL_TOKENS)" "$TOKENS_NONZERO"
echo ""

# ========================================
# 5. VALIDATE STEP-LEVEL COST
# ========================================
echo "5. GET /api/v1/executions/${EXECUTION_ID}/steps - Validate step costs..."

STEPS_HTTP_CODE=$(curl -s -o /tmp/axonflow_exec_cost_steps.json -w "%{http_code}" \
    --max-time 15 \
    "${AGENT_URL}/api/v1/executions/${EXECUTION_ID}/steps" || echo "000")

STEPS_RESPONSE=$(cat /tmp/axonflow_exec_cost_steps.json 2>/dev/null || echo "{}")
echo "   HTTP Status: $STEPS_HTTP_CODE"

check_result "Steps endpoint returns 200" "$([ "$STEPS_HTTP_CODE" = "200" ] && echo true || echo false)"

# Steps endpoint returns a JSON array directly
STEP_WITH_COST=$(echo "$STEPS_RESPONSE" | jq '[.[] | select(.cost_usd > 0)] | length' 2>/dev/null || echo "0")
TOTAL_STEPS=$(echo "$STEPS_RESPONSE" | jq 'length' 2>/dev/null || echo "0")

echo "   Total steps: $TOTAL_STEPS"
echo "   Steps with cost > 0: $STEP_WITH_COST"

check_result "At least one step has cost_usd > 0 ($STEP_WITH_COST of $TOTAL_STEPS)" "$([ "$STEP_WITH_COST" -gt 0 ] 2>/dev/null && echo true || echo false)"
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
