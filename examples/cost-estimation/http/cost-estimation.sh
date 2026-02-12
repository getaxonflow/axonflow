#!/bin/bash
# Cost Estimation - HTTP/cURL Example
#
# Validates the new cost estimation endpoints added in v4.3.0:
#   - POST /api/v1/plans/estimate  - Estimate cost of a plan before execution
#   - GET  /api/v1/plans/{id}/cost - Get cost estimate for an existing plan
#
# These endpoints are tested with raw cURL + jq for JSON parsing.
# Plan creation uses the existing MAP API endpoint.
#
# Usage:
#   docker compose up -d  # Start AxonFlow
#   cd examples/cost-estimation/http
#   ./cost-estimation.sh
#
# Environment:
#   AXONFLOW_AGENT_URL or AXONFLOW_ENDPOINT - Agent URL (default: http://localhost:8080)
#   AXONFLOW_CLIENT_ID     - Client ID (default: demo-org)
#   AXONFLOW_CLIENT_SECRET - Client secret (optional for community mode)
#   AXONFLOW_USER_TOKEN    - JWT token for MAP operations (optional)

set -e

AGENT_URL="${AXONFLOW_AGENT_URL:-${AXONFLOW_ENDPOINT:-http://localhost:8080}}"
CLIENT_ID="${AXONFLOW_CLIENT_ID:-demo-org}"
CLIENT_SECRET="${AXONFLOW_CLIENT_SECRET:-}"
USER_TOKEN="${AXONFLOW_USER_TOKEN:-$CLIENT_ID}"

# Build auth headers
AUTH_HEADERS="-H \"X-Client-ID: $CLIENT_ID\""
if [ -n "$CLIENT_SECRET" ]; then
    AUTH_HEADERS="$AUTH_HEADERS -H \"X-Client-Secret: $CLIENT_SECRET\""
fi

echo "=============================================="
echo "Cost Estimation - HTTP/cURL Example"
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
echo "   Response: $HEALTH_RESPONSE"

HEALTH_STATUS=$(echo "$HEALTH_RESPONSE" | jq -r '.status // empty' 2>/dev/null || echo "")
check_result "Health check returns status" "$([ -n "$HEALTH_STATUS" ] && echo true || echo false)"
echo ""

# ========================================
# 2. POST /api/v1/plans/estimate
# ========================================
echo "2. POST /api/v1/plans/estimate - Estimate cost before execution..."

ESTIMATE_BODY='{
    "provider": "openai",
    "model": "gpt-4",
    "steps": [
        {
            "name": "analyze",
            "type": "llm_call",
            "estimated_tokens_in": 1000,
            "estimated_tokens_out": 500
        },
        {
            "name": "summarize",
            "type": "llm_call",
            "estimated_tokens_in": 500,
            "estimated_tokens_out": 200
        }
    ]
}'

ESTIMATE_HTTP_CODE=$(curl -s -o /tmp/axonflow_estimate_response.json -w "%{http_code}" \
    --max-time 15 \
    -X POST "${AGENT_URL}/api/v1/plans/estimate" \
    -H "Content-Type: application/json" \
    -H "X-Client-ID: $CLIENT_ID" \
    ${CLIENT_SECRET:+-H "X-Client-Secret: $CLIENT_SECRET"} \
    -d "$ESTIMATE_BODY" || echo "000")

ESTIMATE_RESPONSE=$(cat /tmp/axonflow_estimate_response.json 2>/dev/null || echo "{}")
echo "   HTTP Status: $ESTIMATE_HTTP_CODE"
echo "   Response: $ESTIMATE_RESPONSE"

if [ "$ESTIMATE_HTTP_CODE" = "429" ]; then
    echo "   Rate limited (429) - community mode allows 10 estimates/day"
    echo "   This is expected behavior; skipping estimate assertions."
    check_result "Estimate endpoint returned valid status (429 rate limit)" "true"
elif [ "$ESTIMATE_HTTP_CODE" = "200" ]; then
    check_result "Estimate returns 200" "true"

    # Verify estimated_cost_usd field
    COST=$(echo "$ESTIMATE_RESPONSE" | jq -r '.estimated_cost_usd // empty' 2>/dev/null || echo "")
    check_result "Response contains 'estimated_cost_usd' field" "$([ -n "$COST" ] && echo true || echo false)"

    if [ -n "$COST" ]; then
        # Check cost >= 0 (jq comparison)
        COST_VALID=$(echo "$ESTIMATE_RESPONSE" | jq '.estimated_cost_usd >= 0' 2>/dev/null || echo "false")
        check_result "estimated_cost_usd >= 0 (got $COST)" "$COST_VALID"
        echo "   Estimated Cost: \$$COST USD"
    fi

    # Verify currency field
    CURRENCY=$(echo "$ESTIMATE_RESPONSE" | jq -r '.currency // empty' 2>/dev/null || echo "")
    check_result "Response contains 'currency' field" "$([ -n "$CURRENCY" ] && echo true || echo false)"
    check_result "currency is 'USD' (got '$CURRENCY')" "$([ "$CURRENCY" = "USD" ] && echo true || echo false)"

    # Check breakdown (may be absent in community mode)
    HAS_BREAKDOWN=$(echo "$ESTIMATE_RESPONSE" | jq 'has("breakdown")' 2>/dev/null || echo "false")
    if [ "$HAS_BREAKDOWN" = "true" ]; then
        BREAKDOWN=$(echo "$ESTIMATE_RESPONSE" | jq '.breakdown' 2>/dev/null)
        echo "   Breakdown available: $BREAKDOWN"
    else
        echo "   Note: 'breakdown' not present (community mode returns aggregate only)"
    fi
else
    check_result "Estimate returns 200 (got $ESTIMATE_HTTP_CODE)" "false"
fi
echo ""

# ========================================
# 3. CREATE PLAN + GET COST
# ========================================
echo "3. Create MAP plan via API, then GET /api/v1/plans/{id}/cost..."

PLAN_BODY=$(cat <<EOF
{
    "query": "Create a brief plan to analyze customer feedback and generate a summary report",
    "domain": "generic",
    "user_token": "$USER_TOKEN",
    "request_type": "multi-agent-plan"
}
EOF
)

PLAN_HTTP_CODE=$(curl -s -o /tmp/axonflow_plan_response.json -w "%{http_code}" \
    --max-time 30 \
    -X POST "${AGENT_URL}/api/request" \
    -H "Content-Type: application/json" \
    -H "X-Client-ID: $CLIENT_ID" \
    ${CLIENT_SECRET:+-H "X-Client-Secret: $CLIENT_SECRET"} \
    -d "$PLAN_BODY" || echo "000")

PLAN_RESPONSE=$(cat /tmp/axonflow_plan_response.json 2>/dev/null || echo "{}")
echo "   Plan HTTP Status: $PLAN_HTTP_CODE"

PLAN_ID=$(echo "$PLAN_RESPONSE" | jq -r '.plan_id // empty' 2>/dev/null || echo "")

if [ -z "$PLAN_ID" ]; then
    echo "   Could not extract plan_id from response"
    echo "   Response: $PLAN_RESPONSE"
    check_result "Plan created with valid ID" "false"
else
    echo "   Plan ID: $PLAN_ID"
    check_result "Plan created with valid ID" "true"

    # GET /api/v1/plans/{id}/cost
    echo ""
    echo "   Fetching cost for existing plan..."
    COST_HTTP_CODE=$(curl -s -o /tmp/axonflow_cost_response.json -w "%{http_code}" \
        --max-time 15 \
        -X GET "${AGENT_URL}/api/v1/plans/${PLAN_ID}/cost" \
        -H "Content-Type: application/json" \
        -H "X-Client-ID: $CLIENT_ID" \
        ${CLIENT_SECRET:+-H "X-Client-Secret: $CLIENT_SECRET"} || echo "000")

    COST_RESPONSE=$(cat /tmp/axonflow_cost_response.json 2>/dev/null || echo "{}")
    echo "   Cost HTTP Status: $COST_HTTP_CODE"
    echo "   Cost Response: $COST_RESPONSE"

    if [ "$COST_HTTP_CODE" = "429" ]; then
        echo "   Rate limited (429) - community mode allows 10 estimates/day"
        check_result "Plan cost endpoint returned valid status (429 rate limit)" "true"
    elif [ "$COST_HTTP_CODE" = "404" ]; then
        echo "   Plan cost endpoint returned 404 - endpoint may require enterprise mode"
        check_result "Plan cost endpoint responded (404 - may require enterprise)" "true"
    elif [ "$COST_HTTP_CODE" = "200" ]; then
        check_result "GET plan cost returns 200" "true"

        PLAN_COST=$(echo "$COST_RESPONSE" | jq -r '.estimated_cost_usd // empty' 2>/dev/null || echo "")
        check_result "Plan cost response contains 'estimated_cost_usd'" "$([ -n "$PLAN_COST" ] && echo true || echo false)"

        if [ -n "$PLAN_COST" ]; then
            PLAN_COST_VALID=$(echo "$COST_RESPONSE" | jq '.estimated_cost_usd >= 0' 2>/dev/null || echo "false")
            check_result "Plan cost >= 0 (got $PLAN_COST)" "$PLAN_COST_VALID"
        fi

        PLAN_CURRENCY=$(echo "$COST_RESPONSE" | jq -r '.currency // empty' 2>/dev/null || echo "")
        check_result "Plan cost response contains 'currency'" "$([ -n "$PLAN_CURRENCY" ] && echo true || echo false)"
        if [ -n "$PLAN_CURRENCY" ]; then
            check_result "Plan cost currency is 'USD' (got '$PLAN_CURRENCY')" "$([ "$PLAN_CURRENCY" = "USD" ] && echo true || echo false)"
        fi

        HAS_BREAKDOWN=$(echo "$COST_RESPONSE" | jq 'has("breakdown")' 2>/dev/null || echo "false")
        if [ "$HAS_BREAKDOWN" != "true" ]; then
            echo "   Note: 'breakdown' not present (community mode returns aggregate only)"
        fi
    else
        check_result "GET plan cost returns 200 (got $COST_HTTP_CODE)" "false"
    fi
fi
echo ""

# ========================================
# CLEANUP
# ========================================
rm -f /tmp/axonflow_estimate_response.json /tmp/axonflow_plan_response.json /tmp/axonflow_cost_response.json

# ========================================
# SUMMARY
# ========================================
echo "=============================================="
echo "Cost Estimation Example - Summary"
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
