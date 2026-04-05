#!/bin/bash
# MAP Lifecycle - HTTP API Example
#
# This example validates the FULL MAP v1.0 lifecycle using raw HTTP calls:
#   1. Generate plan (default mode) - verify plan_id, steps, version
#   2. Get status (pending)
#   3. Update plan (change execution_mode, optimistic locking)
#   4. Get version history
#   5. Stale update (verify 409 conflict)
#   6. Execute plan - verify completed
#   7. Get status (completed)
#   8. Cancel completed plan - verify rejected
#   9. Generate + cancel + try execute cancelled plan
#  10. Generate with balanced mode - execute - verify completed
#
# Usage:
#   docker compose up -d
#   cd examples/map-lifecycle/http
#   ./map-lifecycle.sh

set -e

AGENT_URL="${AXONFLOW_AGENT_URL:-http://localhost:8080}"
CLIENT_ID="${AXONFLOW_CLIENT_ID:-community}"
CLIENT_SECRET="${AXONFLOW_CLIENT_SECRET:-}"
AUTH_B64=$(printf '%s:%s' "$CLIENT_ID" "$CLIENT_SECRET" | base64)
USER_TOKEN="${AXONFLOW_USER_TOKEN:-$CLIENT_ID}"

echo "=============================================="
echo "MAP Lifecycle - HTTP API Example"
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

extract_json() {
    local json="$1"
    local field="$2"
    echo "$json" | python3 -c "import sys,json; print(json.load(sys.stdin).get('$field', ''))" 2>/dev/null || echo ""
}

extract_nested() {
    local json="$1"
    local expr="$2"
    echo "$json" | python3 -c "import sys,json; r=json.load(sys.stdin); $expr" 2>/dev/null || echo ""
}

generate_plan() {
    local query="$1"
    local exec_mode="${2:-}"
    local context_json='"domain": "generic"'
    if [ -n "$exec_mode" ]; then
        context_json="$context_json, \"execution_mode\": \"$exec_mode\""
    fi

    curl -s -X POST "${AGENT_URL}/api/request" \
      -H "Content-Type: application/json" \
      -H "Authorization: Basic $AUTH_B64" \
      -d '{
        "query": "'"$query"'",
        "user_token": "'"$USER_TOKEN"'",
        "client_id": "'"$CLIENT_ID"'",
        "request_type": "multi-agent-plan",
        "context": {'"$context_json"'}
      }'
}

# ========================================
# 1. GENERATE PLAN (default mode)
# ========================================
echo "1. Generate Plan - Default mode..."
echo "----------------------------------------------"

RESPONSE=$(generate_plan "Create a plan to analyze user feedback and suggest improvements")

PLAN_ID=$(extract_nested "$RESPONSE" "
pid = r.get('plan_id', '')
if not pid:
    data = r.get('data', {})
    if isinstance(data, dict):
        pid = data.get('plan_id', '')
print(pid)
")

HAS_PLAN_ID=$([ -n "$PLAN_ID" ] && echo "true" || echo "false")
check_result "Plan generated with plan_id ($PLAN_ID)" "$HAS_PLAN_ID"

HAS_PREFIX=$(echo "$PLAN_ID" | grep -q "^plan_" && echo "true" || echo "false")
check_result "plan_id has correct prefix 'plan_'" "$HAS_PREFIX"

STEPS=$(extract_nested "$RESPONSE" "
steps = r.get('steps', r.get('data', {}).get('steps', []))
print(len(steps) if isinstance(steps, list) else 0)
")
HAS_STEPS=$([ "$STEPS" -gt 0 ] 2>/dev/null && echo "true" || echo "false")
check_result "Plan has steps ($STEPS)" "$HAS_STEPS"
echo ""

if [ -z "$PLAN_ID" ]; then
    echo "No plan ID returned. Cannot continue."
    echo "Results: $PASS passed, $FAIL failed"
    exit 1
fi

# ========================================
# 2. GET STATUS (pending)
# ========================================
echo "2. Get Plan Status - Should be pending..."
echo "----------------------------------------------"

RESPONSE=$(curl -s "${AGENT_URL}/api/v1/plan/${PLAN_ID}" \
  -H "Authorization: Basic $AUTH_B64" \
)

STATUS=$(extract_json "$RESPONSE" "status")
IS_PENDING=$([ "$STATUS" = "pending" ] || [ "$STATUS" = "created" ] || [ "$STATUS" = "generated" ] && echo "true" || echo "false")
check_result "Plan status is pending ($STATUS)" "$IS_PENDING"
echo ""

# ========================================
# 3. UPDATE PLAN (change execution_mode, optimistic locking)
# ========================================
echo "3. Update Plan - Change execution_mode to parallel (version 1 -> 2)..."
echo "----------------------------------------------"

RESPONSE=$(curl -s -X PUT "${AGENT_URL}/api/v1/plan/${PLAN_ID}" \
  -H "Content-Type: application/json" \
  -H "Authorization: Basic $AUTH_B64" \
  -d '{"version": 1, "execution_mode": "parallel"}')

echo "Response:"
echo "$RESPONSE" | python3 -m json.tool 2>/dev/null || echo "$RESPONSE"

UPDATE_VERSION=$(extract_json "$RESPONSE" "version")
IS_V2=$([ "$UPDATE_VERSION" = "2" ] && echo "true" || echo "false")
check_result "Updated plan version is 2 ($UPDATE_VERSION)" "$IS_V2"

UPDATE_STATUS=$(extract_json "$RESPONSE" "status")
check_result "Update response has status ($UPDATE_STATUS)" "$([ -n "$UPDATE_STATUS" ] && echo 'true' || echo 'false')"
echo ""

# ========================================
# 4. GET VERSION HISTORY
# ========================================
echo "4. Get Version History..."
echo "----------------------------------------------"

RESPONSE=$(curl -s "${AGENT_URL}/api/v1/plan/${PLAN_ID}/versions" \
  -H "Authorization: Basic $AUTH_B64" \
)

echo "Response:"
echo "$RESPONSE" | python3 -m json.tool 2>/dev/null | head -30 || echo "$RESPONSE"

VERSION_COUNT=$(extract_nested "$RESPONSE" "
versions = r.get('versions', [])
print(len(versions))
")
HAS_VERSIONS=$([ "$VERSION_COUNT" -ge 1 ] 2>/dev/null && echo "true" || echo "false")
check_result "Version history has at least 1 entry ($VERSION_COUNT)" "$HAS_VERSIONS"
echo ""

# ========================================
# 5. STALE UPDATE (verify 409 conflict)
# ========================================
echo "5. Stale Update - Send version 1 again (expect 409)..."
echo "----------------------------------------------"

HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X PUT "${AGENT_URL}/api/v1/plan/${PLAN_ID}" \
  -H "Content-Type: application/json" \
  -H "Authorization: Basic $AUTH_B64" \
  -d '{"version": 1, "execution_mode": "sequential"}')

IS_409=$([ "$HTTP_CODE" = "409" ] && echo "true" || echo "false")
check_result "Stale update returns 409 Conflict (got $HTTP_CODE)" "$IS_409"
echo ""

# ========================================
# 6. EXECUTE PLAN
# ========================================
echo "6. Execute Plan..."
echo "----------------------------------------------"

RESPONSE=$(curl -s -X POST "${AGENT_URL}/api/request" \
  -H "Content-Type: application/json" \
  -H "Authorization: Basic $AUTH_B64" \
  -d '{
    "query": "",
    "user_token": "'"$USER_TOKEN"'",
    "client_id": "'"$CLIENT_ID"'",
    "request_type": "execute-plan",
    "context": {"plan_id": "'"$PLAN_ID"'"}
  }')

EXEC_SUCCESS=$(extract_json "$RESPONSE" "success")
check_result "Plan executed successfully ($EXEC_SUCCESS)" "$([ "$EXEC_SUCCESS" = "True" ] || [ "$EXEC_SUCCESS" = "true" ] && echo 'true' || echo 'false')"
echo ""

# ========================================
# 7. GET STATUS (completed)
# ========================================
echo "7. Get Plan Status - Should be completed..."
echo "----------------------------------------------"

RESPONSE=$(curl -s "${AGENT_URL}/api/v1/plan/${PLAN_ID}" \
  -H "Authorization: Basic $AUTH_B64" \
)

FINAL_STATUS=$(extract_json "$RESPONSE" "status")
IS_DONE=$([ "$FINAL_STATUS" = "completed" ] || [ "$FINAL_STATUS" = "success" ] && echo "true" || echo "false")
check_result "Final status is completed ($FINAL_STATUS)" "$IS_DONE"
echo ""

# ========================================
# 8. CANCEL COMPLETED PLAN (expect rejection)
# ========================================
echo "8. Cancel Completed Plan - Should be rejected..."
echo "----------------------------------------------"

HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${AGENT_URL}/api/v1/plan/${PLAN_ID}/cancel" \
  -H "Content-Type: application/json" \
  -H "Authorization: Basic $AUTH_B64" \
  -d '{"reason": "Testing cancel on completed plan"}')

IS_REJECTED=$([ "$HTTP_CODE" = "400" ] || [ "$HTTP_CODE" = "409" ] || [ "$HTTP_CODE" = "422" ] && echo "true" || echo "false")
check_result "Cancel completed plan rejected ($HTTP_CODE)" "$IS_REJECTED"
echo ""

# ========================================
# 9. GENERATE + CANCEL + TRY EXECUTE
# ========================================
echo "9. Generate -> Cancel -> Try Execute..."
echo "----------------------------------------------"

RESPONSE=$(generate_plan "Create a simple greeting plan")
PLAN_ID_2=$(extract_nested "$RESPONSE" "
pid = r.get('plan_id', '')
if not pid:
    data = r.get('data', {})
    if isinstance(data, dict):
        pid = data.get('plan_id', '')
print(pid)
")
check_result "Second plan generated ($PLAN_ID_2)" "$([ -n "$PLAN_ID_2" ] && echo 'true' || echo 'false')"

# Cancel it
RESPONSE=$(curl -s -X POST "${AGENT_URL}/api/v1/plan/${PLAN_ID_2}/cancel" \
  -H "Content-Type: application/json" \
  -H "Authorization: Basic $AUTH_B64" \
  -d '{"reason": "Testing cancel flow"}')

CANCEL_STATUS=$(extract_json "$RESPONSE" "status")
check_result "Plan cancelled ($CANCEL_STATUS)" "$([ "$CANCEL_STATUS" = "cancelled" ] && echo 'true' || echo 'false')"

# Try to execute cancelled plan
RESPONSE=$(curl -s -X POST "${AGENT_URL}/api/request" \
  -H "Content-Type: application/json" \
  -H "Authorization: Basic $AUTH_B64" \
  -d '{
    "query": "",
    "user_token": "'"$USER_TOKEN"'",
    "client_id": "'"$CLIENT_ID"'",
    "request_type": "execute-plan",
    "context": {"plan_id": "'"$PLAN_ID_2"'"}
  }')

DATA_SUCCESS_2=$(extract_nested "$RESPONSE" "print(r.get('data', {}).get('success', True))")
DATA_ERROR_2=$(extract_nested "$RESPONSE" "print(r.get('data', {}).get('error', ''))")
EXEC_REJECTED=$([ "$DATA_SUCCESS_2" = "False" ] || [ "$DATA_SUCCESS_2" = "false" ] || [ -n "$DATA_ERROR_2" ] && echo "true" || echo "false")
check_result "Execute cancelled plan rejected" "$EXEC_REJECTED"
echo ""

# ========================================
# 10. GENERATE WITH BALANCED MODE + EXECUTE
# ========================================
echo "10. Generate with balanced mode -> Execute..."
echo "----------------------------------------------"

RESPONSE=$(generate_plan "Create a plan to process and summarize data" "balanced")
PLAN_ID_3=$(extract_nested "$RESPONSE" "
pid = r.get('plan_id', '')
if not pid:
    data = r.get('data', {})
    if isinstance(data, dict):
        pid = data.get('plan_id', '')
print(pid)
")
check_result "Balanced mode plan generated ($PLAN_ID_3)" "$([ -n "$PLAN_ID_3" ] && echo 'true' || echo 'false')"

# Execute balanced plan
RESPONSE=$(curl -s -X POST "${AGENT_URL}/api/request" \
  -H "Content-Type: application/json" \
  -H "Authorization: Basic $AUTH_B64" \
  -d '{
    "query": "",
    "user_token": "'"$USER_TOKEN"'",
    "client_id": "'"$CLIENT_ID"'",
    "request_type": "execute-plan",
    "context": {"plan_id": "'"$PLAN_ID_3"'"}
  }')

BALANCED_SUCCESS=$(extract_json "$RESPONSE" "success")
check_result "Balanced mode plan executed ($BALANCED_SUCCESS)" "$([ "$BALANCED_SUCCESS" = "True" ] || [ "$BALANCED_SUCCESS" = "true" ] && echo 'true' || echo 'false')"
echo ""

# ========================================
# SUMMARY
# ========================================
echo "=============================================="
echo "Results: $PASS passed, $FAIL failed"
if [ "$FAIL" -gt 0 ]; then
    echo "SOME TESTS FAILED"
    exit 1
fi
echo "ALL TESTS PASSED"
echo "=============================================="
echo ""
echo "API Summary:"
echo "  POST /api/request (request_type=multi-agent-plan)    - Generate a plan"
echo "  GET  /api/v1/plan/{id}                                - Get plan status"
echo "  PUT  /api/v1/plan/{id}                                - Update plan (versioning)"
echo "  GET  /api/v1/plan/{id}/versions                       - Get version history"
echo "  POST /api/v1/plan/{id}/cancel                         - Cancel a plan"
echo "  POST /api/request (request_type=execute-plan)         - Execute a plan"
