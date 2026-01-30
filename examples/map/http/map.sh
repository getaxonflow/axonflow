#!/bin/bash
# MAP (Multi-Agent Planning) - HTTP API Example
#
# This example demonstrates all MAP API endpoints using raw HTTP calls.
# No SDK required - uses cURL to interact with the Agent API directly.
#
# Usage:
#   docker compose up -d  # Start AxonFlow
#   cd examples/map/http
#   ./map.sh
#
# What this demonstrates:
#   1. Generate a multi-agent plan (POST /api/request with request_type=multi-agent-plan)
#   2. Get plan status (GET /api/v1/plan/{id})
#   3. Execute the plan (POST /api/request with request_type=execute-plan)
#   4. Get plan status after execution

set -e

AGENT_URL="${AXONFLOW_AGENT_URL:-http://localhost:8080}"
CLIENT_ID="${AXONFLOW_CLIENT_ID:-map-http-example}"
CLIENT_SECRET="${AXONFLOW_CLIENT_SECRET:-}"

echo "=============================================="
echo "MAP (Multi-Agent Planning) - HTTP API Example"
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

# 1. Generate Plan
echo "1. GeneratePlan - Creating a multi-agent plan..."
echo "----------------------------------------------"

RESPONSE=$(curl -s -X POST "${AGENT_URL}/api/request" \
  -H "Content-Type: application/json" \
  -H "X-Client-ID: $CLIENT_ID" \
  -H "X-Client-Secret: $CLIENT_SECRET" \
  -d '{
    "query": "Create a brief plan to greet a new user and ask how to help them",
    "user_token": "'"$CLIENT_ID"'",
    "client_id": "'"$CLIENT_ID"'",
    "request_type": "multi-agent-plan",
    "context": {
      "domain": "generic"
    }
  }')

echo "Response (truncated):"
echo "$RESPONSE" | python3 -m json.tool 2>/dev/null | head -30 || echo "$RESPONSE"
echo ""

SUCCESS=$(echo "$RESPONSE" | python3 -c "import sys,json; print('true' if json.load(sys.stdin).get('success', False) else 'false')" 2>/dev/null || echo "false")
check_result "GeneratePlan request succeeded" "$SUCCESS"

PLAN_ID=$(echo "$RESPONSE" | python3 -c "
import sys, json
r = json.load(sys.stdin)
pid = r.get('plan_id', '')
if not pid:
    data = r.get('data', {})
    if isinstance(data, dict):
        pid = data.get('plan_id', '')
print(pid)
" 2>/dev/null || echo "")

HAS_PLAN_ID=$([ -n "$PLAN_ID" ] && echo "true" || echo "false")
check_result "GeneratePlan returned plan_id ($PLAN_ID)" "$HAS_PLAN_ID"
echo ""

if [ -z "$PLAN_ID" ]; then
    echo "No plan ID returned. Cannot continue with execute/status tests."
    echo "=============================================="
    echo "Results: $PASS passed, $FAIL failed"
    if [ "$FAIL" -gt 0 ]; then
        exit 1
    fi
    exit 0
fi

# 2. Get Plan Status (before execution)
echo "2. GetPlanStatus - Checking status before execution..."
echo "----------------------------------------------"

RESPONSE=$(curl -s "${AGENT_URL}/api/v1/plan/${PLAN_ID}" \
  -H "X-Client-ID: $CLIENT_ID" \
  -H "X-Client-Secret: $CLIENT_SECRET")

echo "Response:"
echo "$RESPONSE" | python3 -m json.tool 2>/dev/null || echo "$RESPONSE"
echo ""

STATUS=$(echo "$RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status', ''))" 2>/dev/null || echo "")
IS_PENDING=$([ "$STATUS" = "pending" ] || [ "$STATUS" = "created" ] || [ "$STATUS" = "generated" ] && echo "true" || echo "false")
check_result "Plan status before execution ($STATUS)" "$IS_PENDING"
echo ""

# 3. Execute Plan
echo "3. ExecutePlan - Executing the plan..."
echo "----------------------------------------------"

RESPONSE=$(curl -s -X POST "${AGENT_URL}/api/request" \
  -H "Content-Type: application/json" \
  -H "X-Client-ID: $CLIENT_ID" \
  -H "X-Client-Secret: $CLIENT_SECRET" \
  -d '{
    "query": "",
    "user_token": "'"$CLIENT_ID"'",
    "client_id": "'"$CLIENT_ID"'",
    "request_type": "execute-plan",
    "context": {
      "plan_id": "'"$PLAN_ID"'"
    }
  }')

echo "Response (truncated):"
echo "$RESPONSE" | python3 -m json.tool 2>/dev/null | head -30 || echo "$RESPONSE"
echo ""

EXEC_SUCCESS=$(echo "$RESPONSE" | python3 -c "import sys,json; print('true' if json.load(sys.stdin).get('success', False) else 'false')" 2>/dev/null || echo "false")
check_result "ExecutePlan request succeeded" "$EXEC_SUCCESS"
echo ""

# 4. Get Plan Status (after execution)
echo "4. GetPlanStatus - Checking status after execution..."
echo "----------------------------------------------"

RESPONSE=$(curl -s "${AGENT_URL}/api/v1/plan/${PLAN_ID}" \
  -H "X-Client-ID: $CLIENT_ID" \
  -H "X-Client-Secret: $CLIENT_SECRET")

echo "Response:"
echo "$RESPONSE" | python3 -m json.tool 2>/dev/null || echo "$RESPONSE"
echo ""

FINAL_STATUS=$(echo "$RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status', ''))" 2>/dev/null || echo "")
IS_DONE=$([ "$FINAL_STATUS" = "completed" ] || [ "$FINAL_STATUS" = "success" ] && echo "true" || echo "false")
check_result "Final status is completed ($FINAL_STATUS)" "$IS_DONE"
echo ""

# Summary
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
echo "  POST /api/request (request_type=multi-agent-plan) - Generate a plan"
echo "  GET  /api/v1/plan/{id}                            - Get plan status"
echo "  POST /api/request (request_type=execute-plan)     - Execute a plan"
