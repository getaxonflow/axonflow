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
#   5. Cancel a plan (POST /api/v1/plan/{id}/cancel)
#   6. Execution modes (sequential vs parallel)
#   7. Plan versioning (PUT /api/v1/plan/{id}, GET /api/v1/plan/{id}/versions)
#   8. Plan rollback (POST /api/v1/plan/{id}/rollback/{version}) (enterprise)

set -e

AGENT_URL="${AXONFLOW_AGENT_URL:-${AXONFLOW_ENDPOINT:-http://localhost:8080}}"
ORCHESTRATOR_URL="${AXONFLOW_ORCHESTRATOR_URL:-http://localhost:8081}"
CLIENT_ID="${AXONFLOW_CLIENT_ID:-map-http-example}"
CLIENT_SECRET="${AXONFLOW_CLIENT_SECRET:-}"
USER_TOKEN="${AXONFLOW_USER_TOKEN:-$CLIENT_ID}"

# Build auth header: use Authorization: Basic if client_secret is set (enterprise mode)
AUTH_HEADER=""
if [ -n "$CLIENT_SECRET" ]; then
    AUTH_HEADER="Authorization: Basic $(printf '%s:%s' "$CLIENT_ID" "$CLIENT_SECRET" | base64)"
fi

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
  ${AUTH_HEADER:+-H "$AUTH_HEADER"} \
  -H "X-Client-ID: $CLIENT_ID" \
  -H "X-Client-Secret: $CLIENT_SECRET" \
  -d '{
    "query": "Create a brief plan to greet a new user and ask how to help them",
    "user_token": "'"$USER_TOKEN"'",
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
  ${AUTH_HEADER:+-H "$AUTH_HEADER"} \
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
  ${AUTH_HEADER:+-H "$AUTH_HEADER"} \
  -H "X-Client-ID: $CLIENT_ID" \
  -H "X-Client-Secret: $CLIENT_SECRET" \
  -d '{
    "query": "",
    "user_token": "'"$USER_TOKEN"'",
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
  ${AUTH_HEADER:+-H "$AUTH_HEADER"} \
  -H "X-Client-ID: $CLIENT_ID" \
  -H "X-Client-Secret: $CLIENT_SECRET")

echo "Response:"
echo "$RESPONSE" | python3 -m json.tool 2>/dev/null || echo "$RESPONSE"
echo ""

FINAL_STATUS=$(echo "$RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status', ''))" 2>/dev/null || echo "")
IS_DONE=$([ "$FINAL_STATUS" = "completed" ] || [ "$FINAL_STATUS" = "success" ] && echo "true" || echo "false")
check_result "Final status is completed ($FINAL_STATUS)" "$IS_DONE"
echo ""

# 5. Cancel Plan
echo "5. CancelPlan - Cancel a plan and verify rejection..."
echo "----------------------------------------------"

# 5a. Generate a fresh plan to cancel
RESPONSE=$(curl -s -X POST "${AGENT_URL}/api/request" \
  -H "Content-Type: application/json" \
  ${AUTH_HEADER:+-H "$AUTH_HEADER"} \
  -H "X-Client-ID: $CLIENT_ID" \
  -H "X-Client-Secret: $CLIENT_SECRET" \
  -d '{
    "query": "Create a brief plan to greet a new user and ask how to help them",
    "user_token": "'"$USER_TOKEN"'",
    "client_id": "'"$CLIENT_ID"'",
    "request_type": "multi-agent-plan",
    "context": {
      "domain": "generic"
    }
  }')

CANCEL_PLAN_ID=$(echo "$RESPONSE" | python3 -c "
import sys, json
r = json.load(sys.stdin)
pid = r.get('plan_id', '')
if not pid:
    data = r.get('data', {})
    if isinstance(data, dict):
        pid = data.get('plan_id', '')
print(pid)
" 2>/dev/null || echo "")

HAS_CANCEL_PLAN_ID=$([ -n "$CANCEL_PLAN_ID" ] && echo "true" || echo "false")
check_result "Generated plan to cancel ($CANCEL_PLAN_ID)" "$HAS_CANCEL_PLAN_ID"

# 5b. Cancel the plan
RESPONSE=$(curl -s -X POST "${AGENT_URL}/api/v1/plan/${CANCEL_PLAN_ID}/cancel" \
  -H "Content-Type: application/json" \
  ${AUTH_HEADER:+-H "$AUTH_HEADER"} \
  -H "X-Client-ID: $CLIENT_ID" \
  -H "X-Client-Secret: $CLIENT_SECRET" \
  -d '{
    "reason": "Testing cancel functionality"
  }')

echo "Cancel response:"
echo "$RESPONSE" | python3 -m json.tool 2>/dev/null || echo "$RESPONSE"
echo ""

CANCEL_STATUS=$(echo "$RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status', ''))" 2>/dev/null || echo "")
IS_CANCELLED=$([ "$CANCEL_STATUS" = "cancelled" ] && echo "true" || echo "false")
check_result "Plan status is cancelled ($CANCEL_STATUS)" "$IS_CANCELLED"

# 5c. Try executing the cancelled plan - should be rejected
RESPONSE=$(curl -s -X POST "${AGENT_URL}/api/request" \
  -H "Content-Type: application/json" \
  ${AUTH_HEADER:+-H "$AUTH_HEADER"} \
  -H "X-Client-ID: $CLIENT_ID" \
  -H "X-Client-Secret: $CLIENT_SECRET" \
  -d '{
    "query": "",
    "user_token": "'"$USER_TOKEN"'",
    "client_id": "'"$CLIENT_ID"'",
    "request_type": "execute-plan",
    "context": {
      "plan_id": "'"$CANCEL_PLAN_ID"'"
    }
  }')

echo "Execute cancelled plan response:"
echo "$RESPONSE" | python3 -m json.tool 2>/dev/null || echo "$RESPONSE"
echo ""

EXEC_CANCELLED=$(echo "$RESPONSE" | python3 -c "
import sys,json
r=json.load(sys.stdin)
# Check inner data.success (agent wraps with outer success=true)
data = r.get('data', r)
inner_success = data.get('success', True) if isinstance(data, dict) else r.get('success', True)
print('true' if not inner_success else 'false')
" 2>/dev/null || echo "false")
check_result "Executing cancelled plan was rejected" "$EXEC_CANCELLED"
echo ""

# 6. Execution Modes
echo "6. ExecutionModes - Sequential and parallel execution..."
echo "----------------------------------------------"

# 6a. Sequential execution mode
echo "6a. Sequential mode..."
RESPONSE=$(curl -s -X POST "${AGENT_URL}/api/request" \
  -H "Content-Type: application/json" \
  ${AUTH_HEADER:+-H "$AUTH_HEADER"} \
  -H "X-Client-ID: $CLIENT_ID" \
  -H "X-Client-Secret: $CLIENT_SECRET" \
  -d '{
    "query": "Create a brief plan to greet a new user and ask how to help them",
    "user_token": "'"$USER_TOKEN"'",
    "client_id": "'"$CLIENT_ID"'",
    "request_type": "multi-agent-plan",
    "context": {
      "domain": "generic",
      "execution_mode": "sequential"
    }
  }')

SEQ_PLAN_ID=$(echo "$RESPONSE" | python3 -c "
import sys, json
r = json.load(sys.stdin)
pid = r.get('plan_id', '')
if not pid:
    data = r.get('data', {})
    if isinstance(data, dict):
        pid = data.get('plan_id', '')
print(pid)
" 2>/dev/null || echo "")

HAS_SEQ_PLAN=$([ -n "$SEQ_PLAN_ID" ] && echo "true" || echo "false")
check_result "Generated sequential plan ($SEQ_PLAN_ID)" "$HAS_SEQ_PLAN"

RESPONSE=$(curl -s -X POST "${AGENT_URL}/api/request" \
  -H "Content-Type: application/json" \
  ${AUTH_HEADER:+-H "$AUTH_HEADER"} \
  -H "X-Client-ID: $CLIENT_ID" \
  -H "X-Client-Secret: $CLIENT_SECRET" \
  -d '{
    "query": "",
    "user_token": "'"$USER_TOKEN"'",
    "client_id": "'"$CLIENT_ID"'",
    "request_type": "execute-plan",
    "context": {
      "plan_id": "'"$SEQ_PLAN_ID"'"
    }
  }')

SEQ_SUCCESS=$(echo "$RESPONSE" | python3 -c "import sys,json; print('true' if json.load(sys.stdin).get('success', False) else 'false')" 2>/dev/null || echo "false")
check_result "Sequential plan execution succeeded" "$SEQ_SUCCESS"

# 6b. Parallel execution mode
echo "6b. Parallel mode..."
RESPONSE=$(curl -s -X POST "${AGENT_URL}/api/request" \
  -H "Content-Type: application/json" \
  ${AUTH_HEADER:+-H "$AUTH_HEADER"} \
  -H "X-Client-ID: $CLIENT_ID" \
  -H "X-Client-Secret: $CLIENT_SECRET" \
  -d '{
    "query": "Create a brief plan to greet a new user and ask how to help them",
    "user_token": "'"$USER_TOKEN"'",
    "client_id": "'"$CLIENT_ID"'",
    "request_type": "multi-agent-plan",
    "context": {
      "domain": "generic",
      "execution_mode": "parallel"
    }
  }')

PAR_PLAN_ID=$(echo "$RESPONSE" | python3 -c "
import sys, json
r = json.load(sys.stdin)
pid = r.get('plan_id', '')
if not pid:
    data = r.get('data', {})
    if isinstance(data, dict):
        pid = data.get('plan_id', '')
print(pid)
" 2>/dev/null || echo "")

HAS_PAR_PLAN=$([ -n "$PAR_PLAN_ID" ] && echo "true" || echo "false")
check_result "Generated parallel plan ($PAR_PLAN_ID)" "$HAS_PAR_PLAN"

RESPONSE=$(curl -s -X POST "${AGENT_URL}/api/request" \
  -H "Content-Type: application/json" \
  ${AUTH_HEADER:+-H "$AUTH_HEADER"} \
  -H "X-Client-ID: $CLIENT_ID" \
  -H "X-Client-Secret: $CLIENT_SECRET" \
  -d '{
    "query": "",
    "user_token": "'"$USER_TOKEN"'",
    "client_id": "'"$CLIENT_ID"'",
    "request_type": "execute-plan",
    "context": {
      "plan_id": "'"$PAR_PLAN_ID"'"
    }
  }')

PAR_SUCCESS=$(echo "$RESPONSE" | python3 -c "import sys,json; print('true' if json.load(sys.stdin).get('success', False) else 'false')" 2>/dev/null || echo "false")
check_result "Parallel plan execution succeeded" "$PAR_SUCCESS"
echo ""

# 7. Plan Versioning
echo "7. PlanVersioning - Update plan and check version history..."
echo "----------------------------------------------"

# 7a. Generate a fresh plan for versioning
RESPONSE=$(curl -s -X POST "${AGENT_URL}/api/request" \
  -H "Content-Type: application/json" \
  ${AUTH_HEADER:+-H "$AUTH_HEADER"} \
  -H "X-Client-ID: $CLIENT_ID" \
  -H "X-Client-Secret: $CLIENT_SECRET" \
  -d '{
    "query": "Create a brief plan to greet a new user and ask how to help them",
    "user_token": "'"$USER_TOKEN"'",
    "client_id": "'"$CLIENT_ID"'",
    "request_type": "multi-agent-plan",
    "context": {
      "domain": "generic"
    }
  }')

VER_PLAN_ID=$(echo "$RESPONSE" | python3 -c "
import sys, json
r = json.load(sys.stdin)
pid = r.get('plan_id', '')
if not pid:
    data = r.get('data', {})
    if isinstance(data, dict):
        pid = data.get('plan_id', '')
print(pid)
" 2>/dev/null || echo "")

HAS_VER_PLAN=$([ -n "$VER_PLAN_ID" ] && echo "true" || echo "false")
check_result "Generated plan for versioning ($VER_PLAN_ID)" "$HAS_VER_PLAN"

# 7b. Update the plan (version 1 -> 2)
RESPONSE=$(curl -s -X PUT "${AGENT_URL}/api/v1/plan/${VER_PLAN_ID}" \
  -H "Content-Type: application/json" \
  ${AUTH_HEADER:+-H "$AUTH_HEADER"} \
  -H "X-Client-ID: $CLIENT_ID" \
  -H "X-Client-Secret: $CLIENT_SECRET" \
  -d '{
    "version": 1,
    "execution_mode": "parallel"
  }')

echo "Update plan response:"
echo "$RESPONSE" | python3 -m json.tool 2>/dev/null || echo "$RESPONSE"
echo ""

NEW_VERSION=$(echo "$RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('version', 0))" 2>/dev/null || echo "0")
IS_V2=$([ "$NEW_VERSION" = "2" ] && echo "true" || echo "false")
check_result "Plan updated to version 2 (got $NEW_VERSION)" "$IS_V2"

# 7c. Try stale update with version 1 - should get 409 Conflict
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X PUT "${AGENT_URL}/api/v1/plan/${VER_PLAN_ID}" \
  -H "Content-Type: application/json" \
  ${AUTH_HEADER:+-H "$AUTH_HEADER"} \
  -H "X-Client-ID: $CLIENT_ID" \
  -H "X-Client-Secret: $CLIENT_SECRET" \
  -d '{
    "version": 1,
    "execution_mode": "sequential"
  }')

IS_CONFLICT=$([ "$HTTP_CODE" = "409" ] && echo "true" || echo "false")
check_result "Stale update rejected with 409 (got $HTTP_CODE)" "$IS_CONFLICT"

# 7d. Get version history
RESPONSE=$(curl -s "${AGENT_URL}/api/v1/plan/${VER_PLAN_ID}/versions" \
  ${AUTH_HEADER:+-H "$AUTH_HEADER"} \
  -H "X-Client-ID: $CLIENT_ID" \
  -H "X-Client-Secret: $CLIENT_SECRET")

echo "Version history response:"
echo "$RESPONSE" | python3 -m json.tool 2>/dev/null || echo "$RESPONSE"
echo ""

VERSION_COUNT=$(echo "$RESPONSE" | python3 -c "
import sys, json
r = json.load(sys.stdin)
versions = r.get('versions', r if isinstance(r, list) else [])
print(len(versions))
" 2>/dev/null || echo "0")

HAS_VERSIONS=$([ "$VERSION_COUNT" -ge 1 ] 2>/dev/null && echo "true" || echo "false")
check_result "Version history has at least 1 entry (got $VERSION_COUNT)" "$HAS_VERSIONS"
echo ""

# 8. Plan Rollback
echo "8. PlanRollback - Rollback to a previous version (enterprise)..."
echo "----------------------------------------------"

# 8a. Generate a fresh plan for rollback testing
RESPONSE=$(curl -s -X POST "${AGENT_URL}/api/request" \
  -H "Content-Type: application/json" \
  ${AUTH_HEADER:+-H "$AUTH_HEADER"} \
  -H "X-Client-ID: $CLIENT_ID" \
  -H "X-Client-Secret: $CLIENT_SECRET" \
  -d '{
    "query": "Create a brief plan to greet a new user and ask how to help them",
    "user_token": "'"$USER_TOKEN"'",
    "client_id": "'"$CLIENT_ID"'",
    "request_type": "multi-agent-plan",
    "context": {
      "domain": "generic"
    }
  }')

RB_PLAN_ID=$(echo "$RESPONSE" | python3 -c "
import sys, json
r = json.load(sys.stdin)
pid = r.get('plan_id', '')
if not pid:
    data = r.get('data', {})
    if isinstance(data, dict):
        pid = data.get('plan_id', '')
print(pid)
" 2>/dev/null || echo "")

HAS_RB_PLAN=$([ -n "$RB_PLAN_ID" ] && echo "true" || echo "false")
check_result "Generated plan for rollback ($RB_PLAN_ID)" "$HAS_RB_PLAN"

# 8b. Update the plan (version 1 -> 2)
RESPONSE=$(curl -s -X PUT "${AGENT_URL}/api/v1/plan/${RB_PLAN_ID}" \
  -H "Content-Type: application/json" \
  ${AUTH_HEADER:+-H "$AUTH_HEADER"} \
  -H "X-Client-ID: $CLIENT_ID" \
  -H "X-Client-Secret: $CLIENT_SECRET" \
  -d '{
    "version": 1,
    "execution_mode": "parallel"
  }')

echo "Update plan response:"
echo "$RESPONSE" | python3 -m json.tool 2>/dev/null || echo "$RESPONSE"
echo ""

RB_NEW_VERSION=$(echo "$RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('version', 0))" 2>/dev/null || echo "0")
IS_RB_V2=$([ "$RB_NEW_VERSION" = "2" ] && echo "true" || echo "false")
check_result "Plan updated to version 2 (got $RB_NEW_VERSION)" "$IS_RB_V2"

# 8c. Rollback to version 1
HTTP_CODE=$(curl -s -o /tmp/axonflow_rollback_response.json -w "%{http_code}" -X POST "${AGENT_URL}/api/v1/plan/${RB_PLAN_ID}/rollback/1" \
  -H "Content-Type: application/json" \
  ${AUTH_HEADER:+-H "$AUTH_HEADER"} \
  -H "X-Client-ID: $CLIENT_ID" \
  -H "X-Client-Secret: $CLIENT_SECRET")

ROLLBACK_RESPONSE=$(cat /tmp/axonflow_rollback_response.json 2>/dev/null || echo "{}")

if [ "$HTTP_CODE" = "403" ]; then
    echo "   SKIP: Plan rollback requires enterprise license (HTTP 403)"
    echo "   Rollback is an enterprise-only feature."
    echo ""
else
    echo "Rollback response:"
    echo "$ROLLBACK_RESPONSE" | python3 -m json.tool 2>/dev/null || echo "$ROLLBACK_RESPONSE"
    echo ""

    # 8d. Verify rollback response has version=3 and restored_from_version=1
    ROLLBACK_VERSION=$(echo "$ROLLBACK_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('version', 0))" 2>/dev/null || echo "0")
    IS_V3=$([ "$ROLLBACK_VERSION" = "3" ] && echo "true" || echo "false")
    check_result "Rollback created version 3 (got $ROLLBACK_VERSION)" "$IS_V3"

    ROLLED_BACK_TO=$(echo "$ROLLBACK_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('rolled_back_to', 0))" 2>/dev/null || echo "0")
    IS_ROLLED_BACK_TO_1=$([ "$ROLLED_BACK_TO" = "1" ] && echo "true" || echo "false")
    check_result "Rolled back to version 1 (got $ROLLED_BACK_TO)" "$IS_ROLLED_BACK_TO_1"

    # 8e. Get version history and verify rollback entry
    RESPONSE=$(curl -s "${AGENT_URL}/api/v1/plan/${RB_PLAN_ID}/versions" \
      ${AUTH_HEADER:+-H "$AUTH_HEADER"} \
      -H "X-Client-ID: $CLIENT_ID")

    echo "Version history after rollback:"
    echo "$RESPONSE" | python3 -m json.tool 2>/dev/null || echo "$RESPONSE"
    echo ""

    RB_VERSION_COUNT=$(echo "$RESPONSE" | python3 -c "
import sys, json
r = json.load(sys.stdin)
versions = r.get('versions', r if isinstance(r, list) else [])
print(len(versions))
" 2>/dev/null || echo "0")

    HAS_RB_VERSIONS=$([ "$RB_VERSION_COUNT" -ge 2 ] 2>/dev/null && echo "true" || echo "false")
    check_result "Version history has at least 2 entries after rollback (got $RB_VERSION_COUNT)" "$HAS_RB_VERSIONS"

    # 8f. Try rollback to current/future version - should fail
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${AGENT_URL}/api/v1/plan/${RB_PLAN_ID}/rollback/99" \
      -H "Content-Type: application/json" \
      ${AUTH_HEADER:+-H "$AUTH_HEADER"} \
      -H "X-Client-ID: $CLIENT_ID")

    IS_RB_BAD=$([ "$HTTP_CODE" = "400" ] || [ "$HTTP_CODE" = "404" ] && echo "true" || echo "false")
    check_result "Rollback to invalid version rejected (got $HTTP_CODE)" "$IS_RB_BAD"
fi
echo ""

# 15. SSE Streaming - Real-time execution status
echo "15. SSE Streaming - Real-time execution status..."
echo "----------------------------------------------"

# 15a. Generate a fresh plan for SSE streaming
RESPONSE=$(curl -s -X POST "${AGENT_URL}/api/request" \
  -H "Content-Type: application/json" \
  ${AUTH_HEADER:+-H "$AUTH_HEADER"} \
  -H "X-Client-ID: $CLIENT_ID" \
  -H "X-Client-Secret: $CLIENT_SECRET" \
  -d '{
    "query": "Summarize quarterly report",
    "user_token": "'"$USER_TOKEN"'",
    "client_id": "'"$CLIENT_ID"'",
    "request_type": "multi-agent-plan",
    "context": {
      "domain": "generic"
    }
  }')

SSE_PLAN_ID=$(echo "$RESPONSE" | python3 -c "
import sys, json
r = json.load(sys.stdin)
pid = r.get('plan_id', '')
if not pid:
    data = r.get('data', {})
    if isinstance(data, dict):
        pid = data.get('plan_id', '')
print(pid)
" 2>/dev/null || echo "")

HAS_SSE_PLAN=$([ -n "$SSE_PLAN_ID" ] && echo "true" || echo "false")
check_result "Generated plan for SSE streaming ($SSE_PLAN_ID)" "$HAS_SSE_PLAN"

# 15b. Execute the plan
RESPONSE=$(curl -s -X POST "${AGENT_URL}/api/request" \
  -H "Content-Type: application/json" \
  ${AUTH_HEADER:+-H "$AUTH_HEADER"} \
  -H "X-Client-ID: $CLIENT_ID" \
  -H "X-Client-Secret: $CLIENT_SECRET" \
  -d '{
    "query": "",
    "user_token": "'"$USER_TOKEN"'",
    "client_id": "'"$CLIENT_ID"'",
    "request_type": "execute-plan",
    "context": {
      "plan_id": "'"$SSE_PLAN_ID"'"
    }
  }')

SSE_EXEC_SUCCESS=$(echo "$RESPONSE" | python3 -c "import sys,json; print('true' if json.load(sys.stdin).get('success', False) else 'false')" 2>/dev/null || echo "false")
check_result "SSE plan execution succeeded" "$SSE_EXEC_SUCCESS"

# 15c. Verify SSE execution streaming endpoint is available
echo "   Verifying SSE endpoint is registered..."
SSE_URL="${ORCHESTRATOR_URL}/api/v1/unified/executions/${SSE_PLAN_ID}/stream"
echo "   SSE URL: $SSE_URL"

SSE_HTTP_CODE=$(curl -s -o /tmp/sse_body.txt -w "%{http_code}" --max-time 10 \
  -H "X-Client-ID: $CLIENT_ID" \
  -H "X-Client-Secret: $CLIENT_SECRET" \
  "$SSE_URL" 2>/dev/null || echo "000")
SSE_BODY=$(cat /tmp/sse_body.txt 2>/dev/null || echo "")

if [ "$SSE_HTTP_CODE" = "200" ]; then
    # Active execution still streaming — endpoint works
    check_result "SSE endpoint available (HTTP 200 — active stream)" "true"
elif [ "$SSE_HTTP_CODE" = "404" ]; then
    # Expected: execution completed and evicted from tracker
    HAS_NOT_FOUND=$(echo "$SSE_BODY" | grep -c '"NOT_FOUND"' 2>/dev/null || echo "0")
    if [ "$HAS_NOT_FOUND" -ge 1 ]; then
        check_result "SSE endpoint available (JSON 404 NOT_FOUND — execution already completed, connect during active execution for events)" "true"
    else
        echo "   Unexpected 404 body: $SSE_BODY"
        check_result "SSE endpoint returns proper JSON 404 (got plain text 404)" "false"
    fi
else
    echo "   Unexpected HTTP status: $SSE_HTTP_CODE"
    echo "   Body: $SSE_BODY"
    check_result "SSE endpoint available (expected 200 or JSON 404, got $SSE_HTTP_CODE)" "false"
fi
echo "   Tip: For real-time SSE events, connect DURING plan execution:"
echo "     curl -N -H 'Accept: text/event-stream' $SSE_URL"
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
echo "  POST /api/v1/plan/{id}/cancel                     - Cancel a plan"
echo "  PUT  /api/v1/plan/{id}                            - Update a plan (versioning)"
echo "  GET  /api/v1/plan/{id}/versions                   - Get version history"
echo "  POST /api/v1/plan/{id}/rollback/{version}     - Rollback a plan (enterprise)"
echo "  GET  /api/v1/unified/executions/{id}/stream - SSE execution status stream (orchestrator :8081)"
