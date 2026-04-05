#!/bin/bash
# MAP Confirm Mode - HTTP API Example (Enterprise Only)
#
# This example demonstrates the confirm execution mode where every step
# requires explicit approval before execution.
#
# REQUIRES: Enterprise license
#
# Flow:
#   1. Generate plan with execution_mode: "confirm"
#   2. Execute plan -> returns "awaiting_approval"
#   3. Resume plan (approve step) -> executes step, pauses at next
#   4. Repeat until all steps complete
#
# Usage:
#   docker compose up -d  # with enterprise license
#   cd examples/map-confirm-mode/http
#   ./map-confirm.sh

set -e

AGENT_URL="${AXONFLOW_AGENT_URL:-http://localhost:8080}"
CLIENT_ID="${AXONFLOW_CLIENT_ID:-community}"
CLIENT_SECRET="${AXONFLOW_CLIENT_SECRET:-}"
AUTH_B64=$(printf '%s:%s' "$CLIENT_ID" "$CLIENT_SECRET" | base64)
USER_TOKEN="${AXONFLOW_USER_TOKEN:-$CLIENT_ID}"
AUTH_HEADER="Authorization: Basic $(printf '%s:%s' "$CLIENT_ID" "$CLIENT_SECRET" | base64)"

echo "=============================================="
echo "MAP Confirm Mode - HTTP API Example (Enterprise)"
echo "=============================================="
echo "Agent URL: $AGENT_URL"

# Detect community mode — confirm mode requires Enterprise license
HEALTH=$(curl -s "$AGENT_URL/health" 2>/dev/null || echo '{}')
TIER=$(echo "$HEALTH" | jq -r '.license_tier // "community"' 2>/dev/null || echo "community")
if [ "$TIER" = "community" ] || [ "$TIER" = "Community" ] || [ -z "$CLIENT_SECRET" ]; then
    echo ""
    echo "⏭  Skipping: Confirm mode requires Enterprise license (current: $TIER)"
    echo "   Get a free Evaluation license at https://getaxonflow.com/evaluation-license"
    exit 0
fi
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
    # Check top-level first, then data.{field} (agent wraps orchestrator response in data)
    echo "$json" | python3 -c "
import sys,json
d = json.load(sys.stdin)
v = d.get('$field', '')
if not v and isinstance(d.get('data'), dict):
    v = d['data'].get('$field', '')
print(v)
" 2>/dev/null || echo ""
}

# ========================================
# 1. GENERATE PLAN WITH CONFIRM MODE
# ========================================
echo "1. Generate Plan - Confirm mode..."
echo "----------------------------------------------"

RESPONSE=$(curl -s -X POST "${AGENT_URL}/api/request" \
  -H "Content-Type: application/json" \
  -H "$AUTH_HEADER" \
  -H "Authorization: Basic $AUTH_B64" \
  -d '{
    "query": "Create a plan to search flights, analyze options, and book the best one",
    "user_token": "'"$USER_TOKEN"'",
    "client_id": "'"$CLIENT_ID"'",
    "request_type": "multi-agent-plan",
    "context": {
      "domain": "travel",
      "execution_mode": "confirm"
    }
  }')

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

if [ -z "$PLAN_ID" ]; then
    # Confirm mode requires enterprise license
    ERROR=$(extract_json "$RESPONSE" "error")
    if echo "$ERROR" | grep -qi "enterprise\|license\|forbidden"; then
        echo "   SKIP: Confirm mode requires enterprise license"
        echo "   Error: $ERROR"
        echo ""
        echo "=============================================="
        echo "Results: 0 passed, 0 failed (skipped - enterprise only)"
        exit 0
    fi
    echo "   FATAL: No plan ID and no enterprise error: $RESPONSE"
    exit 1
fi

check_result "Confirm mode plan generated ($PLAN_ID)" "true"

STEPS=$(echo "$RESPONSE" | python3 -c "
import sys, json
r = json.load(sys.stdin)
steps = r.get('steps', r.get('data', {}).get('steps', []))
print(len(steps) if isinstance(steps, list) else 0)
" 2>/dev/null || echo "0")
echo "   Steps: $STEPS"
echo ""

# ========================================
# 2. EXECUTE PLAN (should return awaiting_approval)
# ========================================
echo "2. Execute Plan - Should return awaiting_approval..."
echo "----------------------------------------------"

RESPONSE=$(curl -s -X POST "${AGENT_URL}/api/request" \
  -H "Content-Type: application/json" \
  -H "$AUTH_HEADER" \
  -H "Authorization: Basic $AUTH_B64" \
  -d '{
    "query": "",
    "user_token": "'"$USER_TOKEN"'",
    "client_id": "'"$CLIENT_ID"'",
    "request_type": "execute-plan",
    "context": {"plan_id": "'"$PLAN_ID"'"}
  }')

EXEC_STATUS=$(extract_json "$RESPONSE" "status")
IS_AWAITING=$([ "$EXEC_STATUS" = "awaiting_approval" ] && echo "true" || echo "false")
check_result "Execution status is awaiting_approval ($EXEC_STATUS)" "$IS_AWAITING"
echo ""

# ========================================
# 3-N. RESUME LOOP (approve each step)
# ========================================
STEP_NUM=1
TOTAL_STEPS=${STEPS:-3}
while [ "$STEP_NUM" -le "$TOTAL_STEPS" ]; do
    echo "$((STEP_NUM + 2)). Resume Plan - Approve step $STEP_NUM..."
    echo "----------------------------------------------"

    RESPONSE=$(curl -s -X POST "${AGENT_URL}/api/v1/plan/${PLAN_ID}/resume" \
      -H "Content-Type: application/json" \
      -H "$AUTH_HEADER" \
      -H "Authorization: Basic $AUTH_B64" \
      -d '{"approved": true}')

    RESUME_STATUS=$(extract_json "$RESPONSE" "status")
    echo "   Status: $RESUME_STATUS"

    if [ "$RESUME_STATUS" = "completed" ]; then
        check_result "Plan completed after step $STEP_NUM" "true"
        echo ""
        break
    elif [ "$RESUME_STATUS" = "awaiting_approval" ]; then
        check_result "Step $STEP_NUM approved, paused at next step" "true"
    else
        check_result "Resume step $STEP_NUM returned expected status ($RESUME_STATUS)" "false"
    fi
    echo ""

    STEP_NUM=$((STEP_NUM + 1))
done

# ========================================
# FINAL STATUS CHECK
# ========================================
echo "Final Status Check..."
echo "----------------------------------------------"

# Wait for async plan status update (WCP completion triggers plan status update)
# The WCP workflow completion is async — poll for up to 10 seconds
for i in 1 2 3 4 5; do
    RESPONSE=$(curl -s "${AGENT_URL}/api/v1/plan/${PLAN_ID}" \
      -H "$AUTH_HEADER" \
      -H "Authorization: Basic $AUTH_B64" \
)
    FINAL_STATUS=$(extract_json "$RESPONSE" "status")
    [ "$FINAL_STATUS" = "completed" ] && break
    sleep 2
done

RESPONSE=$(curl -s "${AGENT_URL}/api/v1/plan/${PLAN_ID}" \
  -H "$AUTH_HEADER" \
  -H "Authorization: Basic $AUTH_B64" \
)

FINAL_STATUS=$(extract_json "$RESPONSE" "status")
IS_DONE=$([ "$FINAL_STATUS" = "completed" ] || [ "$FINAL_STATUS" = "success" ] && echo "true" || echo "false")
check_result "Final status is completed ($FINAL_STATUS)" "$IS_DONE"
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
echo "Confirm Mode Flow:"
echo "  1. POST /api/request (execution_mode=confirm) - Generate plan"
echo "  2. POST /api/request (execute-plan)            - Start (awaiting_approval)"
echo "  3. POST /api/v1/plan/{id}/resume               - Approve each step"
echo "  4. GET  /api/v1/plan/{id}                      - Final status"
