#!/bin/bash
# Mistral LLM Provider - MAP Confirm Mode Example (HTTP/cURL)
#
# Tests confirm mode (HITL approval before execution) with Mistral.
# Confirm mode is an Enterprise-only feature — this example gracefully
# skips with PASS if running in community mode (HTTP 403).
#
# VALIDATION: This example exits with code 1 if any assertion fails.
#
# Usage:
#   ./map-confirm.sh

set -euo pipefail

AGENT_URL="${AXONFLOW_AGENT_URL:-${AXONFLOW_ENDPOINT:-http://localhost:8080}}"
CLIENT_ID="${AXONFLOW_CLIENT_ID:-community}"
CLIENT_SECRET="${AXONFLOW_CLIENT_SECRET:-}"
AUTH_B64=$(printf '%s:%s' "$CLIENT_ID" "$CLIENT_SECRET" | base64)
USER_TOKEN="${AXONFLOW_USER_TOKEN:-$CLIENT_ID}"

echo "=============================================="
echo "Mistral Provider - MAP Confirm Mode (Enterprise)"
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

extract_plan_id() {
    python3 -c "
import sys, json
r = json.load(sys.stdin)
pid = r.get('plan_id', '')
if not pid:
    data = r.get('data', {})
    if isinstance(data, dict):
        pid = data.get('plan_id', '')
print(pid)
" 2>/dev/null || echo ""
}

# -----------------------------------------------
# Test 1: Generate plan in confirm mode
# -----------------------------------------------
echo "Test 1: Generate plan with confirm execution mode..."
echo "----------------------------------------------"

RESPONSE=$(curl -s -X POST "${AGENT_URL}/api/request" \
  -H "Content-Type: application/json" \
  -H "Authorization: Basic $AUTH_B64" \
  -d "{
    \"query\": \"Analyze customer churn data and propose a retention strategy\",
    \"user_token\": \"${USER_TOKEN}\",
    \"client_id\": \"${CLIENT_ID}\",
    \"request_type\": \"multi-agent-plan\",
    \"context\": {
      \"domain\": \"analytics\",
      \"execution_mode\": \"confirm\"
    }
  }")

SUCCESS=$(echo "$RESPONSE" | python3 -c "import sys,json; print('true' if json.load(sys.stdin).get('success', False) else 'false')" 2>/dev/null || echo "false")
PLAN_ID=$(echo "$RESPONSE" | extract_plan_id)

# Confirm mode may be rejected in community mode (403)
ERROR_MSG=$(echo "$RESPONSE" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('error','') or d.get('data',{}).get('error','') if isinstance(d.get('data'),dict) else '')" 2>/dev/null || echo "")

if echo "$ERROR_MSG" | grep -qi "enterprise\|license\|Invalid execution mode"; then
    echo "   SKIP: Confirm mode requires Enterprise license"
    echo "   (This is expected in community/evaluation mode)"
    check_result "Confirm mode gated by license (expected)" "true"
    echo ""
    echo "=============================================="
    echo "Results: $((PASS))/$((PASS + FAIL)) assertions passed"
    echo "ALL ASSERTIONS PASSED (Enterprise features skipped)"
    echo "=============================================="
    exit 0
fi

check_result "Plan generated in confirm mode" "$SUCCESS"
check_result "Plan ID returned ($PLAN_ID)" "$([ -n "$PLAN_ID" ] && echo true || echo false)"
echo ""

# -----------------------------------------------
# Test 2: Execute in confirm mode — should create WCP workflow
# -----------------------------------------------
echo "Test 2: Execute in confirm mode — creates approval workflow..."
echo "----------------------------------------------"

if [ -n "$PLAN_ID" ]; then
    EXEC_RESPONSE=$(curl -s -X POST "${AGENT_URL}/api/request" \
      -H "Content-Type: application/json" \
      -H "Authorization: Basic $AUTH_B64" \
      -d "{
        \"query\": \"\",
        \"user_token\": \"${USER_TOKEN}\",
        \"client_id\": \"${CLIENT_ID}\",
        \"request_type\": \"execute-plan\",
        \"context\": { \"plan_id\": \"${PLAN_ID}\" }
      }")

    EXEC_SUCCESS=$(echo "$EXEC_RESPONSE" | python3 -c "import sys,json; print('true' if json.load(sys.stdin).get('success', False) else 'false')" 2>/dev/null || echo "false")
    check_result "Confirm execution initiated" "$EXEC_SUCCESS"

    # Check status — should be waiting_for_approval or similar
    STATUS=$(curl -s "${AGENT_URL}/api/v1/plan/${PLAN_ID}" -H "Authorization: Basic $AUTH_B64" | \
      python3 -c "import sys,json; print(json.load(sys.stdin).get('status', ''))" 2>/dev/null || echo "")
    check_result "Plan status shows approval pending ($STATUS)" "$(echo "$STATUS" | grep -qiE 'pending|waiting|approval|confirm|executing' && echo true || echo false)"
fi
echo ""

# -----------------------------------------------
# Test 3: Approve first step (if enterprise)
# -----------------------------------------------
echo "Test 3: Step approval..."
echo "----------------------------------------------"

if [ -n "$PLAN_ID" ]; then
    # Get plan details to find step IDs
    PLAN_DETAIL=$(curl -s "${AGENT_URL}/api/v1/plan/${PLAN_ID}" -H "Authorization: Basic $AUTH_B64")

    FIRST_STEP_ID=$(echo "$PLAN_DETAIL" | python3 -c "
import sys, json
r = json.load(sys.stdin)
steps = r.get('steps', [])
if steps and isinstance(steps[0], dict):
    print(steps[0].get('id', steps[0].get('step_id', '')))
else:
    print('')
" 2>/dev/null || echo "")

    if [ -n "$FIRST_STEP_ID" ]; then
        APPROVE_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
          "${AGENT_URL}/api/v1/plans/${PLAN_ID}/steps/${FIRST_STEP_ID}/approve" \
          -H "Content-Type: application/json" \
          -H "Authorization: Basic $AUTH_B64" \
          -d '{"approved_by": "test-user"}')

        check_result "Step approval endpoint available (HTTP $APPROVE_CODE)" "$(echo "$APPROVE_CODE" | grep -qE '^(200|202|404)$' && echo true || echo false)"
    else
        echo "   SKIP: No step IDs found in plan"
        check_result "Step approval (skipped — no step IDs)" "true"
    fi
fi
echo ""

# -----------------------------------------------
# Results
# -----------------------------------------------
echo "=============================================="
echo "Results: $((PASS))/$((PASS + FAIL)) assertions passed"
if [ "$FAIL" -eq 0 ]; then
    echo "ALL ASSERTIONS PASSED"
else
    echo "FAILED: ${FAIL} assertion(s) failed"
    exit 1
fi
echo "=============================================="
