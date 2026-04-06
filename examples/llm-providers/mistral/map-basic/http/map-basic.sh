#!/bin/bash
# Mistral LLM Provider - MAP Basic Plan Generation (HTTP/cURL)
#
# Tests that Mistral can decompose a task into a multi-agent plan.
# This is the core MAP value proposition: the LLM breaks complex queries
# into coordinated agent steps.
#
# VALIDATION: This example exits with code 1 if any assertion fails.
#
# Prerequisites:
#   docker compose up -d  (with MISTRAL_API_KEY set)
#
# Usage:
#   ./map-basic.sh

set -euo pipefail

AGENT_URL="${AXONFLOW_AGENT_URL:-${AXONFLOW_ENDPOINT:-http://localhost:8080}}"
CLIENT_ID="${AXONFLOW_CLIENT_ID:-community}"
CLIENT_SECRET="${AXONFLOW_CLIENT_SECRET:-}"
AUTH_B64=$(printf '%s:%s' "$CLIENT_ID" "$CLIENT_SECRET" | base64)
USER_TOKEN="${AXONFLOW_USER_TOKEN:-$CLIENT_ID}"

echo "=============================================="
echo "Mistral Provider - MAP Basic Plan Generation"
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

# -----------------------------------------------
# Test 1: Generate a multi-agent plan
# -----------------------------------------------
echo "Test 1: Generate Plan — Mistral decomposes task into agent steps..."
echo "----------------------------------------------"

RESPONSE=$(curl -s -X POST "${AGENT_URL}/api/request" \
  -H "Content-Type: application/json" \
  -H "Authorization: Basic $AUTH_B64" \
  -d '{
    "query": "Research the latest EU AI Act requirements and summarize the key compliance obligations for a financial services company",
    "user_token": "'"$USER_TOKEN"'",
    "client_id": "'"$CLIENT_ID"'",
    "request_type": "multi-agent-plan",
    "context": {
      "domain": "compliance"
    }
  }')

SUCCESS=$(echo "$RESPONSE" | python3 -c "import sys,json; print('true' if json.load(sys.stdin).get('success', False) else 'false')" 2>/dev/null || echo "false")
check_result "GeneratePlan succeeded" "$SUCCESS"

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
check_result "Plan ID returned ($PLAN_ID)" "$([ -n "$PLAN_ID" ] && echo true || echo false)"

# Check plan has steps (Mistral decomposed the task)
STEP_COUNT=$(echo "$RESPONSE" | python3 -c "
import sys, json
r = json.load(sys.stdin)
data = r.get('data', r) if isinstance(r.get('data'), dict) else r
steps = data.get('steps', data.get('plan', {}).get('steps', []))
print(len(steps) if isinstance(steps, list) else 0)
" 2>/dev/null || echo "0")
check_result "Plan has steps (${STEP_COUNT} steps)" "$([ "$STEP_COUNT" -gt 0 ] && echo true || echo false)"
echo ""

# -----------------------------------------------
# Test 2: Get plan status
# -----------------------------------------------
echo "Test 2: Get Plan Status..."
echo "----------------------------------------------"

if [ -n "$PLAN_ID" ]; then
    STATUS_RESPONSE=$(curl -s "${AGENT_URL}/api/v1/plan/${PLAN_ID}" \
      -H "Authorization: Basic $AUTH_B64")

    STATUS=$(echo "$STATUS_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status', ''))" 2>/dev/null || echo "")
    check_result "Plan status is pending/generated ($STATUS)" "$(echo "$STATUS" | grep -qE 'pending|created|generated' && echo true || echo false)"
else
    check_result "Plan status (skipped — no plan ID)" "false"
fi
echo ""

# -----------------------------------------------
# Test 3: Execute the plan
# -----------------------------------------------
echo "Test 3: Execute Plan — run all agent steps..."
echo "----------------------------------------------"

if [ -n "$PLAN_ID" ]; then
    EXEC_RESPONSE=$(curl -s -X POST "${AGENT_URL}/api/request" \
      -H "Content-Type: application/json" \
      -H "Authorization: Basic $AUTH_B64" \
      -d '{
        "query": "",
        "user_token": "'"$USER_TOKEN"'",
        "client_id": "'"$CLIENT_ID"'",
        "request_type": "execute-plan",
        "context": {
          "plan_id": "'"$PLAN_ID"'"
        }
      }')

    EXEC_SUCCESS=$(echo "$EXEC_RESPONSE" | python3 -c "import sys,json; print('true' if json.load(sys.stdin).get('success', False) else 'false')" 2>/dev/null || echo "false")
    check_result "Plan execution succeeded" "$EXEC_SUCCESS"

    # Verify final status is completed
    FINAL_RESPONSE=$(curl -s "${AGENT_URL}/api/v1/plan/${PLAN_ID}" \
      -H "Authorization: Basic $AUTH_B64")

    FINAL_STATUS=$(echo "$FINAL_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status', ''))" 2>/dev/null || echo "")
    check_result "Final status is completed ($FINAL_STATUS)" "$(echo "$FINAL_STATUS" | grep -qE 'completed|success' && echo true || echo false)"
else
    check_result "Plan execution (skipped — no plan ID)" "false"
    check_result "Final status (skipped — no plan ID)" "false"
fi
echo ""

# -----------------------------------------------
# Test 4: Policy enforcement on MAP queries
# -----------------------------------------------
echo "Test 4: Policy enforcement — SQLi blocked even in MAP..."
echo "----------------------------------------------"

SQLI_RESPONSE=$(curl -s -X POST "${AGENT_URL}/api/request" \
  -H "Content-Type: application/json" \
  -H "Authorization: Basic $AUTH_B64" \
  -d '{
    "query": "SELECT * FROM users; DROP TABLE users;",
    "user_token": "'"$USER_TOKEN"'",
    "client_id": "'"$CLIENT_ID"'",
    "request_type": "multi-agent-plan"
  }')

SQLI_BLOCKED=$(echo "$SQLI_RESPONSE" | python3 -c "import sys,json; d=json.load(sys.stdin); print(str(d.get('blocked', False)).lower())" 2>/dev/null || echo "false")
check_result "SQLi blocked in MAP request" "$([ "$SQLI_BLOCKED" = "true" ] && echo true || echo false)"
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
