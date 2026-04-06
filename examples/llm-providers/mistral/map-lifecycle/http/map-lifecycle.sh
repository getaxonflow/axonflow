#!/bin/bash
# Mistral LLM Provider - MAP Lifecycle Example (HTTP/cURL)
#
# Tests the full MAP lifecycle with Mistral as the planning LLM:
# generate → status → execute → complete → cancel → versioning
#
# VALIDATION: This example exits with code 1 if any assertion fails.
#
# Usage:
#   ./map-lifecycle.sh

set -euo pipefail

AGENT_URL="${AXONFLOW_AGENT_URL:-${AXONFLOW_ENDPOINT:-http://localhost:8080}}"
CLIENT_ID="${AXONFLOW_CLIENT_ID:-community}"
CLIENT_SECRET="${AXONFLOW_CLIENT_SECRET:-}"
AUTH_B64=$(printf '%s:%s' "$CLIENT_ID" "$CLIENT_SECRET" | base64)
USER_TOKEN="${AXONFLOW_USER_TOKEN:-$CLIENT_ID}"

echo "=============================================="
echo "Mistral Provider - MAP Full Lifecycle"
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

generate_plan() {
    local query="$1"
    curl -s -X POST "${AGENT_URL}/api/request" \
      -H "Content-Type: application/json" \
      -H "Authorization: Basic $AUTH_B64" \
      -d "{
        \"query\": \"${query}\",
        \"user_token\": \"${USER_TOKEN}\",
        \"client_id\": \"${CLIENT_ID}\",
        \"request_type\": \"multi-agent-plan\",
        \"context\": { \"domain\": \"generic\" }
      }"
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
# Test 1: Generate + Execute + Complete
# -----------------------------------------------
echo "Test 1: Full cycle — Generate, Execute, Complete..."
echo "----------------------------------------------"

RESPONSE=$(generate_plan "Create a brief plan to analyze customer feedback and summarize key themes")
PLAN_ID=$(echo "$RESPONSE" | extract_plan_id)

check_result "Plan generated ($PLAN_ID)" "$([ -n "$PLAN_ID" ] && echo true || echo false)"

if [ -n "$PLAN_ID" ]; then
    # Execute
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
    check_result "Execution succeeded" "$EXEC_SUCCESS"

    # Final status
    STATUS=$(curl -s "${AGENT_URL}/api/v1/plan/${PLAN_ID}" -H "Authorization: Basic $AUTH_B64" | \
      python3 -c "import sys,json; print(json.load(sys.stdin).get('status', ''))" 2>/dev/null || echo "")
    check_result "Final status ($STATUS)" "$(echo "$STATUS" | grep -qE 'completed|success' && echo true || echo false)"
fi
echo ""

# -----------------------------------------------
# Test 2: Cancel — Generate then cancel before execution
# -----------------------------------------------
echo "Test 2: Cancel — Generate and cancel plan..."
echo "----------------------------------------------"

RESPONSE=$(generate_plan "Plan a team offsite event")
CANCEL_ID=$(echo "$RESPONSE" | extract_plan_id)

check_result "Plan to cancel ($CANCEL_ID)" "$([ -n "$CANCEL_ID" ] && echo true || echo false)"

if [ -n "$CANCEL_ID" ]; then
    CANCEL_RESPONSE=$(curl -s -X POST "${AGENT_URL}/api/v1/plan/${CANCEL_ID}/cancel" \
      -H "Content-Type: application/json" \
      -H "Authorization: Basic $AUTH_B64" \
      -d '{"reason": "Testing cancel in lifecycle example"}')

    CANCEL_STATUS=$(echo "$CANCEL_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status', ''))" 2>/dev/null || echo "")
    check_result "Plan cancelled ($CANCEL_STATUS)" "$([ "$CANCEL_STATUS" = "cancelled" ] && echo true || echo false)"

    # Verify execution of cancelled plan is rejected
    EXEC_CANCELLED=$(curl -s -X POST "${AGENT_URL}/api/request" \
      -H "Content-Type: application/json" \
      -H "Authorization: Basic $AUTH_B64" \
      -d "{
        \"query\": \"\",
        \"user_token\": \"${USER_TOKEN}\",
        \"client_id\": \"${CLIENT_ID}\",
        \"request_type\": \"execute-plan\",
        \"context\": { \"plan_id\": \"${CANCEL_ID}\" }
      }")

    EXEC_REJECTED=$(echo "$EXEC_CANCELLED" | python3 -c "
import sys,json
r=json.load(sys.stdin)
data = r.get('data', r)
inner_success = data.get('success', True) if isinstance(data, dict) else r.get('success', True)
print('true' if not inner_success else 'false')
" 2>/dev/null || echo "false")
    check_result "Cancelled plan rejected on execute" "$EXEC_REJECTED"
fi
echo ""

# -----------------------------------------------
# Test 3: Versioning — Update plan and check history
# -----------------------------------------------
echo "Test 3: Versioning — Update plan and track versions..."
echo "----------------------------------------------"

RESPONSE=$(generate_plan "Draft a quarterly report outline")
VER_ID=$(echo "$RESPONSE" | extract_plan_id)

check_result "Plan for versioning ($VER_ID)" "$([ -n "$VER_ID" ] && echo true || echo false)"

if [ -n "$VER_ID" ]; then
    # Update plan (v1 → v2)
    UPDATE_RESPONSE=$(curl -s -X PUT "${AGENT_URL}/api/v1/plan/${VER_ID}" \
      -H "Content-Type: application/json" \
      -H "Authorization: Basic $AUTH_B64" \
      -d '{"version": 1, "execution_mode": "parallel"}')

    NEW_VERSION=$(echo "$UPDATE_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('version', 0))" 2>/dev/null || echo "0")
    check_result "Updated to version 2 (got $NEW_VERSION)" "$([ "$NEW_VERSION" = "2" ] && echo true || echo false)"

    # Stale update with version 1 should get 409
    STALE_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X PUT "${AGENT_URL}/api/v1/plan/${VER_ID}" \
      -H "Content-Type: application/json" \
      -H "Authorization: Basic $AUTH_B64" \
      -d '{"version": 1, "execution_mode": "sequential"}')
    check_result "Stale update rejected (HTTP $STALE_CODE)" "$([ "$STALE_CODE" = "409" ] && echo true || echo false)"

    # Version history
    VERSIONS=$(curl -s "${AGENT_URL}/api/v1/plan/${VER_ID}/versions" \
      -H "Authorization: Basic $AUTH_B64" | \
      python3 -c "
import sys, json
r = json.load(sys.stdin)
versions = r.get('versions', r if isinstance(r, list) else [])
print(len(versions))
" 2>/dev/null || echo "0")
    check_result "Version history has entries ($VERSIONS)" "$([ "$VERSIONS" -ge 1 ] 2>/dev/null && echo true || echo false)"
fi
echo ""

# -----------------------------------------------
# Test 4: Execution modes — Sequential + Parallel
# -----------------------------------------------
echo "Test 4: Execution modes..."
echo "----------------------------------------------"

# Sequential
SEQ_RESPONSE=$(curl -s -X POST "${AGENT_URL}/api/request" \
  -H "Content-Type: application/json" \
  -H "Authorization: Basic $AUTH_B64" \
  -d "{
    \"query\": \"Greet a user and ask how to help\",
    \"user_token\": \"${USER_TOKEN}\",
    \"client_id\": \"${CLIENT_ID}\",
    \"request_type\": \"multi-agent-plan\",
    \"context\": { \"domain\": \"generic\", \"execution_mode\": \"sequential\" }
  }")

SEQ_ID=$(echo "$SEQ_RESPONSE" | extract_plan_id)
check_result "Sequential plan generated ($SEQ_ID)" "$([ -n "$SEQ_ID" ] && echo true || echo false)"

# Parallel
PAR_RESPONSE=$(curl -s -X POST "${AGENT_URL}/api/request" \
  -H "Content-Type: application/json" \
  -H "Authorization: Basic $AUTH_B64" \
  -d "{
    \"query\": \"Greet a user and ask how to help\",
    \"user_token\": \"${USER_TOKEN}\",
    \"client_id\": \"${CLIENT_ID}\",
    \"request_type\": \"multi-agent-plan\",
    \"context\": { \"domain\": \"generic\", \"execution_mode\": \"parallel\" }
  }")

PAR_ID=$(echo "$PAR_RESPONSE" | extract_plan_id)
check_result "Parallel plan generated ($PAR_ID)" "$([ -n "$PAR_ID" ] && echo true || echo false)"
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
