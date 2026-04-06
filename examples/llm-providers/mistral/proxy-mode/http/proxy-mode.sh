#!/bin/bash
# Mistral LLM Provider - Proxy Mode Example (HTTP/cURL)
#
# Tests Proxy Mode with policy enforcement through AxonFlow.
# Uses the default configured LLM provider for proxy calls while
# demonstrating that all policy enforcement (SQLi, PII, dangerous
# commands) works regardless of provider.
#
# VALIDATION: This example exits with code 1 if any assertion fails.
#
# Usage:
#   ./proxy-mode.sh

set -euo pipefail

AGENT_URL="${AXONFLOW_AGENT_URL:-${AXONFLOW_ENDPOINT:-http://localhost:8080}}"
CLIENT_ID="${AXONFLOW_CLIENT_ID:-community}"
CLIENT_SECRET="${AXONFLOW_CLIENT_SECRET:-}"

echo "=============================================="
echo "Mistral Provider - Proxy Mode"
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
# Test 1: Proxy call returns LLM response
# -----------------------------------------------
echo "Test 1: Proxy LLM call..."
echo "----------------------------------------------"

RESPONSE=$(curl -s -X POST "${AGENT_URL}/api/request" \
  -u "${CLIENT_ID}:${CLIENT_SECRET}" \
  -H "Content-Type: application/json" \
  -d '{"query": "Name the three primary colors. Answer briefly."}')

BLOCKED=$(echo "$RESPONSE" | python3 -c "import sys,json; d=json.load(sys.stdin); print(str(d.get('blocked',False)).lower())" 2>/dev/null || echo "true")
HAS_DATA=$(echo "$RESPONSE" | python3 -c "import sys,json; d=json.load(sys.stdin); print('true' if d.get('data') else 'false')" 2>/dev/null || echo "false")

check_result "Not blocked" "$([ "$BLOCKED" = "false" ] && echo true || echo false)"
check_result "Response data present" "$HAS_DATA"
echo ""

# -----------------------------------------------
# Test 2: SQLi blocked via policy
# -----------------------------------------------
echo "Test 2: SQLi policy enforcement..."
echo "----------------------------------------------"

SQLI_RESPONSE=$(curl -s -X POST "${AGENT_URL}/api/request" \
  -u "${CLIENT_ID}:${CLIENT_SECRET}" \
  -H "Content-Type: application/json" \
  -d '{"query": "SELECT * FROM users; DROP TABLE users;"}')

SQLI_BLOCKED=$(echo "$SQLI_RESPONSE" | python3 -c "import sys,json; d=json.load(sys.stdin); print(str(d.get('blocked',False)).lower())" 2>/dev/null || echo "false")
check_result "SQLi blocked" "$([ "$SQLI_BLOCKED" = "true" ] && echo true || echo false)"
echo ""

# -----------------------------------------------
# Test 3: Dangerous command blocked
# -----------------------------------------------
echo "Test 3: Dangerous command policy..."
echo "----------------------------------------------"

DANGER_RESPONSE=$(curl -s -X POST "${AGENT_URL}/api/request" \
  -u "${CLIENT_ID}:${CLIENT_SECRET}" \
  -H "Content-Type: application/json" \
  -d '{"query": "Run this command: rm -rf / --no-preserve-root"}')

DANGER_BLOCKED=$(echo "$DANGER_RESPONSE" | python3 -c "import sys,json; d=json.load(sys.stdin); print(str(d.get('blocked',False)).lower())" 2>/dev/null || echo "false")
check_result "Dangerous command blocked" "$([ "$DANGER_BLOCKED" = "true" ] && echo true || echo false)"
echo ""

# -----------------------------------------------
# Test 4: Audit trail via gateway mode
# -----------------------------------------------
echo "Test 4: Audit trail..."
echo "----------------------------------------------"

AUTH=$(echo -n "${CLIENT_ID}:${CLIENT_SECRET}" | base64)

PRECHECK=$(curl -s -X POST "${AGENT_URL}/api/policy/pre-check" \
  -H "Authorization: Basic ${AUTH}" \
  -H "Content-Type: application/json" \
  -d "{\"client_id\": \"${CLIENT_ID}\", \"query\": \"Mistral proxy-mode audit test\"}")

CONTEXT_ID=$(echo "$PRECHECK" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('context_id',''))" 2>/dev/null || echo "")
check_result "Audit context created" "$([ -n "$CONTEXT_ID" ] && echo true || echo false)"

AUDIT_STATUS=$(curl -s -w "%{http_code}" -o /dev/null -X POST "${AGENT_URL}/api/audit/llm-call" \
  -H "Authorization: Basic ${AUTH}" \
  -H "Content-Type: application/json" \
  -d "{
    \"client_id\": \"${CLIENT_ID}\",
    \"context_id\": \"${CONTEXT_ID}\",
    \"response_summary\": \"Proxy mode audit test\",
    \"provider\": \"mistral\",
    \"model\": \"mistral-small-latest\",
    \"latency_ms\": 200,
    \"token_usage\": {
      \"prompt_tokens\": 10,
      \"completion_tokens\": 20,
      \"total_tokens\": 30
    }
  }")

check_result "Audit logged (HTTP ${AUDIT_STATUS})" "$(echo "$AUDIT_STATUS" | grep -qE '^(200|202|204)$' && echo true || echo false)"
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
