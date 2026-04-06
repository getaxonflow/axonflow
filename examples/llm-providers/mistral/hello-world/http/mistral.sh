#!/bin/bash
# Mistral LLM Provider - Hello World Example (HTTP/cURL)
#
# Tests Mistral integration via Gateway Mode, Proxy Mode, and Streaming.
#
# VALIDATION: This example exits with code 1 if any assertion fails.
#
# Prerequisites:
#   docker compose up -d
#   export MISTRAL_API_KEY=your-api-key
#
# Usage:
#   ./mistral.sh

set -euo pipefail

AGENT_URL="${AXONFLOW_AGENT_URL:-${AXONFLOW_ENDPOINT:-http://localhost:8080}}"
CLIENT_ID="${AXONFLOW_CLIENT_ID:-community}"
CLIENT_SECRET="${AXONFLOW_CLIENT_SECRET:-}"
AUTH=$(echo -n "${CLIENT_ID}:${CLIENT_SECRET}" | base64)

if [ -z "${MISTRAL_API_KEY:-}" ]; then
    echo "FATAL: MISTRAL_API_KEY must be set"
    exit 1
fi

echo "=============================================="
echo "Mistral LLM Provider - Hello World"
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
# Test 1: Gateway Mode — Pre-check + LLM call + Audit
# -----------------------------------------------
echo "Test 1: Gateway Mode..."
echo "----------------------------------------------"

# 1a: Pre-check query with AxonFlow
PRECHECK=$(curl -s -X POST "${AGENT_URL}/api/policy/pre-check" \
  -H "Authorization: Basic ${AUTH}" \
  -H "Content-Type: application/json" \
  -d "{
    \"client_id\": \"${CLIENT_ID}\",
    \"query\": \"Explain what Mistral AI is in one sentence.\",
    \"context\": {
      \"provider\": \"mistral\",
      \"model\": \"mistral-small-latest\"
    }
  }")

CONTEXT_ID=$(echo "$PRECHECK" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('context_id',''))" 2>/dev/null || echo "")
APPROVED=$(echo "$PRECHECK" | python3 -c "import sys,json; d=json.load(sys.stdin); print('true' if d.get('approved') else 'false')" 2>/dev/null || echo "false")

check_result "Pre-check approved" "$APPROVED"
check_result "Context ID returned" "$([ -n "$CONTEXT_ID" ] && echo true || echo false)"

# 1b: Call Mistral directly
MISTRAL_RESPONSE=$(curl -s -X POST "https://api.mistral.ai/v1/chat/completions" \
  -H "Authorization: Bearer ${MISTRAL_API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "mistral-small-latest",
    "messages": [{"role": "user", "content": "Explain what Mistral AI is in one sentence."}],
    "max_tokens": 200
  }')

MISTRAL_CONTENT=$(echo "$MISTRAL_RESPONSE" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['choices'][0]['message']['content'][:100])" 2>/dev/null || echo "")
MISTRAL_TOKENS=$(echo "$MISTRAL_RESPONSE" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['usage']['total_tokens'])" 2>/dev/null || echo "0")
MISTRAL_MODEL=$(echo "$MISTRAL_RESPONSE" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('model',''))" 2>/dev/null || echo "")

check_result "Mistral returned content" "$([ -n "$MISTRAL_CONTENT" ] && echo true || echo false)"
check_result "Token usage tracked" "$([ "$MISTRAL_TOKENS" -gt 0 ] && echo true || echo false)"
check_result "Model is mistral" "$(echo "$MISTRAL_MODEL" | grep -q 'mistral' && echo true || echo false)"

# 1c: Audit the call
AUDIT_RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "${AGENT_URL}/api/audit/llm-call" \
  -H "Authorization: Basic ${AUTH}" \
  -H "Content-Type: application/json" \
  -d "{
    \"client_id\": \"${CLIENT_ID}\",
    \"context_id\": \"${CONTEXT_ID}\",
    \"response_summary\": \"Mistral gateway mode test\",
    \"provider\": \"mistral\",
    \"model\": \"${MISTRAL_MODEL}\",
    \"latency_ms\": 500,
    \"token_usage\": {
      \"prompt_tokens\": 20,
      \"completion_tokens\": 50,
      \"total_tokens\": 70
    }
  }")
AUDIT_STATUS=$(echo "$AUDIT_RESPONSE" | tail -1)
check_result "Audit logged (HTTP ${AUDIT_STATUS})" "$(echo "$AUDIT_STATUS" | grep -qE '^(200|202|204)$' && echo true || echo false)"
echo ""

# -----------------------------------------------
# Test 2: Proxy Mode — Request through AxonFlow
# -----------------------------------------------
echo "Test 2: Proxy Mode..."
echo "----------------------------------------------"

PROXY_RESPONSE=$(curl -s -X POST "${AGENT_URL}/api/request" \
  -u "${CLIENT_ID}:${CLIENT_SECRET}" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "What is 2 + 2? Answer with just the number."
  }')

PROXY_BLOCKED=$(echo "$PROXY_RESPONSE" | python3 -c "import sys,json; d=json.load(sys.stdin); print(str(d.get('blocked', False)).lower())" 2>/dev/null || echo "true")
PROXY_DATA=$(echo "$PROXY_RESPONSE" | python3 -c "
import sys, json
d = json.load(sys.stdin)
data = d.get('data', '')
if isinstance(data, dict):
    print(str(data.get('data', ''))[:100])
else:
    print(str(data)[:100])
" 2>/dev/null || echo "")

check_result "Proxy not blocked" "$([ "$PROXY_BLOCKED" = "false" ] && echo true || echo false)"
check_result "Proxy returned data" "$([ -n "$PROXY_DATA" ] && echo true || echo false)"
echo ""

# -----------------------------------------------
# Test 3: Streaming — SSE events
# -----------------------------------------------
echo "Test 3: Streaming..."
echo "----------------------------------------------"

STREAM_OUTPUT=$(curl -s -N -X POST "https://api.mistral.ai/v1/chat/completions" \
  -H "Authorization: Bearer ${MISTRAL_API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "mistral-small-latest",
    "messages": [{"role": "user", "content": "Count from 1 to 3."}],
    "max_tokens": 50,
    "stream": true
  }' 2>&1 | head -20)

HAS_DATA_LINES=$(echo "$STREAM_OUTPUT" | grep -c "^data: " || true)
HAS_DONE=$(echo "$STREAM_OUTPUT" | grep -c "\[DONE\]" || true)

check_result "Streaming returned data: lines (${HAS_DATA_LINES})" "$([ "$HAS_DATA_LINES" -gt 0 ] && echo true || echo false)"
check_result "Streaming ended with [DONE]" "$([ "$HAS_DONE" -gt 0 ] && echo true || echo false)"
echo ""

# -----------------------------------------------
# Test 4: Policy enforcement — SQLi blocked
# -----------------------------------------------
echo "Test 4: Policy enforcement..."
echo "----------------------------------------------"

SQLI_RESPONSE=$(curl -s -X POST "${AGENT_URL}/api/request" \
  -u "${CLIENT_ID}:${CLIENT_SECRET}" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "SELECT * FROM users; DROP TABLE users;"
  }')

SQLI_BLOCKED=$(echo "$SQLI_RESPONSE" | python3 -c "import sys,json; d=json.load(sys.stdin); print(str(d.get('blocked', False)).lower())" 2>/dev/null || echo "false")
check_result "SQLi query blocked" "$([ "$SQLI_BLOCKED" = "true" ] && echo true || echo false)"
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
