#!/usr/bin/env bash
# Decision Mode MCP Gateway PoC test harness.
# Validates: allow/deny verdicts, trace_id propagation, JSON-RPC error shape,
# and that denied requests never reach the mock MCP server.
#
# Prerequisites: docker compose up -d --build (all 3 services healthy)

set -euo pipefail

ADAPTER_URL="${MCP_ADAPTER_URL:-http://localhost:9090}"
MOCK_MCP_URL="${MOCK_MCP_URL:-http://localhost:9091}"

PASS=0
FAIL=0

pass() { PASS=$((PASS + 1)); echo "  PASS: $1"; }
fail() { FAIL=$((FAIL + 1)); echo "  FAIL: $1"; }

assert_eq() {
  local actual="$1" expected="$2" label="$3"
  if [ "$actual" = "$expected" ]; then
    pass "$label"
  else
    fail "$label (expected='$expected', got='$actual')"
  fi
}

assert_contains() {
  local haystack="$1" needle="$2" label="$3"
  if echo "$haystack" | grep -q "$needle"; then
    pass "$label"
  else
    fail "$label (expected to contain '$needle')"
  fi
}

assert_not_empty() {
  local val="$1" label="$2"
  if [ -n "$val" ] && [ "$val" != "null" ]; then
    pass "$label"
  else
    fail "$label (was empty or null)"
  fi
}

# Wait for services.
echo "Waiting for services..."
for i in $(seq 1 30); do
  if curl -sf "$ADAPTER_URL/health" >/dev/null 2>&1 && \
     curl -sf "$MOCK_MCP_URL/health" >/dev/null 2>&1; then
    echo "Services healthy."
    break
  fi
  if [ "$i" -eq 30 ]; then
    echo "FATAL: services not healthy after 30s"
    exit 1
  fi
  sleep 1
done

# Reset mock MCP request counter baseline.
BASELINE_COUNT=$(curl -sf "$MOCK_MCP_URL/request-count" | python3 -c "import sys,json; print(json.load(sys.stdin)['count'])" 2>/dev/null || echo "0")

# -------------------------------------------------------------------
# Test 1: Clean tool call (lookup_transaction) -> allow, forwarded
# -------------------------------------------------------------------
echo ""
echo "Test 1: Clean tool call — payments.lookup_transaction"
RESP=$(curl -sf -w "\n%{http_code}" -H "Content-Type: application/json" "$ADAPTER_URL" -d '{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "payments.lookup_transaction",
    "arguments": {"customer_id": "C-456", "last": true}
  }
}')
HTTP_CODE=$(echo "$RESP" | tail -1)
BODY=$(echo "$RESP" | sed '$d')

assert_eq "$HTTP_CODE" "200" "HTTP 200 on clean tool call"

RESULT=$(echo "$BODY" | python3 -c "import sys,json; r=json.load(sys.stdin); print('has_result' if 'result' in r and r.get('error') is None else 'no_result')")
assert_eq "$RESULT" "has_result" "response contains result (not error)"

ERROR_CHECK=$(echo "$BODY" | python3 -c "import sys,json; print('no_error' if json.load(sys.stdin).get('error') is None else 'has_error')")
assert_eq "$ERROR_CHECK" "no_error" "no JSON-RPC error on clean call"

# -------------------------------------------------------------------
# Test 2: SQLi in arguments -> deny, blocked before reaching mock
# -------------------------------------------------------------------
echo ""
echo "Test 2: SQL injection in tool arguments"
COUNT_BEFORE=$(curl -sf "$MOCK_MCP_URL/request-count" | python3 -c "import sys,json; print(json.load(sys.stdin)['count'])")

RESP=$(curl -sf -w "\n%{http_code}" -H "Content-Type: application/json" "$ADAPTER_URL" -d '{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "tools/call",
  "params": {
    "name": "payments.lookup_transaction",
    "arguments": {"customer_id": "C-456; SELECT * FROM users UNION SELECT password FROM credentials --"}
  }
}')
HTTP_CODE=$(echo "$RESP" | tail -1)
BODY=$(echo "$RESP" | sed '$d')

assert_eq "$HTTP_CODE" "200" "HTTP 200 (JSON-RPC error, not HTTP error)"

HAS_ERROR=$(echo "$BODY" | python3 -c "import sys,json; r=json.load(sys.stdin); print('yes' if r.get('error') else 'no')")
assert_eq "$HAS_ERROR" "yes" "JSON-RPC error present on SQLi"

ERROR_CODE=$(echo "$BODY" | python3 -c "import sys,json; print(json.load(sys.stdin)['error']['code'])")
assert_eq "$ERROR_CODE" "-32001" "JSON-RPC error code -32001 (policy deny)"

TRACE_IN_BODY=$(echo "$BODY" | python3 -c "
import sys,json
r = json.load(sys.stdin)
data = r.get('error',{}).get('data')
if data:
    if isinstance(data, str):
        d = json.loads(data)
    else:
        d = data
    print(d.get('trace_id',''))
else:
    print('')
")
assert_not_empty "$TRACE_IN_BODY" "trace_id in JSON-RPC error data"

COUNT_AFTER=$(curl -sf "$MOCK_MCP_URL/request-count" | python3 -c "import sys,json; print(json.load(sys.stdin)['count'])")
assert_eq "$COUNT_AFTER" "$COUNT_BEFORE" "mock MCP request count unchanged (blocked before reaching server)"

# -------------------------------------------------------------------
# Test 3: PII (SSN) in arguments -> deny
# -------------------------------------------------------------------
echo ""
echo "Test 3: PII (SSN) in tool arguments"
RESP=$(curl -sf -w "\n%{http_code}" -H "Content-Type: application/json" "$ADAPTER_URL" -d '{
  "jsonrpc": "2.0",
  "id": 3,
  "method": "tools/call",
  "params": {
    "name": "payments.process_refund",
    "arguments": {"transaction_id": "TXN-001", "amount": 50.00, "reason": "Customer SSN 123-45-6789 verified for identity"}
  }
}')
HTTP_CODE=$(echo "$RESP" | tail -1)
BODY=$(echo "$RESP" | sed '$d')

assert_eq "$HTTP_CODE" "200" "HTTP 200 on PII test"
HAS_ERROR=$(echo "$BODY" | python3 -c "import sys,json; r=json.load(sys.stdin); print('yes' if r.get('error') else 'no')")
assert_eq "$HAS_ERROR" "yes" "JSON-RPC error present on PII"

# -------------------------------------------------------------------
# Test 4: trace_id in all responses (check X-Trace-Id header)
# -------------------------------------------------------------------
echo ""
echo "Test 4: trace_id in response headers"
HEADERS=$(curl -sf -D - -o /dev/null -H "Content-Type: application/json" "$ADAPTER_URL" -d '{
  "jsonrpc": "2.0",
  "id": 4,
  "method": "tools/call",
  "params": {
    "name": "payments.lookup_transaction",
    "arguments": {"customer_id": "C-789"}
  }
}')
TRACE_HEADER=$(echo "$HEADERS" | grep -i "x-trace-id" | tr -d '\r' | head -1)
assert_not_empty "$TRACE_HEADER" "X-Trace-Id header present on allow response"

# -------------------------------------------------------------------
# Test 5: JSON-RPC error shape on deny (not bare HTTP 403)
# -------------------------------------------------------------------
echo ""
echo "Test 5: JSON-RPC error shape validation"
RESP=$(curl -sf -w "\n%{http_code}" -H "Content-Type: application/json" "$ADAPTER_URL" -d '{
  "jsonrpc": "2.0",
  "id": 5,
  "method": "tools/call",
  "params": {
    "name": "payments.process_refund",
    "arguments": {"transaction_id": "TXN-001", "amount": 999, "reason": "DROP TABLE transactions; --"}
  }
}')
HTTP_CODE=$(echo "$RESP" | tail -1)
BODY=$(echo "$RESP" | sed '$d')

assert_eq "$HTTP_CODE" "200" "deny returns HTTP 200 (not 403)"

JSONRPC_VER=$(echo "$BODY" | python3 -c "import sys,json; print(json.load(sys.stdin).get('jsonrpc',''))")
assert_eq "$JSONRPC_VER" "2.0" "response has jsonrpc: 2.0"

HAS_ID=$(echo "$BODY" | python3 -c "import sys,json; print('yes' if json.load(sys.stdin).get('id') is not None else 'no')")
assert_eq "$HAS_ID" "yes" "response echoes request id"

ERROR_MSG=$(echo "$BODY" | python3 -c "import sys,json; print(json.load(sys.stdin).get('error',{}).get('message',''))")
assert_not_empty "$ERROR_MSG" "error.message is non-empty"

# -------------------------------------------------------------------
# Test 6: Non-intercepted method (tools/list) passes through
# -------------------------------------------------------------------
echo ""
echo "Test 6: Non-intercepted method passthrough"
RESP=$(curl -sf -w "\n%{http_code}" -H "Content-Type: application/json" "$ADAPTER_URL" -d '{
  "jsonrpc": "2.0",
  "id": 6,
  "method": "tools/list",
  "params": {}
}')
HTTP_CODE=$(echo "$RESP" | tail -1)
BODY=$(echo "$RESP" | sed '$d')

assert_eq "$HTTP_CODE" "200" "HTTP 200 on tools/list passthrough"

HAS_TOOLS=$(echo "$BODY" | python3 -c "import sys,json; r=json.load(sys.stdin); print('yes' if 'result' in r else 'no')")
assert_eq "$HAS_TOOLS" "yes" "tools/list result returned from mock"

# -------------------------------------------------------------------
# Test 7: Traceparent propagation (inbound -> Decision API -> downstream)
# -------------------------------------------------------------------
echo ""
echo "Test 7: Traceparent header propagation"
CUSTOM_TRACE="00-aabbccdd11223344aabbccdd11223344-0000000000000001-01"
RESP=$(curl -sf -D - -H "Content-Type: application/json" -H "Traceparent: $CUSTOM_TRACE" "$ADAPTER_URL" -d '{
  "jsonrpc": "2.0",
  "id": 7,
  "method": "tools/call",
  "params": {
    "name": "payments.lookup_transaction",
    "arguments": {"customer_id": "C-trace-test"}
  }
}')
TRACE_HEADER=$(echo "$RESP" | grep -i "x-trace-id" | tr -d '\r' | head -1)
assert_not_empty "$TRACE_HEADER" "X-Trace-Id header present with custom traceparent"

# -------------------------------------------------------------------
# Summary
# -------------------------------------------------------------------
echo ""
echo "================================"
echo "PASS=$PASS FAIL=$FAIL SKIP=0"
echo "================================"

if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
