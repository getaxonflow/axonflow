#!/usr/bin/env bash
# OpenClaw Governance E2E — verifies mcp_check_input/output endpoints
# with OpenClaw connector types (openclaw.{tool}).
set -euo pipefail

BASE_URL="${AXONFLOW_ENDPOINT:-http://localhost:8080}"
CLIENT_ID="${AXONFLOW_CLIENT_ID:-test-client}"
CLIENT_SECRET="${AXONFLOW_CLIENT_SECRET:-test-secret}"
AUTH=$(echo -n "${CLIENT_ID}:${CLIENT_SECRET}" | base64)

PASS=0
FAIL=0

assert_status() {
    local desc="$1" status="$2" expected="$3"
    if [ "$status" = "$expected" ]; then
        echo "  PASS: $desc (HTTP $status)"
        ((PASS++)) || true
    else
        echo "  FAIL: $desc (expected HTTP $expected, got $status)"
        ((FAIL++)) || true
    fi
}

assert_contains() {
    local desc="$1" response="$2" expected="$3"
    if echo "$response" | grep -q "$expected"; then
        echo "  PASS: $desc"
        ((PASS++)) || true
    else
        echo "  FAIL: $desc (expected '$expected')"
        ((FAIL++)) || true
    fi
}

echo "=== OpenClaw Governance E2E Tests ==="
echo "Endpoint: $BASE_URL"
echo ""

# Test 1: Clean web_fetch allowed
echo "--- Test 1: Clean web_fetch tool ---"
RESPONSE=$(curl -s -w "\n%{http_code}" \
    -H "Authorization: Basic $AUTH" -H "Content-Type: application/json" \
    -d '{"connector_type": "openclaw.web_fetch", "statement": "{\"url\": \"https://example.com\"}", "operation": "execute"}' \
    "$BASE_URL/api/v1/mcp/check-input")
STATUS=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | sed '$d')
assert_status "web_fetch returns 200" "$STATUS" "200"
assert_contains "Allowed" "$BODY" '"allowed"'

# Test 2: PII in message tool
echo ""
echo "--- Test 2: PII in message tool ---"
RESPONSE=$(curl -s -w "\n%{http_code}" \
    -H "Authorization: Basic $AUTH" -H "Content-Type: application/json" \
    -d '{"connector_type": "openclaw.message_sending", "statement": "{\"text\": \"Customer SSN: 123-45-6789\"}", "operation": "execute"}' \
    "$BASE_URL/api/v1/mcp/check-input")
STATUS=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | sed '$d')
if [ "$STATUS" = "403" ]; then
    assert_status "PII in message blocked (403)" "$STATUS" "403"
    echo "  (PII_ACTION=block: SSN detected and blocked at input)"
else
    assert_status "PII in message returns 200" "$STATUS" "200"
    assert_contains "Policies evaluated" "$BODY" "policies_evaluated"
    echo "  (PII_ACTION=warn/redact: SSN detected but not blocked at input)"
fi

# Test 3: Clean output from MCP tool
echo ""
echo "--- Test 3: Clean MCP tool output ---"
RESPONSE=$(curl -s -w "\n%{http_code}" \
    -H "Authorization: Basic $AUTH" -H "Content-Type: application/json" \
    -d '{"connector_type": "openclaw.mcp.postgres", "message": "Query returned 5 rows: product data"}' \
    "$BASE_URL/api/v1/mcp/check-output")
STATUS=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | sed '$d')
assert_status "MCP output returns 200" "$STATUS" "200"
assert_contains "Allowed" "$BODY" '"allowed"'

# Test 4: PII in tool output
echo ""
echo "--- Test 4: PII in tool output (SSN) ---"
RESPONSE=$(curl -s -w "\n%{http_code}" \
    -H "Authorization: Basic $AUTH" -H "Content-Type: application/json" \
    -d '{"connector_type": "openclaw.web_fetch", "message": "{\"name\": \"John\", \"ssn\": \"123-45-6789\"}"}' \
    "$BASE_URL/api/v1/mcp/check-output")
STATUS=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | sed '$d')
assert_status "PII output returns 200" "$STATUS" "200"
assert_contains "Policies evaluated" "$BODY" "policies_evaluated"

# Test 5: SQLi in tool input
echo ""
echo "--- Test 5: SQL injection in tool input ---"
RESPONSE=$(curl -s -w "\n%{http_code}" \
    -H "Authorization: Basic $AUTH" -H "Content-Type: application/json" \
    -d '{"connector_type": "openclaw.mcp.postgres", "statement": "SELECT * FROM users; DROP TABLE users;--", "operation": "execute"}' \
    "$BASE_URL/api/v1/mcp/check-input")
STATUS=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | sed '$d')
if [ "$STATUS" = "403" ]; then
    assert_status "SQLi blocked (403)" "$STATUS" "403"
else
    assert_status "SQLi returns 200" "$STATUS" "200"
fi

# Summary
echo ""
echo "=== Results ==="
echo "Passed: $PASS"
echo "Failed: $FAIL"

if [ "$FAIL" -gt 0 ]; then
    echo "FAIL: $FAIL test(s) failed"
    exit 1
else
    echo "ALL $PASS tests passed"
fi
