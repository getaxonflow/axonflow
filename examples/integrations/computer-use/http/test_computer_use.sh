#!/usr/bin/env bash
# Computer Use Governance E2E — verifies mcp_check_input/output endpoints
# with Computer Use connector types.
set -euo pipefail

BASE_URL="${AXONFLOW_ENDPOINT:-http://localhost:8080}"
CLIENT_ID="${AXONFLOW_CLIENT_ID:-community}"
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

call_check_input() {
    local connector_type="$1" tool="$2" statement="$3"
    local body
    # SDK 9.0.0 two-field identity: connector_type="computer_use" + separate tool
    # (computer/bash/text_editor); the action stays in the statement.
    body=$(jq -n --arg ct "$connector_type" --arg tool "$tool" --arg stmt "$statement" \
        '{connector_type: $ct, tool: $tool, statement: $stmt, operation: "execute"}')
    curl -s -w "\n%{http_code}" \
        -H "Authorization: Basic $AUTH" \
        -H "Content-Type: application/json" \
        -d "$body" \
        "$BASE_URL/api/v1/mcp/check-input"
}

call_check_output() {
    local connector_type="$1" tool="$2" message="$3"
    local body
    body=$(jq -n --arg ct "$connector_type" --arg tool "$tool" --arg msg "$message" \
        '{connector_type: $ct, tool: $tool, message: $msg}')
    curl -s -w "\n%{http_code}" \
        -H "Authorization: Basic $AUTH" \
        -H "Content-Type: application/json" \
        -d "$body" \
        "$BASE_URL/api/v1/mcp/check-output"
}

echo "=== Computer Use Governance E2E Tests ==="
echo "Endpoint: $BASE_URL"
echo ""

# Test 1: Screenshot action allowed
echo "--- Test 1: Screenshot action ---"
RESPONSE=$(call_check_input "computer_use" "computer" '{"action": "screenshot"}')
STATUS=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | sed '$d')
assert_status "Screenshot returns 200" "$STATUS" "200"
assert_contains "Allowed" "$BODY" '"allowed"'

# Test 2: Bash clean command allowed
echo ""
echo "--- Test 2: Clean bash command ---"
RESPONSE=$(call_check_input "computer_use" "bash" '{"command": "ls -la /tmp"}')
STATUS=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | sed '$d')
assert_status "Clean bash returns 200" "$STATUS" "200"
assert_contains "Allowed" "$BODY" '"allowed"'

# Test 3: SQLi in bash blocked
echo ""
echo "--- Test 3: SQL injection in tool input ---"
RESPONSE=$(call_check_input "computer_use" "bash" '{"command": "SELECT * FROM users; DROP TABLE users;--"}')
STATUS=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | sed '$d')
if [ "$STATUS" = "403" ]; then
    assert_status "SQLi returns 403" "$STATUS" "403"
else
    assert_status "SQLi returns 200" "$STATUS" "200"
    assert_contains "Policies evaluated" "$BODY" "policies_evaluated"
fi

# Test 4: Clean output allowed
echo ""
echo "--- Test 4: Clean output ---"
RESPONSE=$(call_check_output "computer_use" "bash" '"Command output: file1.txt file2.txt"')
STATUS=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | sed '$d')
assert_status "Clean output returns 200" "$STATUS" "200"

# Test 5: PII in output
echo ""
echo "--- Test 5: PII in output ---"
RESPONSE=$(call_check_output "computer_use" "bash" '"{\"name\": \"John\", \"ssn\": \"123-45-6789\"}"')
STATUS=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | sed '$d')
assert_status "PII output returns 200" "$STATUS" "200"
assert_contains "Policies evaluated" "$BODY" "policies_evaluated"

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
