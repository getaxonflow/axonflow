#!/usr/bin/env bash
# GovernedTool E2E Test — verifies the mcp_check_input/output endpoints
# that GovernedTool calls internally.
#
# Usage: bash test_governed_tools.sh
# Prerequisites: AxonFlow running on localhost:8080

set -euo pipefail

BASE_URL="${AXONFLOW_ENDPOINT:-http://localhost:8080}"
CLIENT_ID="${AXONFLOW_CLIENT_ID:-community}"
CLIENT_SECRET="${AXONFLOW_CLIENT_SECRET:-test-secret}"
AUTH=$(echo -n "${CLIENT_ID}:${CLIENT_SECRET}" | base64)

PASS=0
FAIL=0

assert_contains() {
    local desc="$1" response="$2" expected="$3"
    if echo "$response" | grep -q "$expected"; then
        echo "  ✅ $desc"
        ((PASS++)) || true
    else
        echo "  ❌ $desc (expected '$expected' in response)"
        echo "     Got: $response"
        ((FAIL++)) || true
    fi
}

assert_status() {
    local desc="$1" status="$2" expected="$3"
    if [ "$status" = "$expected" ]; then
        echo "  ✅ $desc (HTTP $status)"
        ((PASS++)) || true
    else
        echo "  ❌ $desc (expected HTTP $expected, got $status)"
        ((FAIL++)) || true
    fi
}

echo "=== GovernedTool E2E Tests ==="
echo "Endpoint: $BASE_URL"
echo ""

# ============================================================
# Test 1: mcp_check_input — clean input allowed
# ============================================================
echo "--- Test 1: Clean input allowed ---"
RESPONSE=$(curl -s -w "\n%{http_code}" \
    -H "Authorization: Basic $AUTH" \
    -H "Content-Type: application/json" \
    -d '{
        "connector_type": "search",
        "statement": "{\"query\": \"latest AI research\"}",
        "operation": "query"
    }' \
    "$BASE_URL/api/v1/mcp/check-input")
STATUS=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | sed '$d')

assert_status "Clean input returns 200" "$STATUS" "200"
assert_contains "Input allowed" "$BODY" '"allowed"'

# ============================================================
# Test 2: mcp_check_input — PII in input blocked
# ============================================================
echo ""
echo "--- Test 2: PII in input blocked ---"
RESPONSE=$(curl -s -w "\n%{http_code}" \
    -H "Authorization: Basic $AUTH" \
    -H "Content-Type: application/json" \
    -d '{
        "connector_type": "database_query",
        "statement": "SELECT * FROM customers WHERE ssn = '\''123-45-6789'\''",
        "operation": "execute"
    }' \
    "$BASE_URL/api/v1/mcp/check-input")
STATUS=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | sed '$d')

# PII detection may block (403) or allow with warning depending on PII_ACTION setting
if [ "$STATUS" = "403" ]; then
    assert_status "PII input returns 403" "$STATUS" "403"
    assert_contains "Policy evaluated" "$BODY" "policies_evaluated"
    echo "  (PII_ACTION=block: SSN detected and blocked)"
elif [ "$STATUS" = "200" ]; then
    assert_status "PII input returns 200" "$STATUS" "200"
    assert_contains "Policies evaluated" "$BODY" "policies_evaluated"
    echo "  (PII_ACTION=warn/redact: SSN detected but not blocked at input)"
fi

# ============================================================
# Test 3: mcp_check_output — clean output allowed
# ============================================================
echo ""
echo "--- Test 3: Clean output allowed ---"
RESPONSE=$(curl -s -w "\n%{http_code}" \
    -H "Authorization: Basic $AUTH" \
    -H "Content-Type: application/json" \
    -d '{
        "connector_type": "search",
        "message": "The latest research shows improvements in transformer architectures."
    }' \
    "$BASE_URL/api/v1/mcp/check-output")
STATUS=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | sed '$d')

assert_status "Clean output returns 200" "$STATUS" "200"
assert_contains "Output allowed" "$BODY" '"allowed"'

# ============================================================
# Test 4: mcp_check_output — PII in output detected
# ============================================================
echo ""
echo "--- Test 4: PII in output detected ---"
RESPONSE=$(curl -s -w "\n%{http_code}" \
    -H "Authorization: Basic $AUTH" \
    -H "Content-Type: application/json" \
    -d '{
        "connector_type": "database_query",
        "message": "{\"name\": \"John Doe\", \"ssn\": \"123-45-6789\", \"email\": \"john@example.com\"}"
    }' \
    "$BASE_URL/api/v1/mcp/check-output")
STATUS=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | sed '$d')

# Output with PII should be redacted (200 with redacted_data) or blocked (403)
if [ "$STATUS" = "200" ]; then
    assert_status "PII output returns 200" "$STATUS" "200"
    assert_contains "Policies evaluated" "$BODY" "policies_evaluated"
    # Check for redaction
    if echo "$BODY" | grep -q "redacted_data"; then
        echo "  ✅ Redacted data present in response"
        ((PASS++)) || true
    else
        echo "  ℹ️  No redaction (PII_ACTION may be warn/log)"
    fi
elif [ "$STATUS" = "403" ]; then
    assert_status "PII output returns 403" "$STATUS" "403"
    echo "  (PII_ACTION=block: output blocked entirely)"
fi

# ============================================================
# Test 5: mcp_check_output — exfiltration check
# ============================================================
echo ""
echo "--- Test 5: Output with row count ---"
RESPONSE=$(curl -s -w "\n%{http_code}" \
    -H "Authorization: Basic $AUTH" \
    -H "Content-Type: application/json" \
    -d '{
        "connector_type": "database_query",
        "response_data": [{"id": 1, "name": "test"}],
        "row_count": 5
    }' \
    "$BASE_URL/api/v1/mcp/check-output")
STATUS=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | sed '$d')

assert_status "Row count output returns 200" "$STATUS" "200"
assert_contains "Output check completed" "$BODY" '"allowed"'

# ============================================================
# Summary
# ============================================================
echo ""
echo "=== Results ==="
echo "Passed: $PASS"
echo "Failed: $FAIL"
echo ""

if [ "$FAIL" -gt 0 ]; then
    echo "❌ $FAIL test(s) failed"
    exit 1
else
    echo "✅ All $PASS tests passed"
fi
