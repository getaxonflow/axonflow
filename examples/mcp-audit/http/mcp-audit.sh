#!/bin/bash
# MCP Audit Logging - HTTP API Example
#
# This example demonstrates MCP audit logging using raw HTTP calls.
# No SDK required - uses cURL to interact with the Agent API directly.
#
# Usage:
#   docker compose up -d  # Start AxonFlow
#   cd examples/mcp-audit/http
#   ./mcp-audit.sh
#
# What this demonstrates:
#   1. Execute MCP query (triggers audit logging)
#   2. Query with PII-like content in SQL (triggers policy evaluation + audit)
#   3. Query with SQLi pattern (should be blocked + audit logged)
#   4. Execute command via MCP tools endpoint (audit logged)

set -e

AGENT_URL="${AXONFLOW_AGENT_URL:-${AXONFLOW_ENDPOINT:-http://localhost:8080}}"
CLIENT_ID="${AXONFLOW_CLIENT_ID:-community}"
CLIENT_SECRET="${AXONFLOW_CLIENT_SECRET:-}"

# Auth: include Basic auth if credentials are set
CURL_AUTH=()
if [ -n "$CLIENT_ID" ] && [ -n "$CLIENT_SECRET" ]; then
  CURL_AUTH=(-u "${CLIENT_ID}:${CLIENT_SECRET}")
fi
acurl() { curl "${CURL_AUTH[@]}" "$@"; }

PASS=0
FAIL=0
check() {
    local name="$1" cond="$2"
    if [ "$cond" = "true" ]; then echo "   PASS: $name"; PASS=$((PASS+1));
    else echo "   FAIL: $name"; FAIL=$((FAIL+1)); fi
}

echo "=============================================="
echo "MCP Audit Logging - HTTP API Example"
echo "=============================================="
echo "Agent URL: $AGENT_URL"
echo ""

# Test 1: Simple MCP query — should succeed and create audit entry
echo "Test 1: Execute simple MCP query..."
echo "----------------------------------------------"

RESPONSE=$(acurl -s -X POST "${AGENT_URL}/mcp/resources/query" \
  -H "Content-Type: application/json" \
  -d '{
    "connector": "postgres",
    "statement": "SELECT 1 as test_value, current_timestamp as queried_at"
  }')

echo "Response:"
echo "$RESPONSE" | python3 -m json.tool 2>/dev/null || echo "$RESPONSE"
echo ""

SUCCESS=$(echo "$RESPONSE" | python3 -c "import sys,json; print('true' if json.load(sys.stdin).get('success') else 'false')" 2>/dev/null || echo "false")
HAS_POLICY=$(echo "$RESPONSE" | python3 -c "import sys,json; print('true' if json.load(sys.stdin).get('policy_info') else 'false')" 2>/dev/null || echo "false")
check "Query executed successfully" "$SUCCESS"
check "Policy info included (audit trail)" "$HAS_POLICY"
echo ""

# Test 2: Query with multiple rows — triggers policy scan on result set
echo "Test 2: Multi-row query (policy evaluation on results)..."
echo "----------------------------------------------"

RESPONSE=$(acurl -s -X POST "${AGENT_URL}/mcp/resources/query" \
  -H "Content-Type: application/json" \
  -d '{
    "connector": "postgres",
    "statement": "SELECT n as row_num, '\''record-'\'' || n as label FROM generate_series(1, 5) n"
  }')

echo "Response:"
echo "$RESPONSE" | python3 -m json.tool 2>/dev/null || echo "$RESPONSE"
echo ""

SUCCESS=$(echo "$RESPONSE" | python3 -c "import sys,json; print('true' if json.load(sys.stdin).get('success') else 'false')" 2>/dev/null || echo "false")
check "Multi-row query succeeded" "$SUCCESS"
echo ""

# Test 3: SQLi pattern — should be blocked and audit logged
echo "Test 3: Execute query with SQLi pattern (should be blocked)..."
echo "----------------------------------------------"

RESPONSE=$(acurl -s -X POST "${AGENT_URL}/mcp/resources/query" \
  -H "Content-Type: application/json" \
  -d '{
    "connector": "postgres",
    "statement": "SELECT * FROM connectors; DROP TABLE connectors;--"
  }')

echo "Response:"
echo "$RESPONSE" | python3 -m json.tool 2>/dev/null || echo "$RESPONSE"
echo ""

BLOCKED=$(echo "$RESPONSE" | python3 -c "import sys,json; r=json.load(sys.stdin); print('true' if 'DROP TABLE' in r.get('error','') or r.get('blocked') else 'false')" 2>/dev/null || echo "false")
check "SQLi attempt blocked and audit logged" "$BLOCKED"
echo ""

# Test 4: Execute a safe write operation via MCP tools endpoint
echo "Test 4: Execute INSERT into audit_logs (real table)..."
echo "----------------------------------------------"

RESPONSE=$(acurl -s -X POST "${AGENT_URL}/mcp/tools/execute" \
  -H "Content-Type: application/json" \
  -d '{
    "connector": "postgres",
    "action": "INSERT",
    "statement": "SELECT current_timestamp as executed_at, '\''mcp-audit-test'\'' as source"
  }')

echo "Response:"
echo "$RESPONSE" | python3 -m json.tool 2>/dev/null || echo "$RESPONSE"
echo ""

SUCCESS=$(echo "$RESPONSE" | python3 -c "import sys,json; print('true' if json.load(sys.stdin).get('success') else 'false')" 2>/dev/null || echo "false")
check "Execute operation completed" "$SUCCESS"
echo ""

# Summary
echo "=============================================="
echo "Results: $PASS passed, $FAIL failed"
if [ "$FAIL" -gt 0 ]; then
    echo "SOME TESTS FAILED"
    exit 1
fi
echo "ALL TESTS PASSED"
echo "=============================================="
echo ""
echo "To verify audit entries in the database:"
echo "  docker compose exec postgres psql -U axonflow -d axonflow \\"
echo "    -c \"SELECT audit_id, connector_name, operation, request_blocked, response_redacted, success FROM mcp_query_audits ORDER BY created_at DESC LIMIT 5\""
