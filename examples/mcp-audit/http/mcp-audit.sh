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
#   2. Execute MCP query with PII (triggers redaction + audit)
#   3. Query audit logs to verify persistence

set -e

AGENT_URL="${AGENT_URL:-http://localhost:8080}"
CLIENT_ID="${CLIENT_ID:-demo-client}"
CLIENT_SECRET="${CLIENT_SECRET:-demo-secret}"

# Create Basic auth header
AUTH_HEADER="Authorization: Basic $(echo -n "${CLIENT_ID}:${CLIENT_SECRET}" | base64)"

echo "=============================================="
echo "MCP Audit Logging - HTTP API Example"
echo "=============================================="
echo "Agent URL: $AGENT_URL"
echo ""

# Test 1: Execute simple MCP query (creates audit entry)
echo "Test 1: Execute simple MCP query..."
echo "----------------------------------------------"

RESPONSE=$(curl -s -X POST "${AGENT_URL}/mcp/resources/query" \
  -H "Content-Type: application/json" \
  -H "$AUTH_HEADER" \
  -d '{
    "connector": "postgres",
    "statement": "SELECT 1 as test_value, '\''hello'\'' as test_message"
  }')

echo "Response:"
echo "$RESPONSE" | python3 -m json.tool 2>/dev/null || echo "$RESPONSE"
echo ""

# Check if successful
if echo "$RESPONSE" | grep -q '"success":true'; then
  echo "SUCCESS: Query executed and audit logged"
else
  echo "Note: Query may have failed (expected if postgres not configured)"
fi
echo ""

# Test 2: Execute query that contains PII-like data (triggers policy evaluation)
echo "Test 2: Execute query with PII detection..."
echo "----------------------------------------------"

RESPONSE=$(curl -s -X POST "${AGENT_URL}/mcp/resources/query" \
  -H "Content-Type: application/json" \
  -H "$AUTH_HEADER" \
  -d '{
    "connector": "postgres",
    "statement": "SELECT email, name FROM users LIMIT 5"
  }')

echo "Response:"
echo "$RESPONSE" | python3 -m json.tool 2>/dev/null || echo "$RESPONSE"
echo ""

# Check for policy_info in response
if echo "$RESPONSE" | grep -q '"policy_info"'; then
  echo "SUCCESS: Policy info included in response"
  echo "  This shows policies were evaluated and results are audited"
fi
echo ""

# Test 3: Try to trigger SQLi detection (should be blocked)
echo "Test 3: Execute query with SQLi pattern (should be blocked)..."
echo "----------------------------------------------"

RESPONSE=$(curl -s -X POST "${AGENT_URL}/mcp/resources/query" \
  -H "Content-Type: application/json" \
  -H "$AUTH_HEADER" \
  -d '{
    "connector": "postgres",
    "statement": "SELECT * FROM users; DROP TABLE users;--"
  }')

echo "Response:"
echo "$RESPONSE" | python3 -m json.tool 2>/dev/null || echo "$RESPONSE"
echo ""

# Check if blocked
if echo "$RESPONSE" | grep -q '"error"'; then
  echo "SUCCESS: SQLi attempt was blocked and audit logged"
fi
echo ""

# Test 4: Execute command (INSERT) operation
echo "Test 4: Execute INSERT operation..."
echo "----------------------------------------------"

RESPONSE=$(curl -s -X POST "${AGENT_URL}/mcp/tools/execute" \
  -H "Content-Type: application/json" \
  -H "$AUTH_HEADER" \
  -d '{
    "connector": "postgres",
    "action": "INSERT",
    "statement": "INSERT INTO audit_test (name) VALUES ('\''test'\'')"
  }')

echo "Response:"
echo "$RESPONSE" | python3 -m json.tool 2>/dev/null || echo "$RESPONSE"
echo ""

echo "=============================================="
echo "MCP Audit Logging Tests Complete!"
echo "=============================================="
echo ""
echo "To verify audit entries in the database:"
echo "  docker compose exec postgres psql -U axonflow -d axonflow \\"
echo "    -c \"SELECT audit_id, connector_name, operation, request_blocked, response_redacted, success FROM mcp_query_audits ORDER BY created_at DESC LIMIT 5\""
