#!/bin/bash
# MCP Connectors - HTTP API Example
#
# This example tests the MCP connector flow via the Orchestrator API.
# It sends MCP query requests through the orchestrator, which routes
# them to the agent and its registered connectors.
#
# Usage:
#   docker compose up -d  # Start AxonFlow
#   cd examples/mcp-connectors/http
#   ./mcp-connectors.sh
#
# What this demonstrates:
#   1. Query postgres connector via orchestrator routing
#   2. Query with different SQL statements
#   3. Verify orchestrator-to-agent routing works end-to-end

set -e

AGENT_URL="${AXONFLOW_AGENT_URL:-http://localhost:8080}"

echo "=============================================="
echo "MCP Connectors - HTTP API Example"
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

# Test 1: Query postgres connector via orchestrator
echo "Test 1: Query postgres connector via orchestrator..."
echo "----------------------------------------------"

RESPONSE=$(curl -s -X POST "${AGENT_URL}/api/v1/process" \
  -H "Content-Type: application/json" \
  -d '{
    "request_id": "mcp-http-test-1",
    "query": "SELECT 1 as test_value, '\''hello'\'' as test_message",
    "request_type": "mcp-query",
    "user": {
      "email": "test@example.com",
      "role": "user",
      "tenant_id": "default"
    },
    "client": {
      "id": "test-client",
      "tenant_id": "default"
    },
    "context": {
      "connector": "postgres",
      "params": {}
    }
  }')

echo "Response:"
echo "$RESPONSE" | python3 -m json.tool 2>/dev/null || echo "$RESPONSE"
echo ""

SUCCESS=$(echo "$RESPONSE" | python3 -c "import sys,json; print('true' if json.load(sys.stdin).get('success', False) else 'false')" 2>/dev/null || echo "false")
check_result "Test 1: MCP query through orchestrator" "$SUCCESS"

REQUEST_ID=$(echo "$RESPONSE" | python3 -c "import sys,json; r=json.load(sys.stdin).get('request_id',''); print('true' if r else 'false')" 2>/dev/null || echo "false")
check_result "Test 1: Request ID returned" "$REQUEST_ID"
echo ""

# Test 2: Query current timestamp via orchestrator
echo "Test 2: Query current timestamp..."
echo "----------------------------------------------"

RESPONSE=$(curl -s -X POST "${AGENT_URL}/api/v1/process" \
  -H "Content-Type: application/json" \
  -d '{
    "request_id": "mcp-http-test-2",
    "query": "SELECT NOW() as current_time, '\''AxonFlow MCP'\'' as source",
    "request_type": "mcp-query",
    "user": {
      "email": "test@example.com",
      "role": "user",
      "tenant_id": "default"
    },
    "client": {
      "id": "test-client",
      "tenant_id": "default"
    },
    "context": {
      "connector": "postgres",
      "params": {}
    }
  }')

echo "Response:"
echo "$RESPONSE" | python3 -m json.tool 2>/dev/null || echo "$RESPONSE"
echo ""

SUCCESS=$(echo "$RESPONSE" | python3 -c "import sys,json; print('true' if json.load(sys.stdin).get('success', False) else 'false')" 2>/dev/null || echo "false")
check_result "Test 2: Timestamp query succeeded" "$SUCCESS"
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
echo "API Summary:"
echo "  POST /api/v1/process  - Route MCP query through orchestrator"
echo "    request_type: mcp-query"
echo "    context.connector: postgres (or other registered connector)"
