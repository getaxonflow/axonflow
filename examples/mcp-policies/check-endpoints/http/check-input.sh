#!/bin/bash
# MCP Check-Input Endpoint Examples
#
# Validates MCP requests against policies WITHOUT executing the query.
# Use this when an external orchestrator (LangGraph, CrewAI) manages
# MCP execution but needs AxonFlow as a policy gate.
#
# Prerequisites:
#   - Docker Compose running: docker-compose up -d
#   - MCP_STATIC_POLICIES_ENABLED=true (default)

set -e

AGENT_URL="${AXONFLOW_AGENT_URL:-http://localhost:8080}"

# Auth: include Basic auth if credentials are set
CURL_AUTH=()
if [ -n "${AXONFLOW_CLIENT_ID:-}" ] && [ -n "${AXONFLOW_CLIENT_SECRET:-}" ]; then
  CURL_AUTH=(-u "${AXONFLOW_CLIENT_ID}:${AXONFLOW_CLIENT_SECRET}")
fi
acurl() { curl "${CURL_AUTH[@]}" "$@"; }

PASS=0
FAIL=0

check() {
    local label="$1" expected_code="$2" body="$3" check_field="$4" check_value="$5"
    echo "--- $label ---"

    http_code=$(acurl -s -o /tmp/check-input-resp.json -w "%{http_code}" \
        -X POST "${AGENT_URL}/api/v1/mcp/check-input" \
        -H "Content-Type: application/json" \
        -d "$body")

    resp=$(cat /tmp/check-input-resp.json)

    if [ "$http_code" = "$expected_code" ]; then
        echo "  ✓ HTTP $http_code (expected)"
    else
        echo "  ✗ HTTP $http_code (expected $expected_code)"
        echo "  Response: $resp"
        FAIL=$((FAIL + 1))
        echo ""
        return
    fi

    if [ -n "$check_field" ]; then
        actual=$(echo "$resp" | jq -r "$check_field")
        if [ "$actual" = "$check_value" ]; then
            echo "  ✓ $check_field = $check_value"
        else
            echo "  ✗ $check_field = $actual (expected $check_value)"
            FAIL=$((FAIL + 1))
            echo ""
            return
        fi
    fi

    PASS=$((PASS + 1))
    echo ""
}

echo "=== MCP Check-Input Endpoint ==="
echo ""

# Test 1: Clean SQL query — should pass
check "Clean SQL query" "200" '{
    "connector_type": "postgres",
    "statement": "SELECT name, department FROM employees WHERE id = 42",
    "operation": "query"
}' '.allowed' 'true'

# Test 2: SQL injection — should be blocked
check "SQL injection (UNION-based)" "403" '{
    "connector_type": "postgres",
    "statement": "SELECT * FROM users UNION SELECT username, password FROM admin_users--"
}' '.allowed' 'false'

# Test 3: DROP TABLE — should be blocked
check "Dangerous query (DROP TABLE)" "403" '{
    "connector_type": "postgres",
    "statement": "SELECT * FROM users; DROP TABLE users--",
    "operation": "query"
}' '.allowed' 'false'

# Test 4: Execute operation
check "Clean execute operation" "200" '{
    "connector_type": "postgres",
    "statement": "UPDATE orders SET status = $1 WHERE id = $2",
    "operation": "execute"
}' '.allowed' 'true'

# Test 5: Clean parameterized query — should pass
check "Clean parameterized query" "200" '{
    "connector_type": "postgres",
    "statement": "SELECT * FROM users WHERE id = $1",
    "operation": "query",
    "parameters": {"1": "usr-42"}
}' '.allowed' 'true'

# Test 6: SQLi in parameters — should be blocked
check "SQLi in parameters" "403" '{
    "connector_type": "postgres",
    "statement": "SELECT * FROM users WHERE id = $1",
    "operation": "query",
    "parameters": {"1": "1 OR 1=1; DROP TABLE users--"}
}' '.allowed' 'false'

# Test 7: PII in parameters — detected (allowed but policies match)
check "PII in parameters (SSN)" "200" '{
    "connector_type": "postgres",
    "statement": "INSERT INTO contacts VALUES ($1, $2)",
    "operation": "execute",
    "parameters": {"1": "Alice", "2": "123-45-6789"}
}' '.allowed' 'true'

# Test 8: Missing connector_type — bad request
check "Missing connector_type (validation error)" "400" '{
    "statement": "SELECT 1"
}' '' ''

# Test 9: Missing statement — bad request
check "Missing statement (validation error)" "400" '{
    "connector_type": "postgres"
}' '' ''

echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ] || exit 1
