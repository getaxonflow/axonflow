#!/bin/bash
# MCP Check-Output Endpoint Examples
#
# Validates MCP response data against policies WITHOUT having executed
# the query through AxonFlow. Checks PII redaction, SQLi in responses,
# and exfiltration limits.
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

    http_code=$(acurl -s -o /tmp/check-output-resp.json -w "%{http_code}" \
        -X POST "${AGENT_URL}/api/v1/mcp/check-output" \
        -H "Content-Type: application/json" \
        -d "$body")

    resp=$(cat /tmp/check-output-resp.json)

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

echo "=== MCP Check-Output Endpoint ==="
echo ""

# Test 1: Clean response data — should pass
check "Clean response data" "200" '{
    "connector_type": "postgres",
    "response_data": [
        {"id": 1, "name": "Alice Johnson", "department": "Engineering"},
        {"id": 2, "name": "Bob Smith", "department": "Marketing"}
    ],
    "row_count": 2
}' '.allowed' 'true'

# Test 2: Response containing PII (SSN) — should be allowed but with redacted_data
check "PII in response (SSN redaction)" "200" '{
    "connector_type": "postgres",
    "response_data": [
        {"id": 1, "name": "Alice Johnson", "ssn": "123-45-6789"},
        {"id": 2, "name": "Bob Smith", "ssn": "987-65-4321"}
    ],
    "row_count": 2
}' '.allowed' 'true'

# Test 3: Execute-style response (message only)
check "Execute response (message)" "200" '{
    "connector_type": "postgres",
    "message": "3 rows updated",
    "metadata": {
        "query": "UPDATE users SET status = '\''active'\'' WHERE region = '\''us'\''"
    }
}' '.allowed' 'true'

# Test 4: Missing connector_type — bad request
check "Missing connector_type (validation error)" "400" '{
    "response_data": [{"id": 1}]
}' '' ''

# Test 5: Missing both response_data and message — bad request
check "Missing response_data and message (validation error)" "400" '{
    "connector_type": "postgres"
}' '' ''

echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ] || exit 1
