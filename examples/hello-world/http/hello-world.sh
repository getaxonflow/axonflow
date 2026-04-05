#!/bin/bash
# AxonFlow Hello World - HTTP/curl
#
# The simplest possible AxonFlow integration using raw HTTP requests.
# Perfect for languages without an SDK (Ruby, PHP, etc.) or quick testing.
#
# Prerequisites:
#   - AxonFlow Agent running at http://localhost:8080
#   - curl and jq installed
#
# Usage:
#   chmod +x hello-world.sh
#   ./hello-world.sh

set -e

AGENT_URL="${AXONFLOW_AGENT_URL:-http://localhost:8080}"
CLIENT_ID="${AXONFLOW_CLIENT_ID:-community}"
CLIENT_SECRET="${AXONFLOW_CLIENT_SECRET:-}"
AUTH_B64=$(printf '%s:%s' "$CLIENT_ID" "$CLIENT_SECRET" | base64)
USER_TOKEN="${AXONFLOW_USER_TOKEN:-hello-world-user}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "AxonFlow Hello World - HTTP/curl"
echo "========================================"
echo ""
echo "Agent URL: $AGENT_URL"
echo ""

# Health check
echo -e "${YELLOW}Health Check${NC}"
health=$(curl -s "$AGENT_URL/health")
status=$(echo "$health" | jq -r '.status // "unknown"')
if [ "$status" = "healthy" ]; then
    echo -e "   Status: ${GREEN}$status${NC}"
else
    echo -e "   Status: ${RED}$status${NC}"
    echo "   AxonFlow Agent is not running. Start it with: docker compose up -d"
    exit 1
fi
echo ""

# Test function
test_query() {
    local name="$1"
    local query="$2"
    local expected="$3"

    echo -e "${YELLOW}Test: $name${NC}"
    echo "   Query: ${query:0:50}..."

    response=$(curl -s -X POST "$AGENT_URL/api/policy/pre-check" \
        -H "Content-Type: application/json" \
        -H "Authorization: Basic $AUTH_B64" \
        -d "{
            \"query\": \"$query\",
            \"user_token\": \"$USER_TOKEN\",
            \"client_id\": \"$CLIENT_ID\"
        }")

    approved=$(echo "$response" | jq -r '.approved // false')
    block_reason=$(echo "$response" | jq -r '.block_reason // ""')
    context_id=$(echo "$response" | jq -r '.context_id // ""')
    policies=$(echo "$response" | jq -r '.policies // [] | join(", ")')
    requires_redaction=$(echo "$response" | jq -r '.requires_redaction // false')

    if [ "$approved" = "true" ]; then
        if [ "$requires_redaction" = "true" ]; then
            echo -e "   Result: ${YELLOW}APPROVED (requires redaction)${NC}"
            actual="redaction"
        else
            echo -e "   Result: ${GREEN}APPROVED${NC}"
            actual="approved"
        fi
        echo "   Context ID: $context_id"
    else
        echo -e "   Result: ${RED}BLOCKED${NC}"
        echo "   Reason: $block_reason"
        actual="blocked"
    fi

    if [ -n "$policies" ]; then
        echo "   Policies: $policies"
    fi

    # Verify
    if [ "$actual" = "$expected" ]; then
        echo -e "   Test: ${GREEN}PASS${NC} (expected $expected)"
    else
        echo -e "   Test: ${RED}FAIL${NC} (expected $expected)"
    fi

    echo ""
}

echo "Running Hello World Tests..."
echo ""

# Test cases
test_query "Safe Query" \
    "What is the weather today?" \
    "approved"

test_query "SQL Injection" \
    "SELECT * FROM users; DROP TABLE users;" \
    "blocked"

test_query "PII (SSN)" \
    "Process payment for SSN 123-45-6789" \
    "redaction"

echo "========================================"
echo "Hello World Complete!"
echo ""
echo "Next steps:"
echo "  - Gateway Mode: ../integrations/gateway-mode/"
echo "  - Proxy Mode: ../integrations/proxy-mode/"
echo "  - Use SDK for production: ../go/, ../python/, ../typescript/, ../java/"
