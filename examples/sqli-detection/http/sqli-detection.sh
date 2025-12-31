#!/bin/bash
# AxonFlow SQL Injection Detection - HTTP/curl
#
# Demonstrates AxonFlow's SQLi detection using raw HTTP requests.

set -e

AGENT_URL="${AXONFLOW_AGENT_URL:-http://localhost:8080}"
LICENSE_KEY="${AXONFLOW_LICENSE_KEY:-}"
CLIENT_ID="sqli-detection-demo"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "AxonFlow SQL Injection Detection - HTTP/curl"
echo "========================================"
echo ""
echo "Agent URL: $AGENT_URL"
echo ""

test_sqli() {
    local name="$1"
    local query="$2"
    local should_block="$3"

    echo -e "${YELLOW}Test: $name${NC}"
    echo "  Query: ${query:0:60}..."

    response=$(curl -s -X POST "$AGENT_URL/api/policy/pre-check" \
        -H "Content-Type: application/json" \
        -H "X-License-Key: $LICENSE_KEY" \
        -d "{
            \"query\": \"$query\",
            \"user_token\": \"sqli-detection-user\",
            \"client_id\": \"$CLIENT_ID\"
        }")

    approved=$(echo "$response" | jq -r '.approved // false')
    block_reason=$(echo "$response" | jq -r '.block_reason // ""')
    policies=$(echo "$response" | jq -r '.policies // [] | join(", ")')

    if [ "$approved" = "true" ]; then
        echo -e "  Result: ${GREEN}APPROVED${NC}"
        context_id=$(echo "$response" | jq -r '.context_id // "none"')
        echo "  Context ID: $context_id"
    else
        echo -e "  Result: ${RED}BLOCKED${NC}"
        echo "  Reason: $block_reason"
    fi

    if [ -n "$policies" ]; then
        echo "  Policies: $policies"
    fi

    if [ "$should_block" = "true" ] && [ "$approved" = "false" ]; then
        echo -e "  Test: ${GREEN}PASS${NC}"
    elif [ "$should_block" = "false" ] && [ "$approved" = "true" ]; then
        echo -e "  Test: ${GREEN}PASS${NC}"
    else
        expected="blocked"
        [ "$should_block" = "false" ] && expected="approved"
        echo -e "  Test: ${RED}FAIL${NC} (expected $expected)"
    fi

    echo ""
}

echo "Running SQLi Detection Tests..."
echo ""

test_sqli "Safe Query" \
    "Find users who signed up in the last 30 days" \
    "false"

test_sqli "DROP TABLE" \
    "SELECT * FROM users; DROP TABLE users;--" \
    "true"

test_sqli "UNION SELECT" \
    "Get user where id = 1 UNION SELECT password FROM admin" \
    "true"

test_sqli "Boolean Injection (OR 1=1)" \
    "SELECT * FROM users WHERE username='' OR '1'='1'" \
    "true"

test_sqli "Comment Injection" \
    "Find user admin'--" \
    "true"

test_sqli "Stacked Queries" \
    "SELECT name FROM users; DELETE FROM audit_log;" \
    "true"

test_sqli "DELETE Statement" \
    "DELETE FROM users WHERE active = false" \
    "true"

echo "========================================"
echo "SQLi Detection Tests Complete"
