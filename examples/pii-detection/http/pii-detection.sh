#!/bin/bash
# AxonFlow PII Detection - HTTP/curl
#
# Demonstrates AxonFlow's built-in PII detection using raw HTTP requests.
# This is useful for:
# - Languages without an SDK (Ruby, PHP, etc.)
# - Quick testing and debugging
# - Understanding the API structure
#
# Prerequisites:
#   - AxonFlow Agent running at http://localhost:8080
#   - curl and jq installed

set -e

# Configuration
AGENT_URL="${AXONFLOW_AGENT_URL:-http://localhost:8080}"
LICENSE_KEY="${AXONFLOW_LICENSE_KEY:-}"
CLIENT_ID="pii-detection-demo"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "AxonFlow PII Detection - HTTP/curl"
echo "========================================"
echo ""
echo "Agent URL: $AGENT_URL"
echo ""

# Test function
test_pii() {
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
            \"user_token\": \"pii-detection-user\",
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

    # Verify expected behavior
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

# Run tests
echo "Running PII Detection Tests..."
echo ""

test_pii "Safe Query (No PII)" \
    "What is the capital of France?" \
    "false"

test_pii "US Social Security Number" \
    "Process refund for customer with SSN 123-45-6789" \
    "true"

test_pii "Credit Card Number" \
    "Charge card 4111-1111-1111-1111 for \$99.99" \
    "true"

test_pii "India PAN" \
    "Verify PAN number ABCDE1234F for tax filing" \
    "true"

test_pii "India Aadhaar" \
    "Link Aadhaar 2345 6789 0123 to account" \
    "true"

test_pii "Email Address" \
    "Send invoice to john.doe@example.com" \
    "true"

test_pii "Phone Number" \
    "Call customer at +1-555-123-4567" \
    "false"

echo "========================================"
echo "PII Detection Tests Complete"
echo ""
echo "Next steps:"
echo "  - Custom Policies: ../policies/http/"
echo "  - Use SDK examples for production: ../go/, ../python/, ../typescript/, ../java/"
