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
#
# Default Behavior (Issue #891):
#   PII detection defaults to "redact" mode - requests are APPROVED but flagged
#   with requires_redaction=true for downstream redaction by the Orchestrator.
#   Set PII_ACTION=block to restore blocking behavior.

set -e

# Configuration
AGENT_URL="${AXONFLOW_AGENT_URL:-http://localhost:8080}"
CLIENT_ID="${AXONFLOW_CLIENT_ID:-community}"
CLIENT_SECRET="${AXONFLOW_CLIENT_SECRET:-}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo "AxonFlow PII Detection - HTTP/curl"
echo "========================================"
echo ""
echo "Agent URL: $AGENT_URL"
echo "Default Mode: redact (PII flagged for redaction, not blocked)"
echo ""

# Test function
# expect_redact: "true" = expect requires_redaction=true, "false" = no PII expected
test_pii() {
    local name="$1"
    local query="$2"
    local expect_redact="$3"

    echo -e "${YELLOW}Test: $name${NC}"
    echo "  Query: ${query:0:60}..."

    response=$(curl -s -X POST "$AGENT_URL/api/policy/pre-check" \
        -H "Content-Type: application/json" \
        -H "Authorization: Basic $AUTH_B64" \
        -d "{
            \"query\": \"$query\",
            \"user_token\": \"pii-detection-user\",
            \"client_id\": \"$CLIENT_ID\"
        }")

    approved=$(echo "$response" | jq -r '.approved // false')
    requires_redaction=$(echo "$response" | jq -r '.requires_redaction // false')
    block_reason=$(echo "$response" | jq -r '.block_reason // ""')
    policies=$(echo "$response" | jq -r '.policies // [] | join(", ")')

    if [ "$approved" = "true" ]; then
        if [ "$requires_redaction" = "true" ]; then
            echo -e "  Result: ${CYAN}APPROVED (requires redaction)${NC}"
        else
            echo -e "  Result: ${GREEN}APPROVED${NC}"
        fi
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
    if [ "$expect_redact" = "true" ] && [ "$requires_redaction" = "true" ]; then
        echo -e "  Test: ${GREEN}PASS${NC} (PII detected, flagged for redaction)"
    elif [ "$expect_redact" = "false" ] && [ "$requires_redaction" = "false" ] && [ "$approved" = "true" ]; then
        echo -e "  Test: ${GREEN}PASS${NC} (no PII detected)"
    else
        expected="requires_redaction=true"
        [ "$expect_redact" = "false" ] && expected="no PII"
        echo -e "  Test: ${RED}FAIL${NC} (expected $expected)"
    fi

    echo ""
}

# Run tests
echo "Running PII Detection Tests..."
echo ""

# Test cases: (name, query, expect_redact)
# Critical PII (SSN, credit card, PAN, Aadhaar) - expect_redact="true"
# Non-critical PII (email, phone) - expect_redact="false" (logged but not flagged)

test_pii "Safe Query (No PII)" \
    "What is the capital of France?" \
    "false"

test_pii "US Social Security Number (Critical PII)" \
    "Process refund for customer with SSN 123-45-6789" \
    "true"

test_pii "Credit Card Number (Critical PII)" \
    "Charge card 4111-1111-1111-1111 for \$99.99" \
    "true"

test_pii "India PAN (Critical PII)" \
    "Verify PAN number ABCPD1234E for tax filing" \
    "true"

test_pii "India Aadhaar (Critical PII)" \
    "Link Aadhaar 2345 6789 0123 to account" \
    "true"

test_pii "Email Address (Non-Critical PII)" \
    "Send invoice to john.doe@gmail.com" \
    "false"

test_pii "Phone Number (Non-Critical PII)" \
    "Call customer at +1-555-123-4567" \
    "false"

echo "========================================"
echo "PII Detection Tests Complete"
echo ""
echo "Configuration:"
echo "  - Default: PII_ACTION=redact (PII flagged for redaction, not blocked)"
echo "  - To block PII: PII_ACTION=block docker compose up -d"
echo ""
echo "Next steps:"
echo "  - Custom Policies: ../policies/http/"
echo "  - Use SDK examples for production: ../go/, ../python/, ../typescript/, ../java/"
