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
# Default Behavior (v11):
#   The stored action of each matched PII policy decides. On the request side
#   the shipped SSN, credit card, PAN and Aadhaar policies store warn: requests
#   are APPROVED and the matched policy ids are returned in "policies".
#   Environment variables no longer set detection actions; to block, record an
#   organization pii=block override (Enterprise customer portal) or change the
#   policy's action.

set -e

# Configuration
AGENT_URL="${AXONFLOW_AGENT_URL:-http://localhost:8080}"
CLIENT_ID="${AXONFLOW_CLIENT_ID:-community}"
CLIENT_SECRET="${AXONFLOW_CLIENT_SECRET:-}"
AUTH_B64=$(printf '%s:%s' "$CLIENT_ID" "$CLIENT_SECRET" | base64)

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

FAILED=0

echo "AxonFlow PII Detection - HTTP/curl"
echo "========================================"
echo ""
echo "Agent URL: $AGENT_URL"
echo "Stored policy actions decide: request-side PII warns (approved, policy recorded)"
echo ""

# Test function
# expect_detect: "true" = expect a matched PII policy (approved), "false" = no critical PII expected
test_pii() {
    local name="$1"
    local query="$2"
    local expect_detect="$3"

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

    # Verify expected behavior against the shipped stored actions
    if [ "$expect_detect" = "true" ] && [ "$approved" = "true" ] && [ -n "$policies" ]; then
        echo -e "  Test: ${GREEN}PASS${NC} (PII detected, approved: stored request action is warn)"
    elif [ "$expect_detect" = "false" ] && [ "$requires_redaction" = "false" ] && [ "$approved" = "true" ]; then
        echo -e "  Test: ${GREEN}PASS${NC} (no critical PII, approved)"
    else
        expected="approved with a matched PII policy"
        [ "$expect_detect" = "false" ] && expected="approved, no redaction flag"
        echo -e "  Test: ${RED}FAIL${NC} (expected $expected)"
        FAILED=$((FAILED + 1))
    fi

    echo ""
}

# Run tests
echo "Running PII Detection Tests..."
echo ""

# Test cases: (name, query, expect_detect)
# Critical PII (SSN, credit card, PAN, Aadhaar) - expect_detect="true"
# Non-critical PII (email, phone) - expect_detect="false" (approved, no redaction flag)

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
echo "  - The stored policy action decides; request-side PII rows store warn (approved, recorded)"
echo "  - To block PII: record an organization pii=block override (Enterprise customer portal:"
echo "    PUT /api/v1/detection-posture/pii {\"action\":\"block\"}) or change the policy's action"
echo ""
echo "Next steps:"
echo "  - Custom Policies: ../policies/http/"
echo "  - Use SDK examples for production: ../go/, ../python/, ../typescript/, ../java/"

if [ "$FAILED" -gt 0 ]; then
    exit 1
fi
