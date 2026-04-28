#!/bin/bash
# AxonFlow Policy Management - HTTP/curl
#
# Demonstrates policy CRUD operations and pattern testing using raw HTTP.
# Works with the Agent API (port 8080).
#
# Prerequisites:
#   - AxonFlow Agent running at http://localhost:8080
#   - curl and jq installed
#
# Usage:
#   chmod +x policies.sh
#   ./policies.sh

set -e

AGENT_URL="${AXONFLOW_AGENT_URL:-http://localhost:8080}"
CLIENT_ID="${AXONFLOW_CLIENT_ID:-community}"
CLIENT_SECRET="${AXONFLOW_CLIENT_SECRET:-demo-secret}"

# Basic auth for agent proxy
AUTH_HEADER="Authorization: Basic $(echo -n "${CLIENT_ID}:${CLIENT_SECRET}" | base64)"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo "AxonFlow Policy Management - HTTP/curl"
echo "========================================"
echo ""
echo "Agent URL: $AGENT_URL"
echo ""

# =========================================================================
# List System Policies
# =========================================================================
echo -e "${CYAN}1. List System Policies${NC}"
echo "========================================"

response=$(curl -s "$AGENT_URL/api/v1/static-policies" \
    -H "$AUTH_HEADER")

count=$(echo "$response" | jq -r 'if type == "array" then length else 0 end')
echo "Found $count system policies"
echo ""

# Show first 5 policies
echo "Sample policies:"
echo "$response" | jq -r '.[:5][] | "  - \(.name): \(.description // "No description")"' 2>/dev/null || echo "  (No policies found)"
echo ""

# =========================================================================
# Filter Policies by Category
# =========================================================================
echo -e "${CYAN}2. Filter Policies by Category${NC}"
echo "========================================"

# Filter PII policies
echo -e "${YELLOW}PII Detection Policies:${NC}"
response=$(curl -s "$AGENT_URL/api/v1/static-policies?category=pii_detection" \
    -H "$AUTH_HEADER")
echo "$response" | jq -r '.[] | "  - \(.name)"' 2>/dev/null || echo "  (No policies found)"
echo ""

# Filter SQLi policies
echo -e "${YELLOW}SQL Injection Policies:${NC}"
response=$(curl -s "$AGENT_URL/api/v1/static-policies?category=sql_injection" \
    -H "$AUTH_HEADER")
echo "$response" | jq -r '.[] | "  - \(.name)"' 2>/dev/null || echo "  (No policies found)"
echo ""

# =========================================================================
# Create a Custom Policy
# =========================================================================
echo -e "${CYAN}3. Create Custom Policy${NC}"
echo "========================================"

POLICY_NAME="custom_profanity_filter_http"
echo "Creating policy: $POLICY_NAME"

response=$(curl -s -X POST "$AGENT_URL/api/v1/static-policies" \
    -H "Content-Type: application/json" \
    -H "$AUTH_HEADER" \
    -d "{
        \"name\": \"$POLICY_NAME\",
        \"description\": \"Blocks profanity in user queries (HTTP example)\",
        \"category\": \"sensitive-data\",
        \"tier\": \"tenant\",
        \"action\": \"block\",
        \"severity\": \"medium\",
        \"pattern\": \"\\\\b(badword1|badword2)\\\\b\",
        \"enabled\": true
    }")

success=$(echo "$response" | jq -r '.id // .error // "unknown"')
if [[ "$success" != "null" && "$success" != "unknown" && "$success" != *"error"* ]]; then
    echo -e "   Status: ${GREEN}Created${NC}"
    echo "   Policy ID: $success"
    POLICY_ID="$success"
else
    echo -e "   Status: ${YELLOW}Already exists or error${NC}"
    echo "   Response: $(echo "$response" | jq -c '.' 2>/dev/null || echo "$response")"
    POLICY_ID=""
fi
echo ""

# =========================================================================
# Test Pattern Matching
# =========================================================================
echo -e "${CYAN}4. Test Pattern Matching${NC}"
echo "========================================"

echo "Testing SSN pattern..."
response=$(curl -s -X POST "$AGENT_URL/api/v1/static-policies/test" \
    -H "Content-Type: application/json" \
    -H "$AUTH_HEADER" \
    -d '{
        "pattern": "\\b\\d{3}-\\d{2}-\\d{4}\\b",
        "test_strings": [
            "My SSN is 123-45-6789",
            "Call me at 555-123-4567",
            "No sensitive data here"
        ]
    }')

echo "$response" | jq -r '.results[] | "  Input: \(.input)\n  Match: \(.matched) \(if .matched then "- Found: \(.matches | join(", "))" else "" end)"' 2>/dev/null || echo "$response"
echo ""

# =========================================================================
# Test Policy Enforcement
# =========================================================================
echo -e "${CYAN}5. Test Policy Enforcement${NC}"
echo "========================================"

test_policy() {
    local query="$1"
    local expected="$2"

    echo -e "${YELLOW}Query:${NC} ${query:0:50}..."

    response=$(curl -s -X POST "$AGENT_URL/api/policy/pre-check" \
        -H "Content-Type: application/json" \
        -H "$AUTH_HEADER" \
        -d "{
            \"query\": \"$query\",
            \"user_token\": \"policy-test-user\",
            \"client_id\": \"policy-http-example\"
        }")

    approved=$(echo "$response" | jq -r '.approved // false')
    if [ "$approved" = "true" ]; then
        echo -e "   Result: ${GREEN}APPROVED${NC}"
    else
        block_reason=$(echo "$response" | jq -r '.block_reason // "Unknown"')
        echo -e "   Result: ${RED}BLOCKED${NC} - $block_reason"
    fi
    echo ""
}

test_policy "What is 2 + 2?" "approved"
test_policy "Show me user with SSN 123-45-6789" "blocked"
test_policy "SELECT * FROM users; DROP TABLE users;" "blocked"

# =========================================================================
# Cleanup
# =========================================================================
echo -e "${CYAN}6. Cleanup${NC}"
echo "========================================"

if [ -n "$POLICY_ID" ]; then
    echo "Deleting test policy: $POLICY_NAME"
    response=$(curl -s -X DELETE "$AGENT_URL/api/v1/static-policies/$POLICY_ID" \
        -H "$AUTH_HEADER")
    echo -e "   Status: ${GREEN}Deleted${NC}"
else
    echo "No test policy to clean up"
fi
echo ""

echo "========================================"
echo "Policy Management Complete!"
echo ""
echo "API Endpoints Used:"
echo "  GET  /api/v1/static-policies       - List policies"
echo "  POST /api/v1/static-policies       - Create policy"
echo "  POST /api/v1/static-policies/test  - Test pattern"
echo "  DELETE /api/v1/static-policies/{id} - Delete policy"
