#!/bin/bash
# AxonFlow SQL Injection Detection - HTTP/curl
#
# Demonstrates AxonFlow's SQLi detection using raw HTTP requests.
#
# Expected outcome (v11): the stored policy action decides. Every shipped
# sys_sqli_* policy stores action "warn", so a detected SQLi pattern is
# APPROVED with the matched sys_sqli_* id in `policies`; it is not blocked.
# To block SQL injection, record an org override of category "sqli" with
# action "block" (PUT /api/v1/detection-posture/sqli on the customer portal
# API, Enterprise) or change the policy's action. SQLI_ACTION no longer sets
# an action.

set -e

AGENT_URL="${AXONFLOW_AGENT_URL:-http://localhost:8080}"
CLIENT_ID="${AXONFLOW_CLIENT_ID:-community}"
CLIENT_SECRET="${AXONFLOW_CLIENT_SECRET:-}"
AUTH_B64=$(printf '%s:%s' "$CLIENT_ID" "$CLIENT_SECRET" | base64)
# user_token: validated as a JWT in eval/enterprise mode (any string accepted in
# community mode). Reads AXONFLOW_USER_TOKEN — set by setup-e2e-testing.sh
# evaluation/enterprise. The fallback string stays compatible with the prior
# hardcoded behavior so community-mode runs unchanged.
USER_TOKEN="${AXONFLOW_USER_TOKEN:-sqli-detection-user}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

SQLI_FAILURES=0   # failure accumulator (#3964 follow-up)

echo "AxonFlow SQL Injection Detection - HTTP/curl"
echo "========================================"
echo ""
echo "Agent URL: $AGENT_URL"
echo ""

test_sqli() {
    local name="$1"
    local query="$2"
    local expect_detected="$3"

    echo -e "${YELLOW}Test: $name${NC}"
    echo "  Query: ${query:0:60}..."

    response=$(curl -s -X POST "$AGENT_URL/api/policy/pre-check" \
        -H "Content-Type: application/json" \
        -H "Authorization: Basic $AUTH_B64" \
        -d "{
            \"query\": \"$query\",
            \"user_token\": \"${USER_TOKEN}\",
            \"client_id\": \"$CLIENT_ID\"
        }")

    # has(), NOT `// false` (#3964), and the direction matters here: a
    # response carrying no `approved` key rendered as `false`, which this
    # script reads as BLOCKED - so a should_block case PASSED on a response
    # that never said anything about approval.
    approved=$(echo "$response" | jq -r 'if has("approved") then .approved else "absent" end')
    block_reason=$(echo "$response" | jq -r '.block_reason // ""')
    policies=$(echo "$response" | jq -r '.policies // [] | join(", ")')

    if [ "$approved" = "true" ]; then
        echo -e "  Result: ${GREEN}APPROVED${NC}"
        context_id=$(echo "$response" | jq -r '.context_id // "none"')
        echo "  Context ID: $context_id"
    elif [ "$approved" = "false" ]; then
        echo -e "  Result: ${RED}BLOCKED${NC}"
        echo "  Reason: $block_reason"
    else
        # Three states, not two (#3964 follow-up): printing BLOCKED for a
        # response that carried no `approved` key reports a verdict the server
        # never gave, in the reassuring direction.
        echo -e "  Result: ${RED}NO VERDICT${NC} (response carried no 'approved' field)"
        echo "  Raw: $response"
    fi

    if [ -n "$policies" ]; then
        echo "  Policies: $policies"
    fi

    # Count sys_sqli_* ids - the detection signal of a warned request.
    sqli_ids=$(echo "$response" | jq -r '[.policies // [] | .[] | select(startswith("sys_sqli_"))] | length')

    if [ "$approved" != "true" ]; then
        echo -e "  Test: ${RED}FAIL${NC} (expected approved; the shipped sys_sqli_* action is warn - a block means an org sqli=block override or an edited policy action)"
        SQLI_FAILURES=$((SQLI_FAILURES + 1))
    elif [ "$expect_detected" = "true" ] && [ "${sqli_ids:-0}" -gt 0 ]; then
        echo -e "  Test: ${GREEN}PASS${NC} (approved, SQLi WARNED)"
    elif [ "$expect_detected" = "true" ]; then
        echo -e "  Test: ${RED}FAIL${NC} (expected a sys_sqli_* policy in policies)"
        SQLI_FAILURES=$((SQLI_FAILURES + 1))
    else
        echo -e "  Test: ${GREEN}PASS${NC}"
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
    "SELECT * FROM users WHERE name='admin'-- AND password='secret'" \
    "false"  # Comment injection not currently detected by default policies

test_sqli "Stacked Queries" \
    "SELECT name FROM users; DELETE FROM audit_log;" \
    "true"

test_sqli "Truncate Statement" \
    "SELECT * FROM data; TRUNCATE TABLE logs;" \
    "true"

echo "========================================"
echo "SQLi Detection Tests Complete"

# A script that prints FAIL and exits 0 is not a test (#3964 follow-up): every
# caller, CI or human, reads the exit code, and this one always said success.
if [ "${SQLI_FAILURES:-0}" -gt 0 ]; then
    echo -e "${RED}${SQLI_FAILURES} test(s) FAILED${NC}"
    exit 1
fi
echo -e "${GREEN}All SQLi detection tests passed${NC}"
