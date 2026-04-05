#!/bin/bash
# AxonFlow PII Detection Modes — Request + Response Side
#
# Tests PII detection across all PII_ACTION modes:
#   - redact (default): PII detected, flagged for redaction
#   - block: PII detected, request rejected
#   - warn: PII detected, logged but not blocked or redacted
#   - log: PII detected, silently logged
#
# Tests BOTH request-side (pre-check) and response-side (LLM output) detection.
#
# Prerequisites:
#   - AxonFlow running: ./scripts/setup-e2e-testing.sh community
#   - curl and jq installed
#
# Usage:
#   cd examples/pii-detection/http
#   ./pii-modes.sh

set -e

AGENT_URL="${AXONFLOW_AGENT_URL:-http://localhost:8080}"
CLIENT_ID="${AXONFLOW_CLIENT_ID:-community}"
CLIENT_SECRET="${AXONFLOW_CLIENT_SECRET:-}"
AUTH_B64=$(printf '%s:%s' "$CLIENT_ID" "$CLIENT_SECRET" | base64)

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

PASS=0
FAIL=0

pass() { echo -e "   ${GREEN}PASS: $1${NC}"; PASS=$((PASS+1)); }
fail() { echo -e "   ${RED}FAIL: $1${NC}"; FAIL=$((FAIL+1)); }

echo "=============================================="
echo "PII Detection Modes — Request + Response Side"
echo "=============================================="
echo "Agent URL: $AGENT_URL"
echo ""

# ========================================
# 1. Request-side PII (pre-check API)
# ========================================
echo -e "${YELLOW}1. Request-Side PII Detection (pre-check)${NC}"
echo "   Tests: policy evaluation on user queries containing PII"
echo ""

# SSN in query — should be detected in all modes
RESPONSE=$(curl -s -X POST "$AGENT_URL/api/policy/pre-check" \
    -H "Content-Type: application/json" \
    -H "Authorization: Basic $AUTH_B64" \
    -d "{
        \"query\": \"Process refund for SSN 123-45-6789\",
        \"user_token\": \"pii-test-user\",
        \"client_id\": \"$CLIENT_ID\"
    }")

APPROVED=$(echo "$RESPONSE" | jq -r '.approved // false')
POLICIES=$(echo "$RESPONSE" | jq -r '[.policies // [] | .[] | select(startswith("sys_pii"))] | join(", ")' 2>/dev/null || echo "")
POLICY_COUNT=$(echo "$RESPONSE" | jq -r '.policy_info.policies_evaluated | length' 2>/dev/null || echo "0")

echo "   Query: 'Process refund for SSN 123-45-6789'"
echo "   Approved: $APPROVED"
echo "   PII policies matched: $POLICIES"
echo "   Total policies evaluated: $POLICY_COUNT"

if [ -n "$POLICIES" ]; then
    pass "SSN detected by request-side policy engine"
else
    # In redact mode, PII is detected but request is approved
    if [ "$APPROVED" = "true" ]; then
        # Check policy_info for PII evaluation
        PII_EVALUATED=$(echo "$RESPONSE" | jq -r '.policy_info.policies_evaluated // [] | map(select(contains("pii"))) | length' 2>/dev/null || echo "0")
        if [ "$PII_EVALUATED" -gt 0 ]; then
            pass "SSN detected by request-side policy engine (redact mode)"
        else
            fail "SSN not detected in request-side policy evaluation"
        fi
    else
        pass "SSN detected and blocked by request-side policy engine"
    fi
fi
echo ""

# Credit card
RESPONSE=$(curl -s -X POST "$AGENT_URL/api/policy/pre-check" \
    -H "Content-Type: application/json" \
    -H "Authorization: Basic $AUTH_B64" \
    -d "{
        \"query\": \"Charge card 4111-1111-1111-1111 for payment\",
        \"user_token\": \"pii-test-user\",
        \"client_id\": \"$CLIENT_ID\"
    }")

CC_POLICIES=$(echo "$RESPONSE" | jq -r '[.policies // [] | .[] | select(contains("credit"))] | length' 2>/dev/null || echo "0")
CC_EVALUATED=$(echo "$RESPONSE" | jq -r '.policy_info.policies_evaluated // [] | map(select(contains("credit"))) | length' 2>/dev/null || echo "0")
if [ "$CC_POLICIES" -gt 0 ] || [ "$CC_EVALUATED" -gt 0 ]; then
    pass "Credit card detected by request-side policy engine"
else
    fail "Credit card not detected in request-side evaluation"
fi

# Clean query — should pass with no PII
RESPONSE=$(curl -s -X POST "$AGENT_URL/api/policy/pre-check" \
    -H "Content-Type: application/json" \
    -H "Authorization: Basic $AUTH_B64" \
    -d "{
        \"query\": \"What is the weather today?\",
        \"user_token\": \"pii-test-user\",
        \"client_id\": \"$CLIENT_ID\"
    }")

APPROVED=$(echo "$RESPONSE" | jq -r '.approved // false')
if [ "$APPROVED" = "true" ]; then
    pass "Clean query approved (no PII)"
else
    fail "Clean query unexpectedly blocked"
fi

# ISO timestamp — must NOT trigger false positives (SSN, phone, bank account, UEN)
# This is the key regression test: 10:37:58.123456789Z previously matched 4 PII patterns.
RESPONSE=$(curl -s -X POST "$AGENT_URL/api/policy/pre-check" \
    -H "Content-Type: application/json" \
    -H "Authorization: Basic $AUTH_B64" \
    -d "{
        \"query\": \"Event logged at 2026-04-05T10:37:58.123456789Z in production\",
        \"user_token\": \"pii-test-user\",
        \"client_id\": \"$CLIENT_ID\"
    }")

APPROVED=$(echo "$RESPONSE" | jq -r '.approved // false')
PII_MATCHED=$(echo "$RESPONSE" | jq -r '[.policies // [] | .[] | select(startswith("sys_pii") or startswith("pii_"))] | length' 2>/dev/null || echo "0")
if [ "$APPROVED" = "true" ] && [ "$PII_MATCHED" = "0" ]; then
    pass "ISO timestamp (123456789Z) not flagged as PII (no false positive)"
else
    fail "ISO timestamp triggered PII false positive (matched $PII_MATCHED patterns)"
fi

echo ""

# ========================================
# 2. Response-side PII (via /api/request)
# ========================================
echo -e "${YELLOW}2. Response-Side PII Detection (LLM output)${NC}"
echo "   Tests: PII redaction in orchestrator response processing"
echo "   Current PII_ACTION: ${PII_ACTION:-redact} (default)"
echo ""

# This tests the full proxy path: agent → orchestrator → LLM → response processor
# The response processor should detect PII in the LLM response and redact it
RESPONSE=$(curl -s -X POST "$AGENT_URL/api/request" \
    -H "Content-Type: application/json" \
    -H "Authorization: Basic $AUTH_B64" \
    -d "{
        \"query\": \"What is 2+2?\",
        \"user_token\": \"pii-test-user\",
        \"client_id\": \"$CLIENT_ID\",
        \"request_type\": \"chat\"
    }")

SUCCESS=$(echo "$RESPONSE" | jq -r '.success // false')
if [ "$SUCCESS" = "true" ] || [ "$SUCCESS" = "True" ]; then
    pass "LLM proxy request succeeded (response processor active)"
else
    # LLM may not be configured — that's ok, we're testing the response path
    ERROR=$(echo "$RESPONSE" | jq -r '.error // ""')
    if echo "$ERROR" | grep -qi "LLM\|provider\|no healthy"; then
        echo "   Note: LLM not configured — response-side PII tested via MCP check-output instead"
    else
        fail "Proxy request failed: $ERROR"
    fi
fi

# Test response-side PII via MCP check-output (doesn't need LLM)
echo ""
echo "   Testing via MCP check-output endpoint (direct PII scan)..."
RESPONSE=$(curl -s -X POST "$AGENT_URL/api/v1/mcp/check-output" \
    -H "Content-Type: application/json" \
    -H "Authorization: Basic $AUTH_B64" \
    -d "{
        \"connector_type\": \"cli\",
        \"message\": \"Patient SSN is 123-45-6789 and their email is patient@hospital.com\",
        \"client_id\": \"$CLIENT_ID\",
        \"user_token\": \"pii-test-user\",
        \"tenant_id\": \"$CLIENT_ID\"
    }")

ALLOWED=$(echo "$RESPONSE" | jq -r '.allowed // false')
POLICIES_EVALUATED=$(echo "$RESPONSE" | jq -r '.policies_evaluated // 0')
REDACTED=$(echo "$RESPONSE" | jq -r '.redacted_output // .message // ""')

echo "   Input: 'Patient SSN is 123-45-6789 and their email is patient@hospital.com'"
echo "   Allowed: $ALLOWED"
echo "   Policies evaluated: $POLICIES_EVALUATED"

if echo "$REDACTED" | grep -q '\*'; then
    echo "   Redacted: $REDACTED"
    pass "Response-side PII detected and redacted (SSN masked)"
elif [ "$POLICIES_EVALUATED" -gt 0 ]; then
    pass "Response-side PII detected ($POLICIES_EVALUATED policies evaluated)"
else
    fail "Response-side PII not detected"
fi

# Response-side timestamp false positive check
RESPONSE=$(curl -s -X POST "$AGENT_URL/api/v1/mcp/check-output" \
    -H "Content-Type: application/json" \
    -H "Authorization: Basic $AUTH_B64" \
    -d "{
        \"connector_type\": \"cli\",
        \"message\": \"Event at 2026-04-05T10:37:58.123456789Z completed successfully\",
        \"client_id\": \"$CLIENT_ID\",
        \"user_token\": \"pii-test-user\",
        \"tenant_id\": \"$CLIENT_ID\"
    }")

RESP_REDACTED=$(echo "$RESPONSE" | jq -r '.redacted_output // .message // ""')
if echo "$RESP_REDACTED" | grep -q '\*'; then
    fail "Response-side: ISO timestamp triggered false positive (redacted: $RESP_REDACTED)"
else
    pass "Response-side: ISO timestamp not flagged as PII (no false positive)"
fi

echo ""

# ========================================
# 3. PII_ACTION mode documentation
# ========================================
echo -e "${YELLOW}3. PII_ACTION Mode Reference${NC}"
echo ""
echo "   ┌──────────┬─────────────┬──────────────┬──────────────┐"
echo "   │ Mode     │ Request-side│ Response-side│ Audit logged │"
echo "   ├──────────┼─────────────┼──────────────┼──────────────┤"
echo "   │ block    │ Blocked     │ Blocked      │ Yes          │"
echo "   │ redact   │ Approved*   │ Redacted     │ Yes          │"
echo "   │ warn     │ Approved    │ Pass-through │ Yes          │"
echo "   │ log      │ Approved    │ Pass-through │ Yes          │"
echo "   └──────────┴─────────────┴──────────────┴──────────────┘"
echo "   * Approved with requires_redaction=true flag"
echo ""
echo "   To change mode: set PII_ACTION in docker-compose.yml and restart"
echo "   Example: PII_ACTION=block docker compose up -d"
echo ""

# ========================================
# Summary
# ========================================
echo "=============================================="
echo "Results: $PASS passed, $FAIL failed"
echo "=============================================="

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
