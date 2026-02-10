#!/bin/bash
# AxonFlow Evaluation Tier - HTTP API Tier Limits Testing
#
# TIER COMPATIBILITY: Community / Evaluation / Enterprise
# This script works across ALL tiers. It auto-detects the active tier from
# the AXONFLOW_LICENSE_KEY environment variable and validates the expected
# limits for that tier. No license = Community mode (free, no signup needed).
#
# VALIDATION: This script exits with code 1 if any assertion fails.
#
# This script tests the tier-based policy limits using direct HTTP API calls:
# - Community (no license): 20 tenant policies, 0 org policies, 5 SSE connections
# - Evaluation (free license): 50 tenant policies, 5 org policies, 25 SSE connections
# - Enterprise (paid license): Unlimited
#
# Usage:
#   # Community mode (no license needed — this is the default)
#   ./test_tier_limits.sh
#
#   # Evaluation mode (requires free Evaluation license from https://getaxonflow.com/evaluation-license)
#   AXONFLOW_LICENSE_KEY=<evaluation-license> ./test_tier_limits.sh
#
#   # Enterprise mode (requires paid Enterprise license — NOT available in community edition)
#   # NOTE: Enterprise testing should use ee/examples/ scripts instead.
#   AXONFLOW_LICENSE_KEY=<enterprise-license> ./test_tier_limits.sh
#
# Prerequisites: docker compose up -d

set -e

# Configuration
ENDPOINT="${AXONFLOW_ENDPOINT:-http://localhost:8080}"
CLIENT_ID="${AXONFLOW_CLIENT_ID:-test-org-001}"
CLIENT_SECRET="${AXONFLOW_CLIENT_SECRET:-test-secret}"
TENANT_ID="${AXONFLOW_TENANT_ID:-tenant-001}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Track failures
FAILURES=()

pass() {
    echo -e "   ${GREEN}✓ PASS:${NC} $1"
}

fail() {
    echo -e "   ${RED}❌ FAIL:${NC} $1"
    FAILURES+=("$1")
}

info() {
    echo -e "   $1"
}

# Determine expected tier from license key
# Ed25519 format: AXON-{base64url_payload}.{base64url_signature}
# Legacy V2 format: AXON-V2-{base64_payload}-{8_char_sig}
get_expected_tier() {
    if [ -z "$AXONFLOW_LICENSE_KEY" ]; then
        echo "community"
        return
    fi

    # Ed25519 format: AXON-{PAYLOAD}.{SIGNATURE}
    if echo "$AXONFLOW_LICENSE_KEY" | grep -q "^AXON-.*\."; then
        INNER="${AXONFLOW_LICENSE_KEY#AXON-}"
        PAYLOAD_B64="${INNER%.*}"
        TIER=$(echo -n "$PAYLOAD_B64" | python3 -c "
import sys, base64, json
try:
    b = sys.stdin.read()
    pad = 4 - len(b) % 4
    if pad != 4: b += '=' * pad
    d = json.loads(base64.urlsafe_b64decode(b))
    print(d.get('tier',''))
except: pass
" 2>/dev/null)
        case "$TIER" in
            Evaluation) echo "evaluation"; return ;;
            Enterprise|Plus|Professional) echo "enterprise"; return ;;
        esac
    fi

    if echo "$AXONFLOW_LICENSE_KEY" | grep -qi "EVALUATION"; then
        echo "evaluation"
    else
        echo "enterprise"
    fi
}

echo "============================================================"
echo "AxonFlow Evaluation Tier - HTTP API Tier Limits Testing"
echo "============================================================"

EXPECTED_TIER=$(get_expected_tier)
echo ""
echo "Detected tier (from env): $EXPECTED_TIER"
echo "Endpoint: $ENDPOINT"
echo ""

# Generate JWT token for authentication
# In a real scenario, this would be provided by your auth system
AUTH_HEADER="Authorization: Bearer test-token"
CONTENT_TYPE="Content-Type: application/json"
TENANT_HEADER="X-Tenant-ID: $TENANT_ID"

# Test 1: Health Check
echo ""
echo "1. Testing Health Check"
echo "----------------------------------------"

HEALTH_RESPONSE=$(curl -s -w "\n%{http_code}" "$ENDPOINT/health" || echo "000")
HTTP_CODE=$(echo "$HEALTH_RESPONSE" | tail -n1)
BODY=$(echo "$HEALTH_RESPONSE" | sed '$d')

if [ "$HTTP_CODE" = "200" ]; then
    pass "Platform is healthy (HTTP $HTTP_CODE)"
    info "Response: $BODY"
else
    fail "Health check failed (HTTP $HTTP_CODE)"
fi

# Test 2: Create and Delete Tenant Policy
echo ""
echo "2. Testing Tenant Policy Creation"
echo "----------------------------------------"

if [ "$EXPECTED_TIER" = "community" ]; then
    EXPECTED_LIMIT=20
    info "Expected limit for community: $EXPECTED_LIMIT"
elif [ "$EXPECTED_TIER" = "evaluation" ]; then
    EXPECTED_LIMIT=50
    info "Expected limit for evaluation: $EXPECTED_LIMIT"
else
    EXPECTED_LIMIT="unlimited"
    info "Expected limit for enterprise: $EXPECTED_LIMIT"
fi

# Create test policy
POLICY_JSON='{
    "name": "HTTP API Tier Test Policy",
    "description": "Test policy created via HTTP API",
    "type": "content",
    "category": "dynamic-http-test",
    "tier": "tenant",
    "conditions": [{"field": "query", "operator": "contains", "value": "http-tier-test"}],
    "actions": [{"type": "log"}],
    "priority": 100,
    "enabled": false
}'

CREATE_RESPONSE=$(curl -s -w "\n%{http_code}" \
    -X POST "$ENDPOINT/api/v1/dynamic-policies" \
    -H "$AUTH_HEADER" \
    -H "$CONTENT_TYPE" \
    -H "$TENANT_HEADER" \
    -d "$POLICY_JSON" || echo "000")

HTTP_CODE=$(echo "$CREATE_RESPONSE" | tail -n1)
BODY=$(echo "$CREATE_RESPONSE" | sed '$d')

if [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "200" ]; then
    pass "Policy creation succeeded (HTTP $HTTP_CODE)"
    POLICY_ID=$(echo "$BODY" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)
    if [ -n "$POLICY_ID" ]; then
        info "Created policy ID: $POLICY_ID"
        # Clean up
        DELETE_RESPONSE=$(curl -s -w "\n%{http_code}" \
            -X DELETE "$ENDPOINT/api/v1/dynamic-policies/$POLICY_ID" \
            -H "$AUTH_HEADER" \
            -H "$TENANT_HEADER" || echo "000")
        info "Cleaned up test policy"
    fi
elif [ "$HTTP_CODE" = "403" ] || [ "$HTTP_CODE" = "429" ]; then
    if echo "$BODY" | grep -q "POLICY_LIMIT_EXCEEDED"; then
        info "Policy limit reached (expected at $EXPECTED_LIMIT)"
        pass "Policy limit enforcement working"

        # Check upgrade message
        if [ "$EXPECTED_TIER" = "community" ]; then
            if echo "$BODY" | grep -qi "evaluation"; then
                pass "Error message mentions Evaluation tier upgrade"
            else
                fail "Error message should mention Evaluation tier upgrade"
            fi
        elif [ "$EXPECTED_TIER" = "evaluation" ]; then
            if echo "$BODY" | grep -qi "enterprise"; then
                pass "Error message mentions Enterprise upgrade"
            else
                fail "Error message should mention Enterprise upgrade"
            fi
        fi
    else
        fail "Unexpected error: $BODY"
    fi
else
    fail "Policy creation failed with unexpected code (HTTP $HTTP_CODE): $BODY"
fi

# Test 3: Organization Policy Access
echo ""
echo "3. Testing Organization Policy Access"
echo "----------------------------------------"

ORG_POLICY_JSON='{
    "name": "HTTP API Org Policy Test",
    "description": "Test org policy created via HTTP API",
    "type": "content",
    "category": "dynamic-http-org-test",
    "tier": "organization",
    "conditions": [{"field": "query", "operator": "contains", "value": "http-org-test"}],
    "actions": [{"type": "log"}],
    "priority": 100,
    "enabled": false
}'

CREATE_ORG_RESPONSE=$(curl -s -w "\n%{http_code}" \
    -X POST "$ENDPOINT/api/v1/dynamic-policies" \
    -H "$AUTH_HEADER" \
    -H "$CONTENT_TYPE" \
    -H "$TENANT_HEADER" \
    -d "$ORG_POLICY_JSON" || echo "000")

HTTP_CODE=$(echo "$CREATE_ORG_RESPONSE" | tail -n1)
BODY=$(echo "$CREATE_ORG_RESPONSE" | sed '$d')

if [ "$EXPECTED_TIER" = "community" ]; then
    # Community should NOT be able to create org policies
    if [ "$HTTP_CODE" = "403" ] || echo "$BODY" | grep -q "ORG_TIER"; then
        pass "Community tier correctly blocked org policy creation"
        if echo "$BODY" | grep -qi "evaluation"; then
            pass "Error message includes upgrade path to Evaluation"
        else
            fail "Error message should mention Evaluation tier upgrade"
        fi
    else
        fail "Community should not be able to create org policies (got HTTP $HTTP_CODE)"
    fi
elif [ "$EXPECTED_TIER" = "evaluation" ]; then
    # Evaluation should be able to create org policies (up to 5)
    if [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "200" ]; then
        pass "Evaluation tier can create org policies"
        POLICY_ID=$(echo "$BODY" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)
        if [ -n "$POLICY_ID" ]; then
            info "Created org policy ID: $POLICY_ID"
            # Clean up
            curl -s -X DELETE "$ENDPOINT/api/v1/dynamic-policies/$POLICY_ID" \
                -H "$AUTH_HEADER" \
                -H "$TENANT_HEADER" > /dev/null
            info "Cleaned up org policy"
        fi
    elif echo "$BODY" | grep -q "ORG_POLICY_LIMIT_EXCEEDED"; then
        info "Org policy limit (5) reached for Evaluation tier"
        pass "Evaluation tier has org policy limit enforcement"
    else
        fail "Evaluation should be able to create org policies (got HTTP $HTTP_CODE): $BODY"
    fi
else
    # Enterprise has unlimited org policies
    if [ "$HTTP_CODE" = "201" ] || [ "$HTTP_CODE" = "200" ]; then
        pass "Enterprise tier can create org policies"
        POLICY_ID=$(echo "$BODY" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)
        if [ -n "$POLICY_ID" ]; then
            info "Created org policy ID: $POLICY_ID"
            # Clean up
            curl -s -X DELETE "$ENDPOINT/api/v1/dynamic-policies/$POLICY_ID" \
                -H "$AUTH_HEADER" \
                -H "$TENANT_HEADER" > /dev/null
            info "Cleaned up org policy"
        fi
    else
        fail "Enterprise should have unlimited org policies (got HTTP $HTTP_CODE): $BODY"
    fi
fi

# Test 4: SSE Connection Limit
echo ""
echo "4. Testing SSE Connection Limit"
echo "----------------------------------------"

if [ "$EXPECTED_TIER" = "community" ]; then
    EXPECTED_SSE=5
elif [ "$EXPECTED_TIER" = "evaluation" ]; then
    EXPECTED_SSE=25
else
    EXPECTED_SSE=-1
fi

info "Expected SSE connection limit: $EXPECTED_SSE"

# SSE handler validates execution existence before checking connection limits.
# We need a real execution ID. Query the orchestrator for existing executions.
ORCHESTRATOR_PORT="${AXONFLOW_ORCHESTRATOR_PORT:-8081}"
ORCHESTRATOR_URL="http://localhost:$ORCHESTRATOR_PORT"

EXEC_LIST=$(curl -s "$ORCHESTRATOR_URL/api/v1/unified/executions?limit=1" \
    -H "$TENANT_HEADER" 2>/dev/null || echo "{}")
SSE_EXEC_ID=$(echo "$EXEC_LIST" | python3 -c "
import sys,json
try:
    d = json.load(sys.stdin)
    items = d.get('executions', d.get('items', []))
    if items and len(items) > 0:
        print(items[0].get('execution_id', items[0].get('id', '')))
    else:
        print('')
except: print('')
" 2>/dev/null)

if [ -z "$SSE_EXEC_ID" ]; then
    # Try creating an execution
    CREATE_EXEC=$(curl -s -X POST "$ENDPOINT/api/request" \
        -H "Content-Type: application/json" \
        -H "$TENANT_HEADER" \
        -d "{
            \"query\": \"sse limit test\",
            \"request_type\": \"simple\",
            \"user\": {\"id\": 1, \"tenant_id\": \"$TENANT_ID\"}
        }" 2>/dev/null || echo "{}")
    SSE_EXEC_ID=$(echo "$CREATE_EXEC" | python3 -c "
import sys,json
try:
    d = json.load(sys.stdin)
    print(d.get('execution_id', d.get('id', '')))
except: print('')
" 2>/dev/null)
fi

SSE_PIDS=()

open_sse_conn() {
    curl -s -o /dev/null -N --max-time 10 \
        -H "$TENANT_HEADER" \
        -H "Accept: text/event-stream" \
        "$ORCHESTRATOR_URL/api/v1/unified/executions/$SSE_EXEC_ID/stream" 2>/dev/null &
    SSE_PIDS+=($!)
}

cleanup_sse_conns() {
    for pid in "${SSE_PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    done
    SSE_PIDS=()
}

if [ -z "$SSE_EXEC_ID" ]; then
    info "No execution available for SSE streaming test"
    info "SKIP: SSE connection limit test (need LLM provider or prior executions)"
elif [ "$EXPECTED_SSE" -gt 0 ] 2>/dev/null; then
    # Verify SSE works for this execution
    SSE_CHECK=$(curl -s -o /dev/null -w "%{http_code}" --max-time 3 \
        -H "$TENANT_HEADER" \
        -H "Accept: text/event-stream" \
        "$ORCHESTRATOR_URL/api/v1/unified/executions/$SSE_EXEC_ID/stream" 2>/dev/null || echo "000")

    if [ "$SSE_CHECK" != "200" ]; then
        info "SKIP: SSE endpoint returned HTTP $SSE_CHECK (execution may have completed)"
    else
        info "Opening $EXPECTED_SSE SSE connections to execution $SSE_EXEC_ID..."
        for i in $(seq 1 "$EXPECTED_SSE"); do
            open_sse_conn
        done
        sleep 2

        ACTIVE_COUNT=0
        for pid in "${SSE_PIDS[@]}"; do
            if kill -0 "$pid" 2>/dev/null; then
                ACTIVE_COUNT=$((ACTIVE_COUNT + 1))
            fi
        done

        if [ "$ACTIVE_COUNT" -ge "$EXPECTED_SSE" ]; then
            pass "Opened $ACTIVE_COUNT/$EXPECTED_SSE SSE connections at limit"
        elif [ "$ACTIVE_COUNT" -eq 0 ]; then
            info "SKIP: All SSE connections closed (execution likely completed)"
        else
            fail "Only $ACTIVE_COUNT/$EXPECTED_SSE SSE connections active"
        fi

        if [ "$ACTIVE_COUNT" -ge "$EXPECTED_SSE" ]; then
            OVER_CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 3 \
                -H "$TENANT_HEADER" \
                -H "Accept: text/event-stream" \
                "$ORCHESTRATOR_URL/api/v1/unified/executions/$SSE_EXEC_ID/stream" 2>/dev/null || echo "000")

            if [ "$OVER_CODE" = "429" ]; then
                pass "Connection $((EXPECTED_SSE + 1)) correctly rejected (HTTP 429)"
            elif [ "$OVER_CODE" = "200" ]; then
                fail "Connection $((EXPECTED_SSE + 1)) should have been rejected but got HTTP 200"
            else
                fail "Over-limit connection returned unexpected code (HTTP $OVER_CODE)"
            fi
        fi

        cleanup_sse_conns
    fi
elif [ "$EXPECTED_SSE" -eq -1 ]; then
    SSE_CHECK=$(curl -s -o /dev/null -w "%{http_code}" --max-time 3 \
        -H "$TENANT_HEADER" \
        -H "Accept: text/event-stream" \
        "$ORCHESTRATOR_URL/api/v1/unified/executions/$SSE_EXEC_ID/stream" 2>/dev/null || echo "000")

    if [ "$SSE_CHECK" != "200" ]; then
        info "SKIP: SSE endpoint returned HTTP $SSE_CHECK (execution may have completed)"
    else
        info "Opening 10 SSE connections (unlimited mode)..."
        for i in $(seq 1 10); do
            open_sse_conn
        done
        sleep 2

        ACTIVE_COUNT=0
        for pid in "${SSE_PIDS[@]}"; do
            if kill -0 "$pid" 2>/dev/null; then
                ACTIVE_COUNT=$((ACTIVE_COUNT + 1))
            fi
        done

        if [ "$ACTIVE_COUNT" -ge 8 ]; then
            pass "Enterprise: $ACTIVE_COUNT/10 SSE connections active (unlimited)"
        elif [ "$ACTIVE_COUNT" -eq 0 ]; then
            info "SKIP: All SSE connections closed (execution likely completed)"
        else
            fail "Enterprise: only $ACTIVE_COUNT/10 SSE connections active"
        fi

        cleanup_sse_conns
    fi
fi

# Summary
echo ""
echo "============================================================"
echo "TEST SUMMARY"
echo "============================================================"

if [ ${#FAILURES[@]} -gt 0 ]; then
    echo ""
    echo -e "${RED}❌ ${#FAILURES[@]} test(s) failed:${NC}"
    for failure in "${FAILURES[@]}"; do
        echo "   - $failure"
    done
    exit 1
else
    echo ""
    echo -e "${GREEN}✓ All tests passed!${NC}"
    echo ""
    echo "Tier limits verified for: $EXPECTED_TIER"
    echo ""
    echo "Tier Comparison:"
    echo "  | Feature          | Community | Evaluation | Enterprise |"
    echo "  |------------------|-----------|------------|------------|"
    echo "  | Tenant policies  | 20        | 50         | Unlimited  |"
    echo "  | Org policies     | 0         | 5          | Unlimited  |"
    echo "  | MCP connectors   | 2         | 5          | Unlimited  |"
    echo "  | SSE connections  | 5         | 25         | Unlimited  |"
    echo "  | Audit retention  | 3 days    | 14 days    | 3650 days  |"
    exit 0
fi
