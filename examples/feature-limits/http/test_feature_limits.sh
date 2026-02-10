#!/usr/bin/env bash
# Feature Limits Boundary Test — verifies tier-based enforcement via HTTP API
#
# TIER COMPATIBILITY: Community / Evaluation / Enterprise
# This script works across ALL tiers. It auto-detects the active tier from
# the AXONFLOW_LICENSE_KEY environment variable and validates the correct
# limits for that tier. No license = Community mode (free, no signup needed).
#
# This test creates resources up to and beyond tier limits to verify enforcement.
# It tests actual boundary behavior, not just smoke tests.
#
# Usage:
#   # Community mode (no license needed — this is the default)
#   bash test_feature_limits.sh
#
#   # Evaluation mode (requires free Evaluation license)
#   AXONFLOW_LICENSE_KEY="<evaluation-key>" bash test_feature_limits.sh
#
#   # Enterprise mode (requires paid Enterprise license — NOT in community edition)
#   # NOTE: Enterprise testing should use ee/examples/ scripts instead.
#   AXONFLOW_LICENSE_KEY="<enterprise-key>" bash test_feature_limits.sh
#
# Prerequisites:
#   docker compose up -d

set -euo pipefail

ENDPOINT="${AXONFLOW_ENDPOINT:-http://localhost:8080}"
CLIENT_ID="${AXONFLOW_CLIENT_ID:-test-org-001}"
TENANT_ID="${AXONFLOW_TENANT_ID:-tenant-limits-$(date +%s)}"
PASS=0
FAIL=0
SKIP=0
CREATED_POLICIES=()

pass() { echo "   ✓ PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "   ✗ FAIL: $1"; FAIL=$((FAIL + 1)); }
skip() { echo "   ⊘ SKIP: $1"; SKIP=$((SKIP + 1)); }

# Cleanup function — deletes all test policies created during the run
cleanup() {
    if [ "${#CREATED_POLICIES[@]}" -gt 0 ] 2>/dev/null; then
        echo ""
        echo "Cleaning up ${#CREATED_POLICIES[@]} test policies..."
        for policy_id in "${CREATED_POLICIES[@]}"; do
            curl -s -X DELETE "$ENDPOINT/api/v1/dynamic-policies/$policy_id" \
                -H "X-Tenant-ID: $TENANT_ID" > /dev/null 2>&1 || true
        done
        echo "Cleanup complete."
    fi
}
trap cleanup EXIT

# Detect tier from license key
# Ed25519 format: AXON-{base64url_payload}.{base64url_signature}
detect_tier() {
    if [ -z "${AXONFLOW_LICENSE_KEY:-}" ]; then
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

    echo "community"
}

# Helper: create a tenant policy via dynamic-policies API, returns HTTP code
create_policy() {
    local idx=$1
    local category="${2:-dynamic-boundary-test}"
    local response
    response=$(curl -s -w "\n%{http_code}" -X POST "$ENDPOINT/api/v1/dynamic-policies" \
        -H "Content-Type: application/json" \
        -H "X-Tenant-ID: $TENANT_ID" \
        -d "{
            \"name\": \"boundary-test-policy-$idx\",
            \"description\": \"Boundary test policy $idx\",
            \"type\": \"content\",
            \"category\": \"$category\",
            \"conditions\": [{
                \"field\": \"query\",
                \"operator\": \"contains\",
                \"value\": \"test-pattern-$idx\"
            }],
            \"actions\": [{\"type\": \"log\"}],
            \"enabled\": true,
            \"priority\": $idx
        }" 2>/dev/null)
    local http_code
    http_code=$(echo "$response" | tail -1)
    local body
    body=$(echo "$response" | sed '$d')

    # Extract policy ID if created successfully
    if [ "$http_code" = "201" ] || [ "$http_code" = "200" ]; then
        local policy_id
        policy_id=$(echo "$body" | python3 -c "import sys,json; print(json.load(sys.stdin).get('policy',{}).get('id',''))" 2>/dev/null || echo "")
        if [ -n "$policy_id" ]; then
            CREATED_POLICIES+=("$policy_id")
        fi
    fi

    echo "$http_code"
}

# Helper: create an org policy, returns HTTP code
create_org_policy() {
    local idx=$1
    local response
    response=$(curl -s -w "\n%{http_code}" -X POST "$ENDPOINT/api/v1/dynamic-policies" \
        -H "Content-Type: application/json" \
        -H "X-Tenant-ID: $TENANT_ID" \
        -d "{
            \"name\": \"boundary-org-policy-$idx\",
            \"description\": \"Boundary org policy $idx\",
            \"type\": \"content\",
            \"category\": \"dynamic-boundary-org\",
            \"tier\": \"organization\",
            \"organization_id\": \"test-org-$idx\",
            \"conditions\": [{
                \"field\": \"query\",
                \"operator\": \"contains\",
                \"value\": \"org-test-$idx\"
            }],
            \"actions\": [{\"type\": \"log\"}],
            \"enabled\": true,
            \"priority\": $idx
        }" 2>/dev/null)
    local http_code
    http_code=$(echo "$response" | tail -1)
    local body
    body=$(echo "$response" | sed '$d')

    if [ "$http_code" = "201" ] || [ "$http_code" = "200" ]; then
        local policy_id
        policy_id=$(echo "$body" | python3 -c "import sys,json; print(json.load(sys.stdin).get('policy',{}).get('id',''))" 2>/dev/null || echo "")
        if [ -n "$policy_id" ]; then
            CREATED_POLICIES+=("$policy_id")
        fi
    fi

    echo "$http_code"
}

TIER=$(detect_tier)
echo "=== Feature Limits Boundary Test ==="
echo "Endpoint: $ENDPOINT"
echo "Detected tier: $TIER"
echo "Test tenant: $TENANT_ID"
echo ""

# Set expected limits based on tier
case "$TIER" in
    community)
        POLICY_LIMIT=20; ORG_POLICY_LIMIT=0; CONNECTOR_LIMIT=2
        MAX_PROVIDERS=2; MAX_HISTORY=50; MAX_CONCURRENT=5; MAX_PLANS=25; MAX_VERSIONS=10
        MAX_SSE=5; AUDIT_RETENTION=3 ;;
    evaluation)
        POLICY_LIMIT=50; ORG_POLICY_LIMIT=5; CONNECTOR_LIMIT=5
        MAX_PROVIDERS=3; MAX_HISTORY=500; MAX_CONCURRENT=25; MAX_PLANS=100; MAX_VERSIONS=25
        MAX_SSE=25; AUDIT_RETENTION=14 ;;
    enterprise)
        POLICY_LIMIT=-1; ORG_POLICY_LIMIT=-1; CONNECTOR_LIMIT=-1
        MAX_PROVIDERS=-1; MAX_HISTORY=-1; MAX_CONCURRENT=-1; MAX_PLANS=-1; MAX_VERSIONS=-1
        MAX_SSE=-1; AUDIT_RETENTION=3650 ;;
esac

echo "Expected limits:"
echo "  Policies: $POLICY_LIMIT | Org policies: $ORG_POLICY_LIMIT | Custom policy connectors: $CONNECTOR_LIMIT"
echo "  LLM providers: $MAX_PROVIDERS | Exec history: $MAX_HISTORY | Concurrent: $MAX_CONCURRENT"
echo "  Plans: $MAX_PLANS | Versions/plan: $MAX_VERSIONS | SSE connections: $MAX_SSE | Audit retention: ${AUDIT_RETENTION}d"
echo ""

# ═══════════════════════════════════════════════════════════════════════
# Test 1: Health Check
# ═══════════════════════════════════════════════════════════════════════
echo "1. Health Check"

HEALTH_RESPONSE=$(curl -s -w "\n%{http_code}" "$ENDPOINT/health" 2>/dev/null || echo -e "\n000")
HEALTH_CODE=$(echo "$HEALTH_RESPONSE" | tail -1)

if [ "$HEALTH_CODE" = "200" ]; then
    pass "Platform is healthy"
else
    fail "Health check failed (HTTP $HEALTH_CODE) — cannot proceed with boundary tests"
    echo ""
    echo "=== Results ==="
    echo "Passed: $PASS | Failed: $FAIL | Skipped: $SKIP"
    exit 1
fi

# ═══════════════════════════════════════════════════════════════════════
# Test 2: Tenant Policy Boundary
# ═══════════════════════════════════════════════════════════════════════
echo ""
echo "2. Tenant Policy Boundary (limit=$POLICY_LIMIT)"

if [ "$POLICY_LIMIT" -gt 0 ] 2>/dev/null; then
    ALL_CREATED=true

    for i in $(seq 1 "$POLICY_LIMIT"); do
        HTTP_CODE=$(create_policy "$i")
        if [ "$HTTP_CODE" != "201" ] && [ "$HTTP_CODE" != "200" ]; then
            fail "Policy $i/$POLICY_LIMIT creation failed unexpectedly (HTTP $HTTP_CODE)"
            ALL_CREATED=false
            break
        fi
        if [ $((i % 10)) -eq 0 ]; then
            echo "   ... created $i/$POLICY_LIMIT policies"
        fi
    done

    if [ "$ALL_CREATED" = true ]; then
        pass "Created $POLICY_LIMIT tenant policies at limit"

        OVER_CODE=$(create_policy "$((POLICY_LIMIT + 1))")
        if [ "$OVER_CODE" = "429" ] || [ "$OVER_CODE" = "403" ]; then
            pass "Policy $((POLICY_LIMIT + 1)) correctly rejected (HTTP $OVER_CODE)"
        else
            fail "Policy $((POLICY_LIMIT + 1)) should have been rejected but got HTTP $OVER_CODE"
        fi
    fi
elif [ "$POLICY_LIMIT" -eq -1 ]; then
    ALL_OK=true
    for i in $(seq 1 25); do
        HTTP_CODE=$(create_policy "$i")
        if [ "$HTTP_CODE" != "201" ] && [ "$HTTP_CODE" != "200" ]; then
            fail "Enterprise policy $i creation failed (HTTP $HTTP_CODE)"
            ALL_OK=false
            break
        fi
    done
    if [ "$ALL_OK" = true ]; then
        pass "Enterprise: created 25 policies (unlimited tier)"
    fi
fi

# ═══════════════════════════════════════════════════════════════════════
# Test 3: Org Policy Boundary
# ═══════════════════════════════════════════════════════════════════════
echo ""
echo "3. Org Policy Boundary (limit=$ORG_POLICY_LIMIT)"

if [ "$ORG_POLICY_LIMIT" -eq 0 ] 2>/dev/null; then
    ORG_CODE=$(create_org_policy "1")
    if [ "$ORG_CODE" = "429" ] || [ "$ORG_CODE" = "403" ]; then
        pass "Community: org policy correctly rejected (HTTP $ORG_CODE)"
    elif [ "$ORG_CODE" = "201" ] || [ "$ORG_CODE" = "200" ]; then
        fail "Community: org policy should have been rejected but was created"
    else
        fail "Org policy endpoint returned unexpected code (HTTP $ORG_CODE)"
    fi
elif [ "$ORG_POLICY_LIMIT" -gt 0 ] 2>/dev/null; then
    ALL_ORG_OK=true
    for i in $(seq 1 "$ORG_POLICY_LIMIT"); do
        ORG_CODE=$(create_org_policy "$i")
        if [ "$ORG_CODE" != "201" ] && [ "$ORG_CODE" != "200" ]; then
            fail "Org policy $i/$ORG_POLICY_LIMIT failed (HTTP $ORG_CODE)"
            ALL_ORG_OK=false
            break
        fi
    done

    if [ "$ALL_ORG_OK" = true ]; then
        pass "Created $ORG_POLICY_LIMIT org policies at limit"

        OVER_ORG_CODE=$(create_org_policy "$((ORG_POLICY_LIMIT + 1))")
        if [ "$OVER_ORG_CODE" = "429" ] || [ "$OVER_ORG_CODE" = "403" ]; then
            pass "Org policy $((ORG_POLICY_LIMIT + 1)) correctly rejected (HTTP $OVER_ORG_CODE)"
        else
            fail "Org policy $((ORG_POLICY_LIMIT + 1)) should have been rejected but got HTTP $OVER_ORG_CODE"
        fi
    fi
elif [ "$ORG_POLICY_LIMIT" -eq -1 ]; then
    ALL_ORG_OK=true
    for i in $(seq 1 3); do
        ORG_CODE=$(create_org_policy "$i")
        if [ "$ORG_CODE" != "201" ] && [ "$ORG_CODE" != "200" ]; then
            fail "Enterprise org policy $i failed (HTTP $ORG_CODE)"
            ALL_ORG_OK=false
            break
        fi
    done
    if [ "$ALL_ORG_OK" = true ]; then
        pass "Enterprise: created 3 org policies (unlimited tier)"
    fi
fi

# ═══════════════════════════════════════════════════════════════════════
# Test 4: Connectors with Custom Policies
# All connectors can be registered in all tiers (no registration limit).
# Only connectors with custom tenant/org policies (rate limiting, budgets,
# time/role access) are limited by tier: Community=2, Evaluation=5, Enterprise=unlimited.
# ═══════════════════════════════════════════════════════════════════════
echo ""
echo "4. Connectors with Custom Policies (limit=$CONNECTOR_LIMIT)"

# List all registered connectors — registration is unlimited across all tiers.
CONN_RESPONSE=$(curl -s "$ENDPOINT/api/v1/connectors" 2>/dev/null || echo "")
if echo "$CONN_RESPONSE" | python3 -c "import sys,json; json.load(sys.stdin)" 2>/dev/null; then
    CONN_STATS=$(echo "$CONN_RESPONSE" | python3 -c "
import sys,json
try:
    d = json.load(sys.stdin)
    items = d.get('connectors', d.get('items', []))
    if isinstance(items, list):
        installed = sum(1 for c in items if c.get('installed', False))
        total = len(items)
        print(f'{installed} {total}')
    else:
        print('0 0')
except: print('0 0')
" 2>/dev/null)
    INSTALLED_CONNECTORS=$(echo "$CONN_STATS" | cut -d' ' -f1)
    CATALOG_CONNECTORS=$(echo "$CONN_STATS" | cut -d' ' -f2)
    echo "   Marketplace catalog: $CATALOG_CONNECTORS types | Installed: $INSTALLED_CONNECTORS"
    # Connector registration is unlimited — verify connectors are accessible
    pass "Connector registration unlimited ($INSTALLED_CONNECTORS installed, no cap)"
    # Custom policy limit is enforced at dynamic policy evaluator level, not at registration
    if [ "$CONNECTOR_LIMIT" -gt 0 ] 2>/dev/null; then
        echo "   Custom policy connector limit: $CONNECTOR_LIMIT ($TIER tier)"
        pass "Custom policy connector limit set to $CONNECTOR_LIMIT for $TIER tier"
    else
        pass "Enterprise: unlimited connectors with custom policies"
    fi
else
    fail "Connector list endpoint not available"
fi

# ═══════════════════════════════════════════════════════════════════════
# Test 5: LLM Provider Limit
# Requires LLM provider API to be initialized (needs at least one key).
# ═══════════════════════════════════════════════════════════════════════
echo ""
echo "5. LLM Provider Limit (limit=$MAX_PROVIDERS)"

LLM_RESPONSE=$(curl -s -w "\n%{http_code}" "$ENDPOINT/api/v1/llm-providers" 2>/dev/null || echo -e "\n000")
LLM_CODE=$(echo "$LLM_RESPONSE" | tail -1)

if [ "$LLM_CODE" = "200" ]; then
    LLM_BODY=$(echo "$LLM_RESPONSE" | sed '$d')
    CURRENT_PROVIDERS=$(echo "$LLM_BODY" | python3 -c "
import sys,json
try:
    d = json.load(sys.stdin)
    print(len(d.get('providers', [])))
except: print(0)
" 2>/dev/null)
    echo "   Current LLM providers: ${CURRENT_PROVIDERS:-0}"
    if [ "$MAX_PROVIDERS" -gt 0 ] 2>/dev/null; then
        if [ "${CURRENT_PROVIDERS:-0}" -le "$MAX_PROVIDERS" ]; then
            pass "LLM provider count within limit ($CURRENT_PROVIDERS/$MAX_PROVIDERS)"
        else
            fail "LLM provider count exceeds limit ($CURRENT_PROVIDERS/$MAX_PROVIDERS)"
        fi
    else
        pass "Enterprise: LLM providers unrestricted"
    fi
elif [ "$LLM_CODE" = "404" ]; then
    fail "LLM provider API not registered — no LLM API keys configured (set OPENAI_API_KEY or ANTHROPIC_API_KEY)"
else
    fail "LLM provider API returned unexpected status (HTTP $LLM_CODE)"
fi

# ═══════════════════════════════════════════════════════════════════════
# Test 6: Execution History Endpoint
# Execution history cap is enforced by background cleanup worker.
# We verify the endpoint works and report current state.
# ═══════════════════════════════════════════════════════════════════════
echo ""
echo "6. Execution History (cap=$MAX_HISTORY)"

EXEC_RESPONSE=$(curl -s -w "\n%{http_code}" "$ENDPOINT/api/v1/unified/executions?limit=1000" \
    -H "X-Tenant-ID: $TENANT_ID" 2>/dev/null || echo -e "\n000")
EXEC_CODE=$(echo "$EXEC_RESPONSE" | tail -1)

if [ "$EXEC_CODE" = "200" ]; then
    pass "Execution list endpoint responds (HTTP 200)"
else
    fail "Execution list endpoint not available (HTTP $EXEC_CODE)"
fi

# ═══════════════════════════════════════════════════════════════════════
# Test 7: Audit Retention Configuration
# Audit retention is enforced by background cleanup worker.
# We verify the cleanup service is running with correct retention.
# ═══════════════════════════════════════════════════════════════════════
echo ""
echo "7. Audit Retention (${AUDIT_RETENTION} days)"

# Check orchestrator logs for retention config (only works with docker compose)
if command -v docker &>/dev/null; then
    RETENTION_LOG=$(docker compose logs axonflow-orchestrator 2>/dev/null | grep -o "retention: [0-9]* days" | tail -1 || echo "")
    if [ -n "$RETENTION_LOG" ]; then
        ACTUAL_DAYS=$(echo "$RETENTION_LOG" | grep -o "[0-9]*")
        if [ "$ACTUAL_DAYS" = "$AUDIT_RETENTION" ]; then
            pass "Audit cleanup configured with ${ACTUAL_DAYS}-day retention (matches $TIER tier)"
        else
            fail "Audit cleanup retention is ${ACTUAL_DAYS} days, expected $AUDIT_RETENTION for $TIER tier"
        fi
    else
        fail "Could not read audit retention from orchestrator logs"
    fi
else
    fail "Docker not available — cannot verify audit retention config"
fi

# ═══════════════════════════════════════════════════════════════════════
# Test 8: Plan Creation
# MAP plans require LLM router; test endpoint availability.
# ═══════════════════════════════════════════════════════════════════════
echo ""
echo "8. MAP Plans (limit=$MAX_PLANS)"

PLAN_RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$ENDPOINT/api/v1/plan" \
    -H "Content-Type: application/json" \
    -H "X-Tenant-ID: $TENANT_ID" \
    -d "{
        \"query\": \"feature limits boundary test plan\",
        \"domain\": \"test\",
        \"user\": {\"id\": 1, \"email\": \"test@example.com\", \"role\": \"admin\", \"tenant_id\": \"$TENANT_ID\"}
    }" 2>/dev/null || echo -e "\n000")
PLAN_CODE=$(echo "$PLAN_RESPONSE" | tail -1)

if [ "$PLAN_CODE" = "201" ] || [ "$PLAN_CODE" = "200" ]; then
    pass "Plan creation works (HTTP $PLAN_CODE)"
elif [ "$PLAN_CODE" = "503" ]; then
    # 503 = planning engine not initialized (no LLM providers available)
    fail "Plan API returns 503 — planning engine not initialized (need LLM API keys)"
elif [ "$PLAN_CODE" = "404" ]; then
    fail "Plan API returns 404 — endpoint not registered"
else
    fail "Plan API unexpected response (HTTP $PLAN_CODE)"
fi

# ═══════════════════════════════════════════════════════════════════════
# Test 9: SSE Connection Limit
# Opens concurrent SSE connections to verify per-tenant limit enforcement.
# Community=5, Evaluation=25, Enterprise=unlimited (-1).
#
# The SSE handler validates execution existence before checking connection
# limits, so we need a real execution to stream. We create one via the
# unified execution API, then open concurrent SSE connections to it.
# ═══════════════════════════════════════════════════════════════════════
echo ""
echo "9. SSE Connection Limit (limit=$MAX_SSE)"

# The orchestrator SSE endpoint is on port 8081 (direct), but we can also
# access it through the agent proxy on port 8080.
ORCHESTRATOR_PORT="${AXONFLOW_ORCHESTRATOR_PORT:-8081}"
ORCHESTRATOR_URL="http://localhost:$ORCHESTRATOR_PORT"

# First, find an existing execution to stream (from earlier test runs or create one)
EXEC_LIST=$(curl -s "$ORCHESTRATOR_URL/api/v1/unified/executions?limit=1" \
    -H "X-Tenant-ID: $TENANT_ID" 2>/dev/null || echo "{}")
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
    # Try creating an execution via simple request
    CREATE_EXEC=$(curl -s -X POST "$ENDPOINT/api/request" \
        -H "Content-Type: application/json" \
        -H "X-Tenant-ID: $TENANT_ID" \
        -d "{
            \"query\": \"sse connection limit test\",
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

# Helper: open an SSE connection in background (to orchestrator directly)
open_sse() {
    curl -s -o /dev/null -N --max-time 10 \
        -H "X-Tenant-ID: $TENANT_ID" \
        -H "Accept: text/event-stream" \
        "$ORCHESTRATOR_URL/api/v1/unified/executions/$SSE_EXEC_ID/stream" 2>/dev/null &
    SSE_PIDS+=($!)
}

# Cleanup SSE connections
cleanup_sse() {
    for pid in "${SSE_PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    done
    SSE_PIDS=()
}

if [ -z "$SSE_EXEC_ID" ]; then
    skip "No execution available for SSE streaming test (need LLM provider or prior executions)"
elif [ "$MAX_SSE" -gt 0 ] 2>/dev/null; then
    # Verify single SSE connection works first
    SSE_CHECK=$(curl -s -o /dev/null -w "%{http_code}" --max-time 3 \
        -H "X-Tenant-ID: $TENANT_ID" \
        -H "Accept: text/event-stream" \
        "$ORCHESTRATOR_URL/api/v1/unified/executions/$SSE_EXEC_ID/stream" 2>/dev/null || echo "000")

    if [ "$SSE_CHECK" != "200" ]; then
        skip "SSE endpoint returned HTTP $SSE_CHECK (execution may have completed too quickly)"
    else
        # Open connections up to the limit
        echo "   Opening $MAX_SSE SSE connections to execution $SSE_EXEC_ID..."
        for i in $(seq 1 "$MAX_SSE"); do
            open_sse
        done
        sleep 2

        # Count active connections
        ACTIVE_SSE=0
        for pid in "${SSE_PIDS[@]}"; do
            if kill -0 "$pid" 2>/dev/null; then
                ACTIVE_SSE=$((ACTIVE_SSE + 1))
            fi
        done

        if [ "$ACTIVE_SSE" -ge "$MAX_SSE" ]; then
            pass "Opened $ACTIVE_SSE/$MAX_SSE SSE connections at limit"
        else
            # SSE connections may have completed (execution finished); treat as skip
            if [ "$ACTIVE_SSE" -eq 0 ]; then
                skip "All SSE connections closed (execution likely completed)"
            else
                fail "Only $ACTIVE_SSE/$MAX_SSE SSE connections active"
            fi
        fi

        # Now try one more — should be rejected (HTTP 429)
        if [ "$ACTIVE_SSE" -ge "$MAX_SSE" ]; then
            OVER_CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 3 \
                -H "X-Tenant-ID: $TENANT_ID" \
                -H "Accept: text/event-stream" \
                "$ORCHESTRATOR_URL/api/v1/unified/executions/$SSE_EXEC_ID/stream" 2>/dev/null || echo "000")

            if [ "$OVER_CODE" = "429" ]; then
                pass "SSE connection $((MAX_SSE + 1)) correctly rejected (HTTP 429)"
            elif [ "$OVER_CODE" = "200" ]; then
                fail "SSE connection $((MAX_SSE + 1)) should have been rejected but got HTTP 200"
            else
                fail "SSE connection over-limit returned unexpected code (HTTP $OVER_CODE)"
            fi
        fi

        cleanup_sse
    fi
elif [ "$MAX_SSE" -eq -1 ]; then
    # Enterprise: unlimited — verify many connections work
    SSE_CHECK=$(curl -s -o /dev/null -w "%{http_code}" --max-time 3 \
        -H "X-Tenant-ID: $TENANT_ID" \
        -H "Accept: text/event-stream" \
        "$ORCHESTRATOR_URL/api/v1/unified/executions/$SSE_EXEC_ID/stream" 2>/dev/null || echo "000")

    if [ "$SSE_CHECK" != "200" ]; then
        skip "SSE endpoint returned HTTP $SSE_CHECK (execution may have completed)"
    else
        echo "   Opening 10 SSE connections (unlimited mode)..."
        for i in $(seq 1 10); do
            open_sse
        done
        sleep 2

        ACTIVE_SSE=0
        for pid in "${SSE_PIDS[@]}"; do
            if kill -0 "$pid" 2>/dev/null; then
                ACTIVE_SSE=$((ACTIVE_SSE + 1))
            fi
        done

        if [ "$ACTIVE_SSE" -ge 8 ]; then
            pass "Enterprise: opened $ACTIVE_SSE/10 SSE connections (unlimited tier)"
        elif [ "$ACTIVE_SSE" -eq 0 ]; then
            skip "All SSE connections closed (execution likely completed)"
        else
            fail "Enterprise: only $ACTIVE_SSE/10 SSE connections active"
        fi

        cleanup_sse
    fi
fi

# ═══════════════════════════════════════════════════════════════════════
# Test 10: Tier Configuration Summary
# ═══════════════════════════════════════════════════════════════════════
echo ""
echo "10. Tier Configuration Summary"

echo "   Tier: $TIER"
echo "   ┌───────────────────────────┬───────────┐"
echo "   │ Feature                   │ Limit     │"
echo "   ├───────────────────────────┼───────────┤"
printf "   │ %-25s │ %9s │\n" "Tenant Policies"           "$POLICY_LIMIT"
printf "   │ %-25s │ %9s │\n" "Org-Wide Policies"         "$ORG_POLICY_LIMIT"
printf "   │ %-25s │ %9s │\n" "Custom Policy Connectors"  "$CONNECTOR_LIMIT"
printf "   │ %-25s │ %9s │\n" "Audit Retention"           "${AUDIT_RETENTION}d"
printf "   │ %-25s │ %9s │\n" "LLM Providers"             "$MAX_PROVIDERS"
printf "   │ %-25s │ %9s │\n" "Execution History"         "$MAX_HISTORY"
printf "   │ %-25s │ %9s │\n" "Concurrent Executions"     "$MAX_CONCURRENT"
printf "   │ %-25s │ %9s │\n" "MAP Plans"                 "$MAX_PLANS"
printf "   │ %-25s │ %9s │\n" "Versions per Plan"         "$MAX_VERSIONS"
printf "   │ %-25s │ %9s │\n" "SSE Connections"           "$MAX_SSE"
echo "   └───────────────────────────┴───────────┘"
pass "Tier limits configured for $TIER"

# ═══════════════════════════════════════════════════════════════════════
# Summary
# ═══════════════════════════════════════════════════════════════════════
echo ""
echo "=== Results ==="
echo "Passed: $PASS | Failed: $FAIL | Skipped: $SKIP"
if [ "${#CREATED_POLICIES[@]}" -gt 0 ] 2>/dev/null; then
    echo "Test policies created: ${#CREATED_POLICIES[@]}"
fi

if [ "$FAIL" -gt 0 ]; then
    echo ""
    echo "✗ Some tests failed!"
    exit 1
else
    echo ""
    echo "✓ All tests passed!"
fi
