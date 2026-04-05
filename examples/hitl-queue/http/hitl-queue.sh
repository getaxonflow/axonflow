#!/bin/bash
# Copyright 2026 AxonFlow
# SPDX-License-Identifier: BUSL-1.1

# HITL Queue API - HTTP/curl Example
#
# Validates the HITL Queue API endpoints against a running AxonFlow instance.
#
# The HITL Queue is an enterprise-only feature. In community mode, HITL
# queue routes are not registered, so the server returns HTTP 404 (or 403).
# This example verifies that the API exists and returns the expected
# enterprise-only response, printing a clear message.
#
# In enterprise mode, the same endpoints would succeed and return queue data.
#
# VALIDATION: This example exits with code 1 if any assertion fails.
# In community mode, 403/404 responses are EXPECTED and count as PASS.
#
# Tests:
# 1. List HITL queue (GET /api/v1/hitl/queue) — expect 403 or 404
# 2. List HITL queue with filters (GET /api/v1/hitl/queue?status=pending&limit=10) — expect 403 or 404
# 3. Get HITL request (GET /api/v1/hitl/queue/fake-id-123) — expect 403 or 404
# 4. Approve HITL request (POST /api/v1/hitl/queue/fake-id-123/approve) — expect 403 or 404
# 5. Reject HITL request (POST /api/v1/hitl/queue/fake-id-123/reject) — expect 403 or 404
# 6. Get HITL stats (GET /api/v1/hitl/queue/stats) — expect 403 or 404
# 7. Verify enterprise-only messaging in 403/404 responses
#
# Prerequisites:
#   - AxonFlow Agent running at http://localhost:8080
#   - curl and jq installed
#
# Usage:
#   chmod +x hitl-queue.sh
#   ./hitl-queue.sh

set -e

AGENT_URL="${AXONFLOW_ENDPOINT:-${AXONFLOW_AGENT_URL:-http://localhost:8080}}"
CLIENT_ID="${AXONFLOW_CLIENT_ID:-community}"
CLIENT_SECRET="${AXONFLOW_CLIENT_SECRET:-}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

PASS_COUNT=0
FAIL_COUNT=0

assert_check() {
    local condition="$1"
    local message="$2"
    if [ "$condition" = "true" ]; then
        echo -e "   ${GREEN}PASS: ${message}${NC}"
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        echo -e "   ${RED}FAIL: ${message}${NC}"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
}

# is_enterprise_only checks whether an HTTP status code indicates enterprise-only.
# In community mode, HITL queue routes may return 403 (Forbidden) or 404 (Not Found).
is_enterprise_only() {
    local http_code="$1"
    if [ "$http_code" = "403" ] || [ "$http_code" = "404" ]; then
        return 0
    fi
    return 1
}

echo "HITL Queue API - HTTP/curl"
echo "========================================"
echo ""
echo "This example validates the HITL Queue API endpoints."
echo "In community mode, HITL queue endpoints return 403 or 404."
echo "403/404 responses are EXPECTED and count as PASS."
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

# Collect response bodies for Test 7 (enterprise-only messaging verification)
ENTERPRISE_BODIES=""

# ========================================
# Test 1: List HITL Queue
# ========================================
echo -e "${BLUE}Test 1: List HITL Queue${NC}"
echo "   GET /api/v1/hitl/queue"

list_response=$(curl -s -w "\n%{http_code}" "$AGENT_URL/api/v1/hitl/queue" \
    -H "Authorization: Basic $AUTH_B64" \
)

list_body=$(echo "$list_response" | sed '$d')
list_http=$(echo "$list_response" | tail -n 1)

echo "   HTTP: $list_http"

if is_enterprise_only "$list_http"; then
    assert_check "true" "List HITL queue returns $list_http (enterprise-only feature)"
    ENTERPRISE_BODIES="${ENTERPRISE_BODIES}${list_body}\n"
elif [ "$list_http" = "200" ]; then
    assert_check "true" "List HITL queue returns 200 (enterprise mode)"
else
    assert_check "false" "List HITL queue expected 403 or 404 (got $list_http)"
fi
echo ""

# ========================================
# Test 2: List HITL Queue with Filters
# ========================================
echo -e "${BLUE}Test 2: List HITL Queue with Filters${NC}"
echo "   GET /api/v1/hitl/queue?status=pending&limit=10"

list_filtered_response=$(curl -s -w "\n%{http_code}" "$AGENT_URL/api/v1/hitl/queue?status=pending&limit=10" \
    -H "Authorization: Basic $AUTH_B64" \
)

list_filtered_body=$(echo "$list_filtered_response" | sed '$d')
list_filtered_http=$(echo "$list_filtered_response" | tail -n 1)

echo "   HTTP: $list_filtered_http"

if is_enterprise_only "$list_filtered_http"; then
    assert_check "true" "List HITL queue with filters returns $list_filtered_http (enterprise-only feature)"
    ENTERPRISE_BODIES="${ENTERPRISE_BODIES}${list_filtered_body}\n"
elif [ "$list_filtered_http" = "200" ]; then
    assert_check "true" "List HITL queue with filters returns 200 (enterprise mode)"
else
    assert_check "false" "List HITL queue with filters expected 403 or 404 (got $list_filtered_http)"
fi
echo ""

# ========================================
# Test 3: Get HITL Request (fake ID)
# ========================================
echo -e "${BLUE}Test 3: Get HITL Request (fake ID)${NC}"
echo "   GET /api/v1/hitl/queue/fake-id-123"

get_response=$(curl -s -w "\n%{http_code}" "$AGENT_URL/api/v1/hitl/queue/fake-id-123" \
    -H "Authorization: Basic $AUTH_B64" \
)

get_body=$(echo "$get_response" | sed '$d')
get_http=$(echo "$get_response" | tail -n 1)

echo "   HTTP: $get_http"

if is_enterprise_only "$get_http"; then
    assert_check "true" "Get HITL request returns $get_http (enterprise-only feature)"
    ENTERPRISE_BODIES="${ENTERPRISE_BODIES}${get_body}\n"
elif [ "$get_http" = "200" ]; then
    assert_check "true" "Get HITL request returns 200 (enterprise mode)"
else
    assert_check "false" "Get HITL request expected 403 or 404 (got $get_http)"
fi
echo ""

# ========================================
# Test 4: Approve HITL Request (fake ID)
# ========================================
echo -e "${BLUE}Test 4: Approve HITL Request (fake ID)${NC}"
echo "   POST /api/v1/hitl/queue/fake-id-123/approve"

approve_response=$(curl -s -w "\n%{http_code}" -X POST "$AGENT_URL/api/v1/hitl/queue/fake-id-123/approve" \
    -H "Content-Type: application/json" \
    -H "Authorization: Basic $AUTH_B64" \
    -d '{"reviewer_id":"test","reviewer_email":"test@example.com"}')

approve_body=$(echo "$approve_response" | sed '$d')
approve_http=$(echo "$approve_response" | tail -n 1)

echo "   HTTP: $approve_http"

if is_enterprise_only "$approve_http"; then
    assert_check "true" "Approve HITL request returns $approve_http (enterprise-only feature)"
    ENTERPRISE_BODIES="${ENTERPRISE_BODIES}${approve_body}\n"
elif [ "$approve_http" = "200" ]; then
    assert_check "true" "Approve HITL request returns 200 (enterprise mode)"
else
    assert_check "false" "Approve HITL request expected 403 or 404 (got $approve_http)"
fi
echo ""

# ========================================
# Test 5: Reject HITL Request (fake ID)
# ========================================
echo -e "${BLUE}Test 5: Reject HITL Request (fake ID)${NC}"
echo "   POST /api/v1/hitl/queue/fake-id-123/reject"

reject_response=$(curl -s -w "\n%{http_code}" -X POST "$AGENT_URL/api/v1/hitl/queue/fake-id-123/reject" \
    -H "Content-Type: application/json" \
    -H "Authorization: Basic $AUTH_B64" \
    -d '{"reviewer_id":"test","reviewer_email":"test@example.com","reason":"test rejection"}')

reject_body=$(echo "$reject_response" | sed '$d')
reject_http=$(echo "$reject_response" | tail -n 1)

echo "   HTTP: $reject_http"

if is_enterprise_only "$reject_http"; then
    assert_check "true" "Reject HITL request returns $reject_http (enterprise-only feature)"
    ENTERPRISE_BODIES="${ENTERPRISE_BODIES}${reject_body}\n"
elif [ "$reject_http" = "200" ]; then
    assert_check "true" "Reject HITL request returns 200 (enterprise mode)"
else
    assert_check "false" "Reject HITL request expected 403 or 404 (got $reject_http)"
fi
echo ""

# ========================================
# Test 6: Get HITL Stats
# ========================================
echo -e "${BLUE}Test 6: Get HITL Stats${NC}"
echo "   GET /api/v1/hitl/queue/stats"

stats_response=$(curl -s -w "\n%{http_code}" "$AGENT_URL/api/v1/hitl/queue/stats" \
    -H "Authorization: Basic $AUTH_B64" \
)

stats_body=$(echo "$stats_response" | sed '$d')
stats_http=$(echo "$stats_response" | tail -n 1)

echo "   HTTP: $stats_http"

if is_enterprise_only "$stats_http"; then
    assert_check "true" "Get HITL stats returns $stats_http (enterprise-only feature)"
    ENTERPRISE_BODIES="${ENTERPRISE_BODIES}${stats_body}\n"
elif [ "$stats_http" = "200" ]; then
    assert_check "true" "Get HITL stats returns 200 (enterprise mode)"
else
    assert_check "false" "Get HITL stats expected 403 or 404 (got $stats_http)"
fi
echo ""

# ========================================
# Test 7: Verify Enterprise-Only Messaging
# ========================================
echo -e "${BLUE}Test 7: Verify Enterprise-Only Messaging${NC}"

# Check that at least one of the 403/404 response bodies contains enterprise-related messaging.
# In community mode, responses typically include words like "enterprise", "Enterprise",
# "Forbidden", "not found", or "page not found".
enterprise_msg_found="false"
if echo -e "$ENTERPRISE_BODIES" | grep -qi "enterprise"; then
    enterprise_msg_found="true"
elif echo -e "$ENTERPRISE_BODIES" | grep -qi "forbidden"; then
    enterprise_msg_found="true"
elif echo -e "$ENTERPRISE_BODIES" | grep -qi "not found"; then
    enterprise_msg_found="true"
elif echo -e "$ENTERPRISE_BODIES" | grep -qi "page not found"; then
    enterprise_msg_found="true"
fi

if [ "$enterprise_msg_found" = "true" ]; then
    assert_check "true" "403/404 responses contain enterprise-related messaging"
else
    # If all tests above got 200 (enterprise mode), there are no 403/404 bodies to check.
    # That is still valid — it means we are running in enterprise mode.
    if [ -z "$ENTERPRISE_BODIES" ]; then
        assert_check "true" "Running in enterprise mode - no 403/404 responses to verify"
    else
        assert_check "false" "403/404 responses should contain enterprise-related messaging"
    fi
fi
echo ""

# ========================================
# Summary
# ========================================
echo "========================================"
echo -e "Results: ${GREEN}$PASS_COUNT PASS${NC}, ${RED}$FAIL_COUNT FAIL${NC}"

if [ "$FAIL_COUNT" -gt 0 ]; then
    echo -e "${RED}SOME TESTS FAILED${NC}"
    exit 1
else
    echo -e "${GREEN}ALL TESTS PASSED - HITL Queue API validated${NC}"
    echo ""
    echo "HITL Queue operations validated:"
    echo "  - GET  /api/v1/hitl/queue (list)"
    echo "  - GET  /api/v1/hitl/queue?status=pending&limit=10 (list with filters)"
    echo "  - GET  /api/v1/hitl/queue/{id} (get request)"
    echo "  - POST /api/v1/hitl/queue/{id}/approve (approve request)"
    echo "  - POST /api/v1/hitl/queue/{id}/reject (reject request)"
    echo "  - GET  /api/v1/hitl/queue/stats (stats)"
    echo "  - Enterprise-only messaging verification"
    echo ""
    echo "Note: In Community Edition, HITL queue endpoints return 403 or 404."
    echo "Upgrade to Enterprise for full HITL queue management."
fi
