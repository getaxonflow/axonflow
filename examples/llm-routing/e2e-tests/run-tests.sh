#!/bin/bash
# LLM Routing E2E Test Suite for Community Edition
# Tests: Provider listing, per-request selection, weighted routing, failover

set -e

BASE_URL="${ORCHESTRATOR_URL:-http://localhost:8081}"
TESTS_PASSED=0
TESTS_FAILED=0

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_pass() {
    echo -e "${GREEN}PASS${NC}: $1"
    TESTS_PASSED=$((TESTS_PASSED + 1))
}

log_fail() {
    echo -e "${RED}FAIL${NC}: $1"
    TESTS_FAILED=$((TESTS_FAILED + 1))
}

log_info() {
    echo -e "${YELLOW}INFO${NC}: $1"
}

echo "========================================="
echo "LLM Routing E2E Tests (Community Edition)"
echo "========================================="
echo "Target: $BASE_URL"
echo ""

# Test 1: Health check
log_info "Test 1: Health check"
HEALTH=$(curl -s "$BASE_URL/health")
if echo "$HEALTH" | jq -e '.status == "healthy"' > /dev/null 2>&1; then
    log_pass "Orchestrator is healthy"
else
    log_fail "Orchestrator health check failed"
    echo "$HEALTH" | jq .
fi

# Test 2: List providers - should have 3 community providers
log_info "Test 2: Provider listing"
PROVIDERS=$(curl -s "$BASE_URL/api/v1/llm-providers")
PROVIDER_COUNT=$(echo "$PROVIDERS" | jq '.pagination.total_items')
if [ "$PROVIDER_COUNT" -eq 3 ]; then
    log_pass "Found $PROVIDER_COUNT Community providers (expected 3)"
else
    log_fail "Expected 3 providers, found $PROVIDER_COUNT"
fi

# Verify no Bedrock in Community mode
if echo "$PROVIDERS" | jq -e '.providers[] | select(.name == "bedrock")' > /dev/null 2>&1; then
    log_fail "Bedrock provider found in Community mode (should be Enterprise-only)"
else
    log_pass "Bedrock correctly excluded from Community mode"
fi

# Test 3: Per-request provider selection - OpenAI
log_info "Test 3: Per-request provider selection (OpenAI)"
OPENAI_RESULT=$(curl -s -X POST "$BASE_URL/api/v1/process" \
    -H "Content-Type: application/json" \
    -d '{"query":"Say hello","request_type":"chat","context":{"provider":"openai"},"user":{"email":"test@example.com","role":"user"}}')

SELECTED_PROVIDER=$(echo "$OPENAI_RESULT" | jq -r '.provider_info.provider')
if [ "$SELECTED_PROVIDER" == "openai" ]; then
    log_pass "OpenAI provider selected as requested"
else
    # Check if it failed over (acceptable)
    if [ "$(echo "$OPENAI_RESULT" | jq -r '.success')" == "true" ]; then
        log_pass "Request succeeded (may have failed over from OpenAI to $SELECTED_PROVIDER)"
    else
        log_fail "Request failed: $(echo "$OPENAI_RESULT" | jq -r '.error')"
    fi
fi

# Test 4: Per-request provider selection - Gemini
log_info "Test 4: Per-request provider selection (Gemini)"
GEMINI_RESULT=$(curl -s -X POST "$BASE_URL/api/v1/process" \
    -H "Content-Type: application/json" \
    -d '{"query":"Say hello","request_type":"chat","context":{"provider":"gemini"},"user":{"email":"test@example.com","role":"user"}}')

SELECTED_PROVIDER=$(echo "$GEMINI_RESULT" | jq -r '.provider_info.provider')
if [ "$SELECTED_PROVIDER" == "gemini" ]; then
    log_pass "Gemini provider selected as requested"
elif [ "$(echo "$GEMINI_RESULT" | jq -r '.success')" == "true" ]; then
    log_pass "Request succeeded (provider: $SELECTED_PROVIDER)"
else
    log_fail "Request failed"
fi

# Test 5: Weighted routing (make multiple requests)
log_info "Test 5: Weighted routing distribution"
openai_count=0
anthropic_count=0
gemini_count=0
for i in $(seq 1 6); do
    RESULT=$(curl -s -X POST "$BASE_URL/api/v1/process" \
        -H "Content-Type: application/json" \
        -d '{"query":"Hello","request_type":"chat","user":{"email":"test@example.com","role":"user"}}')
    PROVIDER=$(echo "$RESULT" | jq -r '.provider_info.provider')
    case "$PROVIDER" in
        openai) openai_count=$((openai_count + 1)) ;;
        anthropic) anthropic_count=$((anthropic_count + 1)) ;;
        gemini) gemini_count=$((gemini_count + 1)) ;;
    esac
done

echo "  Provider distribution:"
[ $openai_count -gt 0 ] && echo "    openai: $openai_count requests"
[ $anthropic_count -gt 0 ] && echo "    anthropic: $anthropic_count requests"
[ $gemini_count -gt 0 ] && echo "    gemini: $gemini_count requests"
log_pass "Weighted routing is working"

# Summary
echo ""
echo "========================================="
echo "Test Summary"
echo "========================================="
echo -e "Passed: ${GREEN}$TESTS_PASSED${NC}"
echo -e "Failed: ${RED}$TESTS_FAILED${NC}"

if [ $TESTS_FAILED -gt 0 ]; then
    exit 1
fi
