#!/usr/bin/env bash
# Decision Mode PoC — end-to-end test harness.
#
# Prerequisites: docker compose up -d --build (services healthy)
# Usage:         ./test.sh
# Exit code:     0 = all pass, 1 = at least one failure
#
# Deny-path verification: on policy deny, the test confirms the
# request was BLOCKED before reaching the upstream mock by checking
# the mock's /stats endpoint (request_count must not increase).

set -euo pipefail

ADAPTER_URL="${ADAPTER_URL:-http://localhost:8888}"
MOCK_URL="${MOCK_URL:-http://localhost:9090}"
PASS=0
FAIL=0
TESTS=()

pass() { PASS=$((PASS + 1)); TESTS+=("PASS: $1"); echo "  ✓ PASS: $1"; }
fail() { FAIL=$((FAIL + 1)); TESTS+=("FAIL: $1"); echo "  ✗ FAIL: $1"; }

get_mock_count() {
    curl -s "$MOCK_URL/stats" | python3 -c "import json,sys; print(json.load(sys.stdin)['request_count'])" 2>/dev/null || echo "-1"
}

echo "============================================================"
echo "Decision Mode PoC — End-to-End Tests"
echo "============================================================"
echo ""

# Reset mock stats
curl -s "$MOCK_URL/stats/reset" > /dev/null

# ------------------------------------------------------------------
# Test 1: Clean request -> expect allow (200) + trace_id + mock hit
# ------------------------------------------------------------------
echo "Test 1: Clean request (expect allow)"
COUNT_BEFORE=$(get_mock_count)
RESP=$(curl -s -w "\n%{http_code}" -X POST "$ADAPTER_URL/v1/chat/completions" \
    -H "Content-Type: application/json" \
    -D /tmp/poc-headers-clean.txt \
    -d '{
        "model": "gpt-4o-mini",
        "messages": [
            {"role": "system", "content": "You are helpful."},
            {"role": "user", "content": "What are best practices for AI deployment?"}
        ]
    }')

HTTP_CODE=$(echo "$RESP" | tail -1)
BODY=$(echo "$RESP" | sed '$d')
TRACE_ID=$(grep -i "x-axonflow-trace-id" /tmp/poc-headers-clean.txt 2>/dev/null | tr -d '\r' | awk '{print $2}' || true)
COUNT_AFTER=$(get_mock_count)

if [ "$HTTP_CODE" = "200" ]; then pass "clean request returns 200"; else fail "clean request returns 200 (got $HTTP_CODE)"; fi
if echo "$BODY" | grep -q "chat.completion"; then pass "clean response contains chat completion"; else fail "clean response contains chat completion"; fi
if [ -n "$TRACE_ID" ]; then pass "clean response has trace_id header"; else fail "clean response has trace_id header"; fi
if [ "$COUNT_AFTER" -gt "$COUNT_BEFORE" ]; then pass "clean request reached upstream mock (count $COUNT_BEFORE->$COUNT_AFTER)"; else fail "clean request should reach upstream mock (count $COUNT_BEFORE->$COUNT_AFTER)"; fi
echo ""

# ------------------------------------------------------------------
# Test 2: PII request (SSN) -> expect deny (403) + mock NOT hit
# ------------------------------------------------------------------
echo "Test 2: PII request — SSN (expect deny)"
COUNT_BEFORE=$(get_mock_count)
RESP=$(curl -s -w "\n%{http_code}" -X POST "$ADAPTER_URL/v1/chat/completions" \
    -H "Content-Type: application/json" \
    -D /tmp/poc-headers-pii.txt \
    -d '{
        "model": "gpt-4o-mini",
        "messages": [
            {"role": "user", "content": "Process refund for customer with SSN 123-45-6789 and credit card 4111-1111-1111-1111"}
        ]
    }')

HTTP_CODE=$(echo "$RESP" | tail -1)
BODY=$(echo "$RESP" | sed '$d')
PII_TRACE=$(grep -i "x-axonflow-trace-id" /tmp/poc-headers-pii.txt 2>/dev/null | tr -d '\r' | awk '{print $2}' || true)
COUNT_AFTER=$(get_mock_count)

if [ "$HTTP_CODE" = "403" ]; then pass "PII request returns 403"; else fail "PII request returns 403 (got $HTTP_CODE)"; fi
if echo "$BODY" | grep -q "policy_deny"; then pass "PII response contains policy_deny"; else fail "PII response contains policy_deny"; fi
if [ -n "$PII_TRACE" ]; then pass "PII response has trace_id header"; else fail "PII response has trace_id header"; fi
if echo "$BODY" | grep -q "decision_id"; then pass "PII response has decision_id"; else fail "PII response has decision_id"; fi
if [ "$COUNT_AFTER" = "$COUNT_BEFORE" ]; then pass "PII request did NOT reach upstream mock (count stayed $COUNT_BEFORE)"; else fail "PII request SHOULD NOT reach upstream mock (count $COUNT_BEFORE->$COUNT_AFTER)"; fi
echo ""

# ------------------------------------------------------------------
# Test 3: SQLi request -> expect deny (403) + mock NOT hit
# ------------------------------------------------------------------
echo "Test 3: SQL injection (expect deny)"
COUNT_BEFORE=$(get_mock_count)
RESP=$(curl -s -w "\n%{http_code}" -X POST "$ADAPTER_URL/v1/chat/completions" \
    -H "Content-Type: application/json" \
    -D /tmp/poc-headers-sqli.txt \
    -d '{
        "model": "gpt-4o-mini",
        "messages": [
            {"role": "user", "content": "SELECT * FROM users; DROP TABLE users;--"}
        ]
    }')

HTTP_CODE=$(echo "$RESP" | tail -1)
BODY=$(echo "$RESP" | sed '$d')
SQLI_TRACE=$(grep -i "x-axonflow-trace-id" /tmp/poc-headers-sqli.txt 2>/dev/null | tr -d '\r' | awk '{print $2}' || true)
COUNT_AFTER=$(get_mock_count)

if [ "$HTTP_CODE" = "403" ]; then pass "SQLi request returns 403"; else fail "SQLi request returns 403 (got $HTTP_CODE)"; fi
if echo "$BODY" | grep -q "policy_deny"; then pass "SQLi response contains policy_deny"; else fail "SQLi response contains policy_deny"; fi
if [ -n "$SQLI_TRACE" ]; then pass "SQLi response has trace_id header"; else fail "SQLi response has trace_id header"; fi
if echo "$BODY" | grep -q "decision_id"; then pass "SQLi response has decision_id"; else fail "SQLi response has decision_id"; fi
if [ "$COUNT_AFTER" = "$COUNT_BEFORE" ]; then pass "SQLi request did NOT reach upstream mock (count stayed $COUNT_BEFORE)"; else fail "SQLi request SHOULD NOT reach upstream mock (count $COUNT_BEFORE->$COUNT_AFTER)"; fi
echo ""

# ------------------------------------------------------------------
# Test 4: Traceparent propagation — send a known trace_id, verify it round-trips
# ------------------------------------------------------------------
echo "Test 4: Traceparent propagation"
KNOWN_TRACE="aabbccdd11223344aabbccdd11223344"
RESP=$(curl -s -w "\n%{http_code}" -X POST "$ADAPTER_URL/v1/chat/completions" \
    -H "Content-Type: application/json" \
    -H "traceparent: 00-${KNOWN_TRACE}-0000000000000001-01" \
    -D /tmp/poc-headers-trace.txt \
    -d '{
        "model": "gpt-4o-mini",
        "messages": [
            {"role": "user", "content": "Tell me about traceparent headers"}
        ]
    }')

HTTP_CODE=$(echo "$RESP" | tail -1)
RETURNED_TRACE=$(grep -i "x-axonflow-trace-id" /tmp/poc-headers-trace.txt 2>/dev/null | tr -d '\r' | awk '{print $2}' || true)

if [ "$HTTP_CODE" = "200" ]; then pass "traceparent request returns 200"; else fail "traceparent request returns 200 (got $HTTP_CODE)"; fi
if [ "$RETURNED_TRACE" = "$KNOWN_TRACE" ]; then pass "trace_id matches input traceparent"; else fail "trace_id matches input traceparent (got $RETURNED_TRACE)"; fi
echo ""

# ------------------------------------------------------------------
# Summary
# ------------------------------------------------------------------
echo "============================================================"
echo "Results: PASS=$PASS  FAIL=$FAIL"
echo "============================================================"
for t in "${TESTS[@]}"; do
    echo "  $t"
done
echo ""

if [ "$FAIL" -gt 0 ]; then
    echo "FAILED — $FAIL test(s) did not pass."
    exit 1
fi
echo "ALL TESTS PASSED"
exit 0
