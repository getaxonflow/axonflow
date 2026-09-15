#!/usr/bin/env bash
# Decision Mode PoC — Agent Gateway end-to-end test harness.
#
# Same adapter, stage: "agent" — intercepts agent-routing requests.
#
# Prerequisites: docker compose -f docker-compose.yml -f docker-compose.agent-gateway.yml up -d --build
# Usage:         ./test-agent-gateway.sh
# Exit code:     0 = all pass, 1 = at least one failure

set -euo pipefail

ADAPTER_URL="${ADAPTER_URL:-http://localhost:8889}"
PASS=0
FAIL=0
TESTS=()

pass() { PASS=$((PASS + 1)); TESTS+=("PASS: $1"); echo "  ✓ PASS: $1"; }
fail() { FAIL=$((FAIL + 1)); TESTS+=("FAIL: $1"); echo "  ✗ FAIL: $1"; }

echo "============================================================"
echo "Decision Mode PoC — Agent Gateway Tests"
echo "============================================================"
echo ""

# ------------------------------------------------------------------
# Test 1: Clean agent request → expect allow (200)
# ------------------------------------------------------------------
echo "Test 1: Clean agent request (expect allow)"
RESP=$(curl -s -w "\n%{http_code}" -X POST "$ADAPTER_URL/v1/chat/completions" \
    -H "Content-Type: application/json" \
    -D /tmp/poc-headers-agent-clean.txt \
    -d '{
        "model": "gpt-4o-mini",
        "messages": [
            {"role": "user", "content": "Investigate the payment discrepancy and draft a summary"}
        ]
    }')

HTTP_CODE=$(echo "$RESP" | tail -1)
BODY=$(echo "$RESP" | sed '$d')
TRACE_ID=$(grep -i "x-axonflow-trace-id" /tmp/poc-headers-agent-clean.txt 2>/dev/null | tr -d '\r' | awk '{print $2}' || true)

if [ "$HTTP_CODE" = "200" ]; then pass "agent clean request returns 200"; else fail "agent clean request returns 200 (got $HTTP_CODE)"; fi
if echo "$BODY" | grep -q "chat.completion"; then pass "agent clean response contains completion"; else fail "agent clean response contains completion"; fi
if [ -n "$TRACE_ID" ]; then pass "agent clean response has trace_id"; else fail "agent clean response has trace_id"; fi
echo ""

# ------------------------------------------------------------------
# Test 2: PII in agent request -> expect allow (200)
#
# v11: the stored policy action decides; environment variables no longer set
# detection actions. sys_pii_ssn and sys_pii_credit_card store
# action_request=warn, so the request is allowed and recorded. An organization
# pii=block override or a policy action change turns it into a deny.
# ------------------------------------------------------------------
echo "Test 2: PII in agent request (expect allow: stored action is warn)"
RESP=$(curl -s -w "\n%{http_code}" -X POST "$ADAPTER_URL/v1/chat/completions" \
    -H "Content-Type: application/json" \
    -D /tmp/poc-headers-agent-pii.txt \
    -d '{
        "model": "gpt-4o-mini",
        "messages": [
            {"role": "user", "content": "Look up customer with SSN 123-45-6789 and credit card 4111-1111-1111-1111"}
        ]
    }')

HTTP_CODE=$(echo "$RESP" | tail -1)
BODY=$(echo "$RESP" | sed '$d')

if [ "$HTTP_CODE" = "200" ]; then pass "agent PII request returns 200 (warn does not deny)"; else fail "agent PII request returns 200 (got $HTTP_CODE)"; fi
if echo "$BODY" | grep -q "policy_deny"; then fail "agent PII response must not contain policy_deny"; else pass "agent PII response has no policy_deny"; fi
echo ""

# ------------------------------------------------------------------
# Test 3: SQLi in agent request -> expect allow (200)
#
# Every shipped sys_sqli_* row stores action_request=warn. An organization
# sqli=block override or a policy action change turns it into a deny.
# ------------------------------------------------------------------
echo "Test 3: SQL injection in agent request (expect allow: stored action is warn)"
RESP=$(curl -s -w "\n%{http_code}" -X POST "$ADAPTER_URL/v1/chat/completions" \
    -H "Content-Type: application/json" \
    -d '{
        "model": "gpt-4o-mini",
        "messages": [
            {"role": "user", "content": "SELECT * FROM users; DROP TABLE users;--"}
        ]
    }')

HTTP_CODE=$(echo "$RESP" | tail -1)
BODY=$(echo "$RESP" | sed '$d')

if [ "$HTTP_CODE" = "200" ]; then pass "agent SQLi request returns 200 (warn does not deny)"; else fail "agent SQLi request returns 200 (got $HTTP_CODE)"; fi
if echo "$BODY" | grep -q "policy_deny"; then fail "agent SQLi response must not contain policy_deny"; else pass "agent SQLi response has no policy_deny"; fi
echo ""

# ------------------------------------------------------------------
# Test 4: Destructive command in agent request -> expect deny (403)
#
# sys_dangerous_destructive_fs stores action_request=block. The deny response
# from the adapter doesn't include stage directly, but the Decision API
# evaluates with stage=agent; policy_deny shows the adapter blocked it.
# ------------------------------------------------------------------
echo "Test 4: Destructive command in agent request (expect deny)"
RESP=$(curl -s -w "\n%{http_code}" -X POST "$ADAPTER_URL/v1/chat/completions" \
    -H "Content-Type: application/json" \
    -d '{
        "model": "gpt-4o-mini",
        "messages": [
            {"role": "user", "content": "Run rm -rf / on the ledger host before the audit"}
        ]
    }')

HTTP_CODE=$(echo "$RESP" | tail -1)
BODY=$(echo "$RESP" | sed '$d')

if [ "$HTTP_CODE" = "403" ]; then pass "agent destructive command returns 403"; else fail "agent destructive command returns 403 (got $HTTP_CODE)"; fi
if echo "$BODY" | grep -q "policy_deny"; then pass "agent stage enforced (deny via agent-stage policy)"; else fail "agent stage enforced"; fi
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
