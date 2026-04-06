#!/bin/bash
# Mistral LLM Provider - PII Detection Example (HTTP/cURL)
#
# Tests that PII detection policies work when routing through Mistral.
# Verifies SSN and Aadhaar PII are detected via the pre-check endpoint.
#
# VALIDATION: This example exits with code 1 if any assertion fails.
#
# Usage:
#   ./pii-detection.sh

set -euo pipefail

AGENT_URL="${AXONFLOW_AGENT_URL:-${AXONFLOW_ENDPOINT:-http://localhost:8080}}"
CLIENT_ID="${AXONFLOW_CLIENT_ID:-community}"
CLIENT_SECRET="${AXONFLOW_CLIENT_SECRET:-}"
AUTH=$(echo -n "${CLIENT_ID}:${CLIENT_SECRET}" | base64)

echo "=============================================="
echo "Mistral Provider - PII Detection"
echo "=============================================="
echo "Agent URL: $AGENT_URL"
echo ""

PASS=0
FAIL=0

check_result() {
    local test_name="$1"
    local condition="$2"
    if [ "$condition" = "true" ]; then
        echo "   PASS: $test_name"
        PASS=$((PASS + 1))
    else
        echo "   FAIL: $test_name"
        FAIL=$((FAIL + 1))
    fi
}

# -----------------------------------------------
# Test 1: SSN detected in query
# -----------------------------------------------
echo "Test 1: SSN PII detection..."
echo "----------------------------------------------"

RESPONSE=$(curl -s -X POST "${AGENT_URL}/api/policy/pre-check" \
  -H "Authorization: Basic ${AUTH}" \
  -H "Content-Type: application/json" \
  -d "{
    \"client_id\": \"${CLIENT_ID}\",
    \"query\": \"Process payment for customer with SSN 123-45-6789\",
    \"context\": { \"provider\": \"mistral\" }
  }")

SSN_DETECTED=$(echo "$RESPONSE" | python3 -c "
import sys, json
d = json.load(sys.stdin)
policies = d.get('policies', [])
print('true' if any('ssn' in p.lower() for p in policies) else 'false')
" 2>/dev/null || echo "false")

REQUIRES_REDACTION=$(echo "$RESPONSE" | python3 -c "
import sys, json
d = json.load(sys.stdin)
print('true' if d.get('requires_redaction') else 'false')
" 2>/dev/null || echo "false")

check_result "SSN policy matched" "$SSN_DETECTED"
check_result "Requires redaction" "$REQUIRES_REDACTION"
echo ""

# -----------------------------------------------
# Test 2: Aadhaar detected in query
# -----------------------------------------------
echo "Test 2: Aadhaar PII detection..."
echo "----------------------------------------------"

RESPONSE=$(curl -s -X POST "${AGENT_URL}/api/policy/pre-check" \
  -H "Authorization: Basic ${AUTH}" \
  -H "Content-Type: application/json" \
  -d "{
    \"client_id\": \"${CLIENT_ID}\",
    \"query\": \"Link Aadhaar 2345 6789 0123 to bank account\",
    \"context\": { \"provider\": \"mistral\" }
  }")

AADHAAR_DETECTED=$(echo "$RESPONSE" | python3 -c "
import sys, json
d = json.load(sys.stdin)
policies = d.get('policies', [])
print('true' if any('aadhaar' in p.lower() for p in policies) else 'false')
" 2>/dev/null || echo "false")

check_result "Aadhaar policy matched" "$AADHAAR_DETECTED"
echo ""

# -----------------------------------------------
# Test 3: Clean query passes without PII flags
# -----------------------------------------------
echo "Test 3: Clean query (no PII)..."
echo "----------------------------------------------"

RESPONSE=$(curl -s -X POST "${AGENT_URL}/api/policy/pre-check" \
  -H "Authorization: Basic ${AUTH}" \
  -H "Content-Type: application/json" \
  -d "{
    \"client_id\": \"${CLIENT_ID}\",
    \"query\": \"What is the capital of France?\",
    \"context\": { \"provider\": \"mistral\" }
  }")

APPROVED=$(echo "$RESPONSE" | python3 -c "import sys,json; d=json.load(sys.stdin); print('true' if d.get('approved') else 'false')" 2>/dev/null || echo "false")
NO_REDACTION=$(echo "$RESPONSE" | python3 -c "import sys,json; d=json.load(sys.stdin); print('true' if not d.get('requires_redaction') else 'false')" 2>/dev/null || echo "false")

check_result "Clean query approved" "$APPROVED"
check_result "No redaction required" "$NO_REDACTION"
echo ""

# -----------------------------------------------
# Results
# -----------------------------------------------
echo "=============================================="
echo "Results: $((PASS))/$((PASS + FAIL)) assertions passed"
if [ "$FAIL" -eq 0 ]; then
    echo "ALL ASSERTIONS PASSED"
else
    echo "FAILED: ${FAIL} assertion(s) failed"
    exit 1
fi
echo "=============================================="
