#!/bin/bash
# AxonFlow Circuit Breaker Example - HTTP API
#
# This example demonstrates the Circuit Breaker endpoints for EU AI Act Article 14
# (Human oversight and intervention mechanisms).
#
# The circuit breaker allows operators to immediately halt AI processing
# in emergency situations or when human intervention is required.
#
# Prerequisites:
#   docker compose up -d
#
# Usage:
#   ./circuit-breaker.sh

set -e

AGENT_URL="${AXONFLOW_AGENT_URL:-http://localhost:8080}"
TENANT_ID="${AXONFLOW_TENANT_ID:-test-org-001}"
CLIENT_SECRET="${AXONFLOW_CLIENT_SECRET:-demo-secret}"

echo "AxonFlow Circuit Breaker - HTTP API Example"
echo "============================================"
echo ""
echo "Agent URL: $AGENT_URL"
echo "Tenant ID: $TENANT_ID"
echo ""

# ========================================
# 1. GET CIRCUIT BREAKER STATUS
# ========================================
echo "1. Get Circuit Breaker Status"
echo "------------------------------"

RESPONSE=$(curl -s -w "\n%{http_code}" -X GET \
  "${AGENT_URL}/api/v1/circuit-breaker/status" \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: ${TENANT_ID}" \
  -H "X-Client-Secret: ${CLIENT_SECRET}")

HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | sed '$d')

if [ "$HTTP_CODE" = "404" ]; then
  echo "Response: 404 Not Found"
  echo ""
  echo "NOTE: Circuit Breaker API is not available."
  echo "This feature may require Enterprise license or is not yet implemented."
  echo ""
  echo "============================================"
  echo "Circuit Breaker endpoints to be tested:"
  echo "  GET  /api/v1/circuit-breaker/status"
  echo "  POST /api/v1/circuit-breaker/activate"
  echo "  POST /api/v1/circuit-breaker/deactivate"
  echo ""
  echo "These endpoints are part of EU AI Act Article 14 compliance."
  exit 0
fi

echo "Response: $BODY"
echo ""

IS_ACTIVE=$(echo "$BODY" | jq -r '.active // false' 2>/dev/null || echo "false")
echo "Circuit Breaker Active: $IS_ACTIVE"
echo ""

# ========================================
# 2. ACTIVATE CIRCUIT BREAKER
# ========================================
echo "2. Activate Circuit Breaker"
echo "----------------------------"

RESPONSE=$(curl -s -X POST \
  "${AGENT_URL}/api/v1/circuit-breaker/activate" \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: ${TENANT_ID}" \
  -H "X-Client-Secret: ${CLIENT_SECRET}" \
  -d '{
    "reason": "Demo: Testing circuit breaker activation",
    "scope": "tenant",
    "activated_by": "sdk-example-test",
    "duration_seconds": 60
  }')

echo "Response: $RESPONSE"
echo ""

SUCCESS=$(echo "$RESPONSE" | jq -r '.success // .activated // false')
if [ "$SUCCESS" = "true" ]; then
  echo "Circuit Breaker ACTIVATED successfully!"
else
  echo "Note: Activation may require Enterprise license"
fi
echo ""

# ========================================
# 3. VERIFY STATUS IS ACTIVE
# ========================================
echo "3. Verify Status is Active"
echo "---------------------------"

RESPONSE=$(curl -s -X GET \
  "${AGENT_URL}/api/v1/circuit-breaker/status" \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: ${TENANT_ID}" \
  -H "X-Client-Secret: ${CLIENT_SECRET}")

echo "Response: $RESPONSE"
echo ""

IS_ACTIVE=$(echo "$RESPONSE" | jq -r '.active // false')
echo "Circuit Breaker Active: $IS_ACTIVE"

if [ "$IS_ACTIVE" = "true" ]; then
  REASON=$(echo "$RESPONSE" | jq -r '.reason // "N/A"')
  ACTIVATED_AT=$(echo "$RESPONSE" | jq -r '.activated_at // "N/A"')
  EXPIRES_AT=$(echo "$RESPONSE" | jq -r '.expires_at // "N/A"')

  echo "  Reason: $REASON"
  echo "  Activated at: $ACTIVATED_AT"
  echo "  Expires at: $EXPIRES_AT"
fi
echo ""

# ========================================
# 4. TEST REQUEST DURING CIRCUIT BREAKER
# ========================================
echo "4. Test Request During Circuit Breaker Active"
echo "----------------------------------------------"
echo "(Requests should be blocked or return circuit breaker error)"
echo ""

RESPONSE=$(curl -s -X POST \
  "${AGENT_URL}/api/policy/pre-check" \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: ${TENANT_ID}" \
  -H "X-Client-Secret: ${CLIENT_SECRET}" \
  -d '{
    "user_token": "test-user",
    "query": "Hello, world!",
    "data_sources": ["general"]
  }')

echo "Response: $RESPONSE"
echo ""

BLOCKED=$(echo "$RESPONSE" | jq -r '.blocked // .circuit_breaker_active // false')
if [ "$BLOCKED" = "true" ]; then
  echo "Request correctly BLOCKED by circuit breaker"
else
  echo "Request processed (circuit breaker may not be active)"
fi
echo ""

# ========================================
# 5. DEACTIVATE CIRCUIT BREAKER
# ========================================
echo "5. Deactivate Circuit Breaker"
echo "------------------------------"

RESPONSE=$(curl -s -X POST \
  "${AGENT_URL}/api/v1/circuit-breaker/deactivate" \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: ${TENANT_ID}" \
  -H "X-Client-Secret: ${CLIENT_SECRET}" \
  -d '{
    "reason": "Demo: Deactivating after test",
    "deactivated_by": "sdk-example-test"
  }')

echo "Response: $RESPONSE"
echo ""

SUCCESS=$(echo "$RESPONSE" | jq -r '.success // .deactivated // false')
if [ "$SUCCESS" = "true" ]; then
  echo "Circuit Breaker DEACTIVATED successfully!"
else
  echo "Note: Deactivation may require Enterprise license"
fi
echo ""

# ========================================
# 6. VERIFY STATUS IS INACTIVE
# ========================================
echo "6. Verify Status is Inactive"
echo "-----------------------------"

RESPONSE=$(curl -s -X GET \
  "${AGENT_URL}/api/v1/circuit-breaker/status" \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: ${TENANT_ID}" \
  -H "X-Client-Secret: ${CLIENT_SECRET}")

echo "Response: $RESPONSE"
echo ""

IS_ACTIVE=$(echo "$RESPONSE" | jq -r '.active // false')
echo "Circuit Breaker Active: $IS_ACTIVE"

if [ "$IS_ACTIVE" = "false" ]; then
  echo "Circuit breaker is now INACTIVE - normal operation resumed"
fi
echo ""

echo "============================================"
echo "Circuit Breaker Example Complete!"
echo ""
echo "API Endpoints Demonstrated:"
echo "  GET  /api/v1/circuit-breaker/status     - Check status"
echo "  POST /api/v1/circuit-breaker/activate   - Activate"
echo "  POST /api/v1/circuit-breaker/deactivate - Deactivate"
echo ""
echo "EU AI Act Article 14 Compliance:"
echo "  - Human oversight mechanism"
echo "  - Emergency stop capability"
echo "  - Audit trail for activations"
echo ""
echo "NOTE: SDK methods for circuit breaker are planned for a future release."
echo "      Currently only available via HTTP API."
