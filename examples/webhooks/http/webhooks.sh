#!/bin/bash
# AxonFlow Webhook Management Example - HTTP/curl
#
# Demonstrates webhook subscription CRUD operations:
# 1. Create a webhook subscription
# 2. Get a webhook subscription
# 3. List all webhook subscriptions
# 4. Update a webhook subscription
# 5. Delete a webhook subscription
#
# Run with: bash webhooks.sh
# Prerequisites: docker compose up -d

set -euo pipefail

AGENT_URL="${AXONFLOW_AGENT_URL:-http://localhost:8080}"
CLIENT_ID="${AXONFLOW_CLIENT_ID:-community}"
CLIENT_SECRET="${AXONFLOW_CLIENT_SECRET:-demo}"

PASS=0
FAIL=0

check_result() {
    local description="$1"
    local result="$2"

    if [ "$result" = "true" ]; then
        echo "   PASS: $description"
        PASS=$((PASS + 1))
    else
        echo "   FAIL: $description"
        FAIL=$((FAIL + 1))
    fi
}

echo "AxonFlow Webhook Management - HTTP/curl"
echo "========================================"
echo ""

# ========================================
# 1. CREATE WEBHOOK SUBSCRIPTION
# ========================================
echo "1. CreateWebhook - Create a new subscription..."
echo "-------------------------------------------"

RESPONSE=$(curl -s -X POST "${AGENT_URL}/api/v1/webhooks" \
  -H "Content-Type: application/json" \
  -H "Authorization: Basic $AUTH_B64" \
  -d '{
    "url": "https://example.com/webhooks/axonflow",
    "events": ["step.approval_required", "workflow.completed"],
    "active": true
  }')

echo "Create response:"
echo "$RESPONSE" | python3 -m json.tool 2>/dev/null || echo "$RESPONSE"
echo ""

WEBHOOK_ID=$(echo "$RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('id', ''))" 2>/dev/null || echo "")
WEBHOOK_URL=$(echo "$RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('url', ''))" 2>/dev/null || echo "")
WEBHOOK_ACTIVE=$(echo "$RESPONSE" | python3 -c "import sys,json; print('true' if json.load(sys.stdin).get('active', False) else 'false')" 2>/dev/null || echo "false")

HAS_ID=$([ -n "$WEBHOOK_ID" ] && echo "true" || echo "false")
check_result "Webhook created with valid ID ($WEBHOOK_ID)" "$HAS_ID"
URL_MATCH=$([ "$WEBHOOK_URL" = "https://example.com/webhooks/axonflow" ] && echo "true" || echo "false")
check_result "Webhook URL matches" "$URL_MATCH"
check_result "Webhook is active" "$WEBHOOK_ACTIVE"
echo ""

# ========================================
# 2. GET WEBHOOK SUBSCRIPTION
# ========================================
echo "2. GetWebhook - Retrieve the subscription..."
echo "-------------------------------------------"

RESPONSE=$(curl -s "${AGENT_URL}/api/v1/webhooks/${WEBHOOK_ID}" \
  -H "Authorization: Basic $AUTH_B64" \
)

echo "Get response:"
echo "$RESPONSE" | python3 -m json.tool 2>/dev/null || echo "$RESPONSE"
echo ""

GOT_ID=$(echo "$RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('id', ''))" 2>/dev/null || echo "")
ID_MATCH=$([ "$GOT_ID" = "$WEBHOOK_ID" ] && echo "true" || echo "false")
check_result "Retrieved webhook has correct ID" "$ID_MATCH"
echo ""

# ========================================
# 3. LIST WEBHOOK SUBSCRIPTIONS
# ========================================
echo "3. ListWebhooks - List all subscriptions..."
echo "-------------------------------------------"

# Create a second webhook for listing
RESPONSE=$(curl -s -X POST "${AGENT_URL}/api/v1/webhooks" \
  -H "Content-Type: application/json" \
  -H "Authorization: Basic $AUTH_B64" \
  -d '{
    "url": "https://example.com/webhooks/backup",
    "events": ["step.approved", "step.rejected"],
    "active": true
  }')

WEBHOOK2_ID=$(echo "$RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('id', ''))" 2>/dev/null || echo "")

RESPONSE=$(curl -s "${AGENT_URL}/api/v1/webhooks" \
  -H "Authorization: Basic $AUTH_B64" \
)

echo "List response:"
echo "$RESPONSE" | python3 -m json.tool 2>/dev/null || echo "$RESPONSE"
echo ""

TOTAL=$(echo "$RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('total', 0))" 2>/dev/null || echo "0")
HAS_TWO=$([ "$TOTAL" -ge 2 ] 2>/dev/null && echo "true" || echo "false")
check_result "At least 2 webhooks listed (got $TOTAL)" "$HAS_TWO"
echo ""

# ========================================
# 4. UPDATE WEBHOOK SUBSCRIPTION
# ========================================
echo "4. UpdateWebhook - Update URL and deactivate..."
echo "-------------------------------------------"

RESPONSE=$(curl -s -X PUT "${AGENT_URL}/api/v1/webhooks/${WEBHOOK_ID}" \
  -H "Content-Type: application/json" \
  -H "Authorization: Basic $AUTH_B64" \
  -d '{
    "url": "https://example.com/webhooks/updated",
    "active": false
  }')

echo "Update response:"
echo "$RESPONSE" | python3 -m json.tool 2>/dev/null || echo "$RESPONSE"
echo ""

UPDATED_URL=$(echo "$RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('url', ''))" 2>/dev/null || echo "")
UPDATED_ACTIVE=$(echo "$RESPONSE" | python3 -c "import sys,json; print('true' if json.load(sys.stdin).get('active', False) else 'false')" 2>/dev/null || echo "true")

URL_UPDATED=$([ "$UPDATED_URL" = "https://example.com/webhooks/updated" ] && echo "true" || echo "false")
check_result "Webhook URL was updated" "$URL_UPDATED"
IS_INACTIVE=$([ "$UPDATED_ACTIVE" = "false" ] && echo "true" || echo "false")
check_result "Webhook was deactivated" "$IS_INACTIVE"
echo ""

# ========================================
# 5. DELETE WEBHOOK SUBSCRIPTIONS
# ========================================
echo "5. DeleteWebhook - Delete both subscriptions..."
echo "-------------------------------------------"

HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X DELETE "${AGENT_URL}/api/v1/webhooks/${WEBHOOK_ID}" \
  -H "Authorization: Basic $AUTH_B64" \
)

DEL1_OK=$([ "$HTTP_CODE" = "204" ] && echo "true" || echo "false")
check_result "First webhook deleted (HTTP $HTTP_CODE)" "$DEL1_OK"

HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X DELETE "${AGENT_URL}/api/v1/webhooks/${WEBHOOK2_ID}" \
  -H "Authorization: Basic $AUTH_B64" \
)

DEL2_OK=$([ "$HTTP_CODE" = "204" ] && echo "true" || echo "false")
check_result "Second webhook deleted (HTTP $HTTP_CODE)" "$DEL2_OK"

# Verify deletion
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "${AGENT_URL}/api/v1/webhooks/${WEBHOOK_ID}" \
  -H "Authorization: Basic $AUTH_B64" \
)

IS_GONE=$([ "$HTTP_CODE" = "404" ] && echo "true" || echo "false")
check_result "Deleted webhook returns 404 (HTTP $HTTP_CODE)" "$IS_GONE"
echo ""

# ========================================
# 6. ERROR HANDLING
# ========================================
echo "6. Error Handling - Invalid webhook ID..."
echo "-------------------------------------------"

HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "${AGENT_URL}/api/v1/webhooks/nonexistent-webhook-id" \
  -H "Authorization: Basic $AUTH_B64" \
)

IS_NOT_FOUND=$([ "$HTTP_CODE" = "404" ] && echo "true" || echo "false")
check_result "Nonexistent webhook returns 404 (HTTP $HTTP_CODE)" "$IS_NOT_FOUND"
echo ""

# ========================================
# SUMMARY
# ========================================
echo "========================================"
echo "Results: $PASS passed, $FAIL failed"
if [ "$FAIL" -gt 0 ]; then
    echo "SOME TESTS FAILED"
    exit 1
fi
echo "ALL TESTS PASSED"
echo "========================================"
echo ""
echo "API Summary:"
echo "  POST   /api/v1/webhooks         - Create webhook subscription"
echo "  GET    /api/v1/webhooks/{id}     - Get webhook subscription"
echo "  GET    /api/v1/webhooks          - List webhook subscriptions"
echo "  PUT    /api/v1/webhooks/{id}     - Update webhook subscription"
echo "  DELETE /api/v1/webhooks/{id}     - Delete webhook subscription"
