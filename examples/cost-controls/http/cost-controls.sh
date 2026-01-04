#!/bin/bash
# AxonFlow Cost Controls Example - HTTP (curl) - Comprehensive
#
# This script demonstrates ALL Cost Controls API endpoints using curl commands.
# Make sure the orchestrator is running at http://localhost:8081
#
# Endpoints tested:
# 1.  POST   /api/v1/budgets         - Create a budget
# 2.  GET    /api/v1/budgets/{id}    - Get a budget
# 3.  GET    /api/v1/budgets         - List budgets
# 4.  PUT    /api/v1/budgets/{id}    - Update a budget
# 5.  GET    /api/v1/budgets/{id}/status  - Get budget status
# 6.  GET    /api/v1/budgets/{id}/alerts  - Get budget alerts
# 7.  POST   /api/v1/budgets/check   - Check if request allowed
# 8.  GET    /api/v1/usage           - Get usage summary
# 9.  GET    /api/v1/usage/breakdown - Get usage breakdown
# 10. GET    /api/v1/usage/records   - List usage records
# 11. GET    /api/v1/pricing         - Get pricing info
# 12. DELETE /api/v1/budgets/{id}    - Delete a budget

set -e

BASE_URL="${AXONFLOW_ORCHESTRATOR_URL:-http://localhost:8081}"
ORG_ID="demo-org"
BUDGET_ID="demo-budget-http-$(date +%s)"

echo "AxonFlow Cost Controls - HTTP (curl) - Comprehensive"
echo "====================================================="
echo ""

# ========================================
# BUDGET MANAGEMENT
# ========================================

# 1. POST /api/v1/budgets - Create a budget
echo "1. POST /api/v1/budgets - Creating a monthly budget..."
BUDGET_RESPONSE=$(curl -s -X POST "${BASE_URL}/api/v1/budgets" \
  -H "Content-Type: application/json" \
  -H "X-Org-ID: ${ORG_ID}" \
  -d '{
    "id": "'"${BUDGET_ID}"'",
    "name": "Demo Budget (HTTP)",
    "scope": "organization",
    "limit_usd": 100.0,
    "period": "monthly",
    "on_exceed": "warn",
    "alert_thresholds": [50, 80, 100]
  }')
echo "   Response: ${BUDGET_RESPONSE}" | head -c 200
echo ""
echo ""

# 2. GET /api/v1/budgets/{id} - Get a budget
echo "2. GET /api/v1/budgets/{id} - Getting budget by ID..."
GET_RESPONSE=$(curl -s "${BASE_URL}/api/v1/budgets/${BUDGET_ID}")
echo "   Response: ${GET_RESPONSE}" | head -c 200
echo ""
echo ""

# 3. GET /api/v1/budgets - List budgets
echo "3. GET /api/v1/budgets - Listing all budgets..."
LIST_RESPONSE=$(curl -s "${BASE_URL}/api/v1/budgets?limit=5" \
  -H "X-Org-ID: ${ORG_ID}")
echo "   Response: ${LIST_RESPONSE}" | head -c 300
echo ""
echo ""

# 4. PUT /api/v1/budgets/{id} - Update a budget
echo "4. PUT /api/v1/budgets/{id} - Updating budget limit..."
UPDATE_RESPONSE=$(curl -s -X PUT "${BASE_URL}/api/v1/budgets/${BUDGET_ID}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Demo Budget (HTTP) - Updated",
    "limit_usd": 150.0
  }')
echo "   Response: ${UPDATE_RESPONSE}" | head -c 200
echo ""
echo ""

# ========================================
# BUDGET STATUS & ALERTS
# ========================================

# 5. GET /api/v1/budgets/{id}/status - Get budget status
echo "5. GET /api/v1/budgets/{id}/status - Checking budget status..."
STATUS_RESPONSE=$(curl -s "${BASE_URL}/api/v1/budgets/${BUDGET_ID}/status")
echo "   Response: ${STATUS_RESPONSE}" | head -c 300
echo ""
echo ""

# 6. GET /api/v1/budgets/{id}/alerts - Get budget alerts
echo "6. GET /api/v1/budgets/{id}/alerts - Getting budget alerts..."
ALERTS_RESPONSE=$(curl -s "${BASE_URL}/api/v1/budgets/${BUDGET_ID}/alerts")
echo "   Response: ${ALERTS_RESPONSE}" | head -c 200
echo ""
echo ""

# 7. POST /api/v1/budgets/check - Check if request allowed
echo "7. POST /api/v1/budgets/check - Pre-flight budget check..."
CHECK_RESPONSE=$(curl -s -X POST "${BASE_URL}/api/v1/budgets/check" \
  -H "Content-Type: application/json" \
  -d '{
    "org_id": "'"${ORG_ID}"'"
  }')
echo "   Response: ${CHECK_RESPONSE}"
echo ""

# ========================================
# USAGE TRACKING
# ========================================

# 8. GET /api/v1/usage - Get usage summary
echo "8. GET /api/v1/usage - Getting usage summary..."
USAGE_RESPONSE=$(curl -s "${BASE_URL}/api/v1/usage?period=monthly" \
  -H "X-Org-ID: ${ORG_ID}")
echo "   Response: ${USAGE_RESPONSE}"
echo ""

# 9. GET /api/v1/usage/breakdown - Get usage breakdown
echo "9. GET /api/v1/usage/breakdown - Getting usage breakdown by provider..."
BREAKDOWN_RESPONSE=$(curl -s "${BASE_URL}/api/v1/usage/breakdown?group_by=provider&period=monthly" \
  -H "X-Org-ID: ${ORG_ID}")
echo "   Response: ${BREAKDOWN_RESPONSE}" | head -c 300
echo ""
echo ""

# 10. GET /api/v1/usage/records - List usage records
echo "10. GET /api/v1/usage/records - Listing usage records..."
RECORDS_RESPONSE=$(curl -s "${BASE_URL}/api/v1/usage/records?limit=5" \
  -H "X-Org-ID: ${ORG_ID}")
echo "   Response: ${RECORDS_RESPONSE}" | head -c 300
echo ""
echo ""

# ========================================
# PRICING
# ========================================

# 11. GET /api/v1/pricing - Get pricing info
echo "11. GET /api/v1/pricing - Getting model pricing..."
PRICING_RESPONSE=$(curl -s "${BASE_URL}/api/v1/pricing?provider=anthropic&model=claude-sonnet-4")
echo "   Response: ${PRICING_RESPONSE}"
echo ""

# ========================================
# CLEANUP
# ========================================

# 12. DELETE /api/v1/budgets/{id} - Delete a budget
echo "12. DELETE /api/v1/budgets/{id} - Cleaning up..."
DELETE_RESPONSE=$(curl -s -X DELETE "${BASE_URL}/api/v1/budgets/${BUDGET_ID}" \
  -w "HTTP %{http_code}")
echo "   Response: ${DELETE_RESPONSE}"
echo ""

echo "====================================================="
echo "All 12 Cost Control API endpoints tested!"
echo ""
echo "API Endpoints Summary:"
echo "  POST   /api/v1/budgets             - Create a budget"
echo "  GET    /api/v1/budgets             - List budgets"
echo "  GET    /api/v1/budgets/{id}        - Get a budget"
echo "  PUT    /api/v1/budgets/{id}        - Update a budget"
echo "  DELETE /api/v1/budgets/{id}        - Delete a budget"
echo "  GET    /api/v1/budgets/{id}/status - Get budget status"
echo "  GET    /api/v1/budgets/{id}/alerts - Get budget alerts"
echo "  POST   /api/v1/budgets/check       - Check if request allowed"
echo "  GET    /api/v1/usage               - Get usage summary"
echo "  GET    /api/v1/usage/breakdown     - Get usage breakdown"
echo "  GET    /api/v1/usage/records       - List usage records"
echo "  GET    /api/v1/pricing             - Get pricing info"
