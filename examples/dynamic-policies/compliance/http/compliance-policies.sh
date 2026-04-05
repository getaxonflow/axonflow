#!/bin/bash
# Compliance Policy Examples - HTTP API
#
# Demonstrates using allowed_providers in dynamic policies for:
#   - GDPR: EU data sovereignty
#   - HIPAA: Healthcare data protection
#   - RBI: India financial data sovereignty
#
# API Endpoints demonstrated:
#   POST   /api/v1/dynamic-policies     - Create policy with allowed_providers
#   GET    /api/v1/dynamic-policies     - List policies
#   DELETE /api/v1/dynamic-policies/:id - Delete policy
#
# Usage:
#   ./compliance-policies.sh
#
# Environment:
#   AXONFLOW_ENDPOINT - Agent URL (default: http://localhost:8080)

set -e

ENDPOINT="${AXONFLOW_ENDPOINT:-http://localhost:8080}"
CLIENT_ID="${AXONFLOW_CLIENT_ID:-community}"
CLIENT_SECRET="${AXONFLOW_CLIENT_SECRET:-}"
ORG_ID="${ORG_ID:-demo-org}"

echo "=== Compliance Policy Examples (HTTP API) ==="
echo ""
echo "Endpoint: $ENDPOINT"
echo ""

CREATED_IDS=()

# 1. GDPR - EU Data Sovereignty
echo "1. Creating GDPR policy for EU data sovereignty..."
GDPR_RESPONSE=$(curl -s -X POST "$ENDPOINT/api/v1/dynamic-policies" \
  -u "$CLIENT_ID:${CLIENT_SECRET}" \
  -H "Content-Type: application/json" \
  -H "X-Org-ID: $ORG_ID" \
  -d '{
    "name": "gdpr-eu-data-sovereignty",
    "description": "Route EU users to EU-hosted LLMs only (GDPR Article 44)",
    "type": "content",
    "category": "dynamic-compliance",
    "conditions": [
      {
        "field": "user.region",
        "operator": "equals",
        "value": "EU"
      }
    ],
    "actions": [
      {
        "type": "route",
        "config": {
          "allowed_providers": ["ollama", "azure-eu"],
          "reason": "GDPR Article 44 - EU data sovereignty"
        }
      }
    ],
    "priority": 100,
    "enabled": true
  }')

GDPR_ID=$(echo "$GDPR_RESPONSE" | jq -r '.policy.id // empty')
if [ -n "$GDPR_ID" ]; then
  echo "   Created: gdpr-eu-data-sovereignty (ID: $GDPR_ID)"
  echo "   Allowed providers: ollama, azure-eu"
  CREATED_IDS+=("$GDPR_ID")
else
  echo "   Failed: $GDPR_RESPONSE"
fi

# 2. HIPAA - Healthcare Data Protection
echo ""
echo "2. Creating HIPAA policy for PHI protection..."
HIPAA_RESPONSE=$(curl -s -X POST "$ENDPOINT/api/v1/dynamic-policies" \
  -u "$CLIENT_ID:${CLIENT_SECRET}" \
  -H "Content-Type: application/json" \
  -H "X-Org-ID: $ORG_ID" \
  -d '{
    "name": "hipaa-phi-protection",
    "description": "Route PHI queries to local LLM only (HIPAA Safe Harbor)",
    "type": "content",
    "category": "dynamic-compliance",
    "conditions": [
      {
        "field": "request_type",
        "operator": "equals",
        "value": "healthcare"
      }
    ],
    "actions": [
      {
        "type": "route",
        "config": {
          "allowed_providers": ["ollama"],
          "reason": "HIPAA Safe Harbor - PHI must stay local"
        }
      }
    ],
    "priority": 100,
    "enabled": true
  }')

HIPAA_ID=$(echo "$HIPAA_RESPONSE" | jq -r '.policy.id // empty')
if [ -n "$HIPAA_ID" ]; then
  echo "   Created: hipaa-phi-protection (ID: $HIPAA_ID)"
  echo "   Allowed providers: ollama"
  CREATED_IDS+=("$HIPAA_ID")
else
  echo "   Failed: $HIPAA_RESPONSE"
fi

# 3. RBI - India Financial Data Sovereignty
echo ""
echo "3. Creating RBI policy for financial data sovereignty..."
RBI_RESPONSE=$(curl -s -X POST "$ENDPOINT/api/v1/dynamic-policies" \
  -u "$CLIENT_ID:${CLIENT_SECRET}" \
  -H "Content-Type: application/json" \
  -H "X-Org-ID: $ORG_ID" \
  -d '{
    "name": "rbi-financial-data-sovereignty",
    "description": "Route banking queries to India-hosted providers (RBI Data Localization)",
    "type": "content",
    "category": "dynamic-compliance",
    "conditions": [
      {
        "field": "request_type",
        "operator": "equals",
        "value": "banking"
      },
      {
        "field": "user.region",
        "operator": "equals",
        "value": "IN"
      }
    ],
    "actions": [
      {
        "type": "route",
        "config": {
          "allowed_providers": ["azure-india", "ollama"],
          "reason": "RBI Data Localization - financial data must stay in India"
        }
      }
    ],
    "priority": 100,
    "enabled": true
  }')

RBI_ID=$(echo "$RBI_RESPONSE" | jq -r '.policy.id // empty')
if [ -n "$RBI_ID" ]; then
  echo "   Created: rbi-financial-data-sovereignty (ID: $RBI_ID)"
  echo "   Allowed providers: azure-india, ollama"
  CREATED_IDS+=("$RBI_ID")
else
  echo "   Failed: $RBI_RESPONSE"
fi

# 4. List all compliance policies
echo ""
echo "4. Listing all compliance policies..."
POLICIES=$(curl -s "$ENDPOINT/api/v1/dynamic-policies?category=dynamic-compliance" \
  -u "$CLIENT_ID:${CLIENT_SECRET}" \
  -H "X-Org-ID: $ORG_ID")

echo "$POLICIES" | jq -r '.policies[]? | "   - \(.name): \(.description)"' 2>/dev/null || echo "   No policies found or error parsing response"

COMPLIANCE_COUNT=$(echo "$POLICIES" | jq '.pagination.total_items // 0')
echo "   Found $COMPLIANCE_COUNT compliance policies"

# 5. Cleanup
echo ""
echo "5. Cleaning up test policies..."
for ID in "${CREATED_IDS[@]}"; do
  curl -s -X DELETE "$ENDPOINT/api/v1/dynamic-policies/$ID" \
    -u "$CLIENT_ID:${CLIENT_SECRET}" \
    -H "X-Org-ID: $ORG_ID" > /dev/null
done
echo "   Deleted ${#CREATED_IDS[@]} test policies"

echo ""
echo "=== Compliance Policy Examples Complete ==="
