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
#   AXONFLOW_ORCHESTRATOR_ENDPOINT - Orchestrator URL (default: http://localhost:8081)
#
# Note: Dynamic policies are managed by the Orchestrator, not the Agent.

set -e

ENDPOINT="${AXONFLOW_ORCHESTRATOR_ENDPOINT:-http://localhost:8081}"
ORG_ID="${ORG_ID:-demo-org}"
TENANT_ID="${TENANT_ID:-demo-tenant}"

echo "=== Compliance Policy Examples (HTTP API) ==="
echo ""
echo "Endpoint: $ENDPOINT"
echo ""

CREATED_IDS=()

# 1. GDPR - EU Data Sovereignty
echo "1. Creating GDPR policy for EU data sovereignty..."
GDPR_RESPONSE=$(curl -s -X POST "$ENDPOINT/api/v1/dynamic-policies" \
  -H "Content-Type: application/json" \
  -H "X-Org-ID: $ORG_ID" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{
    "name": "gdpr-eu-data-sovereignty",
    "description": "Route EU users to EU-hosted LLMs only (GDPR Article 44)",
    "conditions": {
      "user_region": "EU"
    },
    "allowed_providers": ["ollama", "azure-eu"],
    "action": "allow",
    "enabled": true
  }')

GDPR_ID=$(echo "$GDPR_RESPONSE" | jq -r '.id // empty')
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
  -H "Content-Type: application/json" \
  -H "X-Org-ID: $ORG_ID" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{
    "name": "hipaa-phi-protection",
    "description": "Route PHI queries to local LLM only (HIPAA Safe Harbor)",
    "conditions": {
      "request_type": "healthcare",
      "contains_phi": true
    },
    "allowed_providers": ["ollama"],
    "action": "allow",
    "enabled": true
  }')

HIPAA_ID=$(echo "$HIPAA_RESPONSE" | jq -r '.id // empty')
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
  -H "Content-Type: application/json" \
  -H "X-Org-ID: $ORG_ID" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{
    "name": "rbi-financial-data-sovereignty",
    "description": "Route banking queries to India-hosted providers (RBI Data Localization)",
    "conditions": {
      "request_type": "banking",
      "user_region": "IN"
    },
    "allowed_providers": ["azure-india", "ollama"],
    "action": "allow",
    "enabled": true
  }')

RBI_ID=$(echo "$RBI_RESPONSE" | jq -r '.id // empty')
if [ -n "$RBI_ID" ]; then
  echo "   Created: rbi-financial-data-sovereignty (ID: $RBI_ID)"
  echo "   Allowed providers: azure-india, ollama"
  CREATED_IDS+=("$RBI_ID")
else
  echo "   Failed: $RBI_RESPONSE"
fi

# 4. List all compliance policies
echo ""
echo "4. Listing all compliance policies with provider restrictions..."
POLICIES=$(curl -s "$ENDPOINT/api/v1/dynamic-policies" \
  -H "X-Org-ID: $ORG_ID" \
  -H "X-Tenant-ID: $TENANT_ID")

echo "$POLICIES" | jq -r '.policies[] | select(.allowed_providers != null and (.allowed_providers | length) > 0) | "   - \(.name): providers=\(.allowed_providers)"'

COMPLIANCE_COUNT=$(echo "$POLICIES" | jq '[.policies[] | select(.allowed_providers != null and (.allowed_providers | length) > 0)] | length')
echo "   Found $COMPLIANCE_COUNT policies with provider restrictions"

# 5. Cleanup
echo ""
echo "5. Cleaning up test policies..."
for ID in "${CREATED_IDS[@]}"; do
  curl -s -X DELETE "$ENDPOINT/api/v1/dynamic-policies/$ID" \
    -H "X-Org-ID: $ORG_ID" \
    -H "X-Tenant-ID: $TENANT_ID" > /dev/null
done
echo "   Deleted ${#CREATED_IDS[@]} test policies"

echo ""
echo "=== Compliance Policy Examples Complete ==="
