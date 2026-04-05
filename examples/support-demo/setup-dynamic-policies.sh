#!/bin/bash
# Setup Dynamic Policies for Support Demo
#
# This script creates dynamic policies to test the CRUD APIs:
#   1. PII/EU queries route to local Ollama model (privacy/sovereignty)
#   2. Confidential queries route to Anthropic or Local (data protection)
#   3. OpenAI access restricted to managers and admins (cost control)
#
# Prerequisites:
#   - AxonFlow platform running (docker compose up -d from repo root)
#   - Support demo running (docker compose up -d from this directory)
#
# Usage:
#   chmod +x setup-dynamic-policies.sh
#   ./setup-dynamic-policies.sh

set -e

# Configuration
AGENT_URL="${AXONFLOW_AGENT_URL:-http://localhost:8080}"
ORG_ID="${ORG_ID:-demo-org}"
USER_ID="${USER_ID:-admin@company.com}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}=== AxonFlow Dynamic Policies Setup ===${NC}"
echo ""
echo "Agent URL: $AGENT_URL"
echo "Organization ID: $ORG_ID"
echo ""

# Helper function to make API calls
api_call() {
    local method="$1"
    local endpoint="$2"
    local data="$3"
    local description="$4"

    echo -e "${YELLOW}$description${NC}"

    if [ "$method" = "GET" ]; then
        response=$(curl -s -X GET "${AGENT_URL}${endpoint}" \
            -H "Content-Type: application/json" \
            -H "X-Org-ID: $ORG_ID" \
            -H "X-User-ID: $USER_ID")
    elif [ "$method" = "DELETE" ]; then
        response=$(curl -s -X DELETE "${AGENT_URL}${endpoint}" \
            -H "Content-Type: application/json" \
            -H "X-Org-ID: $ORG_ID" \
            -H "X-User-ID: $USER_ID")
    else
        response=$(curl -s -X POST "${AGENT_URL}${endpoint}" \
            -H "Content-Type: application/json" \
            -H "X-Org-ID: $ORG_ID" \
            -H "X-User-ID: $USER_ID" \
            -d "$data")
    fi

    # Check for errors
    if echo "$response" | grep -q '"error"'; then
        error_msg=$(echo "$response" | grep -o '"message":"[^"]*"' | head -1 | cut -d'"' -f4)
        echo -e "   ${RED}Error: $error_msg${NC}"
        return 1
    else
        echo -e "   ${GREEN}Success${NC}"
        echo "$response" | head -c 200
        echo ""
    fi
    echo ""
}

# Check orchestrator health
echo "Checking orchestrator health..."
health_response=$(curl -s "${AGENT_URL}/health" 2>/dev/null || echo '{"status":"unavailable"}')
if echo "$health_response" | grep -q '"status":"healthy"'; then
    echo -e "   ${GREEN}Orchestrator is healthy${NC}"
else
    echo -e "   ${RED}Orchestrator not available at ${AGENT_URL}${NC}"
    echo "   Make sure AxonFlow platform is running: docker compose up -d"
    exit 1
fi
echo ""

# List existing policies
echo -e "${BLUE}--- Current Dynamic Policies ---${NC}"
api_call "GET" "/api/v1/dynamic-policies" "" "Listing existing policies..."

# Policy 1: PII and EU Region queries route to Ollama
echo -e "${BLUE}--- Policy 1: PII/EU Queries → Ollama (Privacy & Data Sovereignty) ---${NC}"
POLICY_1='{
  "name": "pii-eu-route-to-local",
  "description": "Route PII queries and EU region users to local Ollama for privacy and data sovereignty compliance",
  "type": "content",
  "category": "dynamic-compliance",
  "tier": "tenant",
  "conditions": [
    {
      "field": "query",
      "operator": "contains_any",
      "value": ["credit card", "social security", "SSN", "passport", "bank account", "medical record", "health insurance", "date of birth", "phone number", "email address"]
    }
  ],
  "actions": [
    {
      "type": "route",
      "config": {
        "preferred_provider": "ollama",
        "fallback_provider": "anthropic",
        "reason": "PII detected - routing to local model for privacy"
      }
    },
    {
      "type": "log",
      "config": {
        "level": "info",
        "message": "PII query routed to local Ollama"
      }
    }
  ],
  "priority": 100,
  "enabled": true,
  "tags": ["privacy", "pii", "gdpr", "compliance"]
}'
api_call "POST" "/api/v1/dynamic-policies" "$POLICY_1" "Creating PII routing policy..."

# Policy 1b: EU Region routing (separate policy for region-based routing)
echo -e "${BLUE}--- Policy 1b: EU Region → Ollama Only (Strict GDPR Data Sovereignty) ---${NC}"
POLICY_1B='{
  "name": "eu-region-route-to-local",
  "description": "Route EU region user queries to local Ollama ONLY for strict GDPR data sovereignty - no US-based providers allowed",
  "type": "user",
  "category": "dynamic-compliance",
  "tier": "tenant",
  "conditions": [
    {
      "field": "user.region",
      "operator": "contains_any",
      "value": ["eu-west", "eu-central", "eu-north", "eu-south", "europe"]
    }
  ],
  "actions": [
    {
      "type": "route",
      "config": {
        "preferred_provider": "ollama",
        "allowed_providers": ["ollama"],
        "reason": "EU user - strict GDPR compliance requires local model only"
      }
    },
    {
      "type": "alert",
      "config": {
        "severity": "info",
        "channel": "compliance-team"
      }
    }
  ],
  "priority": 90,
  "enabled": true,
  "tags": ["gdpr", "eu", "data-sovereignty", "compliance", "strict"]
}'
api_call "POST" "/api/v1/dynamic-policies" "$POLICY_1B" "Creating EU region routing policy (strict GDPR)..."

# Policy 2: Confidential queries route to Anthropic or Local
echo -e "${BLUE}--- Policy 2: Confidential Queries → Anthropic/Local (Data Protection) ---${NC}"
POLICY_2='{
  "name": "confidential-route-to-secure",
  "description": "Route confidential or sensitive business queries to Anthropic or local model",
  "type": "content",
  "category": "dynamic-security",
  "tier": "tenant",
  "conditions": [
    {
      "field": "query",
      "operator": "contains_any",
      "value": ["confidential", "proprietary", "trade secret", "internal only", "restricted", "classified", "board meeting", "merger", "acquisition", "financial forecast", "salary", "compensation"]
    }
  ],
  "actions": [
    {
      "type": "route",
      "config": {
        "preferred_provider": "anthropic",
        "fallback_provider": "ollama",
        "reason": "Confidential content - routing to secure provider"
      }
    },
    {
      "type": "alert",
      "config": {
        "severity": "medium",
        "channel": "security-team"
      }
    },
    {
      "type": "log",
      "config": {
        "level": "warn",
        "message": "Confidential query detected and routed securely"
      }
    }
  ],
  "priority": 95,
  "enabled": true,
  "tags": ["confidential", "security", "data-protection"]
}'
api_call "POST" "/api/v1/dynamic-policies" "$POLICY_2" "Creating confidential content routing policy..."

# Policy 3: OpenAI access restricted to managers and admins
echo -e "${BLUE}--- Policy 3: OpenAI Access → Managers/Admins Only (Cost Control) ---${NC}"
POLICY_3='{
  "name": "openai-managers-admins-only",
  "description": "Restrict OpenAI access to managers and admins only for cost control",
  "type": "user",
  "category": "dynamic-cost",
  "tier": "tenant",
  "conditions": [
    {
      "field": "user.role",
      "operator": "not_in",
      "value": ["manager", "admin", "executive", "director"]
    },
    {
      "field": "context.requested_provider",
      "operator": "equals",
      "value": "openai"
    }
  ],
  "actions": [
    {
      "type": "route",
      "config": {
        "preferred_provider": "ollama",
        "fallback_provider": "anthropic",
        "reason": "OpenAI restricted to managers/admins - routing to alternative provider"
      }
    },
    {
      "type": "log",
      "config": {
        "level": "info",
        "message": "Non-manager user routed away from OpenAI"
      }
    }
  ],
  "priority": 85,
  "enabled": true,
  "tags": ["cost-control", "access-control", "openai"]
}'
api_call "POST" "/api/v1/dynamic-policies" "$POLICY_3" "Creating OpenAI access restriction policy..."

# Policy 3b: Block non-privileged users from explicitly requesting OpenAI
echo -e "${BLUE}--- Policy 3b: Block Agents from OpenAI (Explicit Block) ---${NC}"
POLICY_3B='{
  "name": "block-agents-from-openai",
  "description": "Block agent role users from using OpenAI to control costs",
  "type": "user",
  "category": "dynamic-cost",
  "tier": "tenant",
  "conditions": [
    {
      "field": "user.role",
      "operator": "equals",
      "value": "agent"
    }
  ],
  "actions": [
    {
      "type": "route",
      "config": {
        "preferred_provider": "ollama",
        "fallback_provider": "anthropic",
        "reason": "Agent role restricted from premium providers - using local/anthropic"
      }
    },
    {
      "type": "alert",
      "config": {
        "severity": "low",
        "channel": "cost-monitoring"
      }
    }
  ],
  "priority": 80,
  "enabled": true,
  "tags": ["cost-control", "agent-restriction"]
}'
api_call "POST" "/api/v1/dynamic-policies" "$POLICY_3B" "Creating agent role restriction policy..."

# Verify all policies were created
echo -e "${BLUE}--- Verifying Created Policies ---${NC}"
api_call "GET" "/api/v1/dynamic-policies" "" "Listing all policies..."

# Get effective policies (active, sorted by priority)
echo -e "${BLUE}--- Effective Policies (Active, Priority Sorted) ---${NC}"
api_call "GET" "/api/v1/dynamic-policies/effective" "" "Getting effective policies..."

echo ""
echo -e "${GREEN}=== Setup Complete ===${NC}"
echo ""
echo "Created 5 dynamic policies:"
echo "  1. pii-eu-route-to-local       - PII queries → Ollama (priority: 100)"
echo "  2. eu-region-route-to-local    - EU users → Ollama (priority: 90)"
echo "  3. confidential-route-to-secure - Confidential → Anthropic/Ollama (priority: 95)"
echo "  4. openai-managers-admins-only - Non-managers → Alt providers (priority: 85)"
echo "  5. block-agents-from-openai    - Agents → Ollama/Anthropic (priority: 80)"
echo ""
echo "Test these policies by:"
echo "  1. Login as john.doe@company.com (agent role) - should be routed away from OpenAI"
echo "  2. Login as sarah.manager@company.com (manager role) - should have OpenAI access"
echo "  3. Query with PII terms - should route to Ollama"
echo "  4. Login as eu.agent@company.com - should route to local model"
echo ""
echo "To delete all policies:"
echo "  curl -X DELETE '${AGENT_URL}/api/v1/dynamic-policies/{policy-id}' \\"
echo "       -H 'X-Org-ID: $ORG_ID' -H 'X-User-ID: $USER_ID'"
