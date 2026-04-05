#!/bin/bash
# Support Demo - Setup AxonFlow Policies
#
# This script creates demo-specific policies via AxonFlow's Policy API.
# Run AFTER starting AxonFlow platform from repo root.
#
# Policies:
#   1. Agent Role LLM Restriction - Agents cannot use OpenAI (cost control)
#   2. PII Query Routing - PII-containing queries route to local model
#   3. EU Region Data Sovereignty - EU users route to local model (Ollama)

set -e

AGENT_URL="${AXONFLOW_AGENT_URL:-http://localhost:8080}"
TENANT_ID="${AXONFLOW_TENANT_ID:-support-demo}"

echo "🔧 Setting up Support Demo policies..."
echo "   Agent: $AGENT_URL"
echo "   Tenant: $TENANT_ID"
echo ""

# Wait for orchestrator to be ready
echo "⏳ Waiting for AxonFlow Agent..."
for i in {1..30}; do
  if curl -s "$AGENT_URL/health" > /dev/null 2>&1; then
    echo "✅ Agent is ready"
    break
  fi
  if [ $i -eq 30 ]; then
    echo "❌ Timeout waiting for agent"
    exit 1
  fi
  sleep 1
done

echo ""

# Policy 1: Agent Role LLM Restriction
# Agents (support staff) are routed to cost-effective providers (Anthropic/local)
# This demonstrates role-based LLM governance for cost control
echo "📋 Creating policy: Agent Role LLM Restriction..."
curl -s -X POST "$AGENT_URL/api/v1/policies" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Agent Role LLM Restriction",
    "description": "Route support agents to cost-effective providers. Agents use Anthropic/local instead of OpenAI for cost control.",
    "type": "user",
    "category": "dynamic-cost",
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
          "preferred_provider": "anthropic",
          "fallback_provider": "local_llm",
          "reason": "Cost optimization: agents route to Anthropic"
        }
      },
      {
        "type": "log",
        "config": {
          "audit_type": "cost_governance",
          "message": "Agent routed to cost-effective provider"
        }
      }
    ],
    "priority": 80,
    "enabled": true,
    "tags": ["demo", "cost-control", "role-based"]
  }' | jq -r 'if .id then "✅ Created: \(.id)" else "⚠️  \(.error.message // "Already exists or error")" end' 2>/dev/null || echo "✅ Policy configured"

# Policy 2: PII Query Routing
# Queries containing PII patterns route to local model (data never leaves premises)
# This demonstrates privacy-preserving LLM governance
echo "📋 Creating policy: PII Query Routing..."
curl -s -X POST "$AGENT_URL/api/v1/policies" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "PII Query Routing",
    "description": "Route queries containing PII to local model. Sensitive data never leaves premises.",
    "type": "content",
    "category": "dynamic-security",
    "conditions": [
      {
        "field": "query",
        "operator": "regex",
        "value": "(?i)(ssn|social.?security|\\b\\d{3}-\\d{2}-\\d{4}\\b|credit.?card|\\b\\d{4}[- ]?\\d{4}[- ]?\\d{4}[- ]?\\d{4}\\b)"
      }
    ],
    "actions": [
      {
        "type": "route",
        "config": {
          "preferred_provider": "local_llm",
          "fallback_provider": "anthropic",
          "reason": "PII detected: routing to on-premises model"
        }
      },
      {
        "type": "log",
        "config": {
          "audit_type": "pii_routing",
          "message": "Query with PII routed to local model"
        }
      },
      {
        "type": "alert",
        "config": {
          "channel": "security",
          "severity": "medium"
        }
      }
    ],
    "priority": 90,
    "enabled": true,
    "tags": ["demo", "pii", "privacy"]
  }' | jq -r 'if .id then "✅ Created: \(.id)" else "⚠️  \(.error.message // "Already exists or error")" end' 2>/dev/null || echo "✅ Policy configured"

# Policy 3: EU Region Data Sovereignty
# EU users route to local model (Ollama) to ensure data stays in region
# This demonstrates GDPR/data sovereignty compliance
echo "📋 Creating policy: EU Region Data Sovereignty..."
curl -s -X POST "$AGENT_URL/api/v1/policies" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "EU Region Data Sovereignty",
    "description": "Route EU users to local model (Ollama) for data sovereignty compliance. Data never leaves the region.",
    "type": "user",
    "category": "dynamic-compliance",
    "conditions": [
      {
        "field": "context.user_region",
        "operator": "in",
        "value": ["eu-west", "eu-central", "eu", "europe"]
      }
    ],
    "actions": [
      {
        "type": "route",
        "config": {
          "preferred_provider": "local_llm",
          "fallback_provider": "anthropic",
          "reason": "EU data sovereignty: routing to on-premises Ollama"
        }
      },
      {
        "type": "log",
        "config": {
          "audit_type": "gdpr_routing",
          "message": "EU user routed to local model for data sovereignty"
        }
      }
    ],
    "priority": 85,
    "enabled": true,
    "tags": ["demo", "gdpr", "eu", "data-sovereignty"]
  }' | jq -r 'if .id then "✅ Created: \(.id)" else "⚠️  \(.error.message // "Already exists or error")" end' 2>/dev/null || echo "✅ Policy configured"

echo ""
echo "🎉 Demo policies configured!"
echo ""
echo "Test scenarios:"
echo "  • Login as john.doe@company.com (agent) → Routes to Anthropic"
echo "  • Login as eu.agent@company.com (EU agent) → Routes to Local/Ollama"
echo "  • Query with SSN like '123-45-6789' → Routes to Local model"
echo "  • Login as admin@company.com → Full access to all providers"
echo ""
echo "View policies: curl $AGENT_URL/api/v1/dynamic-policies | jq"
