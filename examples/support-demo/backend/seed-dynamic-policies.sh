#!/bin/bash
# Seed dynamic policies for support demo
# Issue #883 - Strict provider enforcement policies

set -e

ORCHESTRATOR_URL="${ORCHESTRATOR_URL:-http://localhost:8081}"
TENANT_ID="${TENANT_ID:-demo-tenant}"

echo "=== Seeding Dynamic Policies for Support Demo ==="
echo "Orchestrator URL: $ORCHESTRATOR_URL"
echo "Tenant ID: $TENANT_ID"
echo ""

# Function to create a policy
create_policy() {
    local name="$1"
    local json_file="$2"

    echo "Creating policy: $name"
    response=$(curl -s -w "\n%{http_code}" -X POST "$ORCHESTRATOR_URL/api/v1/dynamic-policies" \
        -H "Content-Type: application/json" \
        -H "X-Tenant-ID: $TENANT_ID" \
        -d @"$json_file")

    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | sed '$d')

    if [ "$http_code" = "201" ] || [ "$http_code" = "200" ]; then
        echo "  ✅ Created successfully"
        echo "$body" | jq -r '.policy.id // .id' 2>/dev/null || true
    elif [ "$http_code" = "409" ]; then
        echo "  ⚠️  Already exists (skipping)"
    else
        echo "  ❌ Failed (HTTP $http_code)"
        echo "$body" | jq '.' 2>/dev/null || echo "$body"
    fi
    echo ""
}

# Create temp directory for policy JSON files
POLICY_DIR=$(mktemp -d)
trap "rm -rf $POLICY_DIR" EXIT

# Policy 1: PII Content - Ollama Only (strict local processing)
cat > "$POLICY_DIR/pii-ollama.json" << 'EOF'
{
  "name": "PII Content - Ollama Only",
  "description": "Route PII queries to Ollama ONLY - strict compliance. No fallback to cloud providers.",
  "type": "content",
  "category": "dynamic-compliance",
  "enabled": true,
  "priority": 100,
  "conditions": [
    {"field": "query", "operator": "contains", "value": "PII"},
    {"field": "query", "operator": "contains", "value": "SSN"}
  ],
  "actions": [{
    "type": "route",
    "config": {
      "preferred_provider": "ollama",
      "allowed_providers": ["ollama"],
      "reason": "PII compliance - data must stay local"
    }
  }]
}
EOF

# Policy 2: GDPR EU Agent - Ollama Only
cat > "$POLICY_DIR/gdpr-eu.json" << 'EOF'
{
  "name": "GDPR EU Agent - Ollama Only",
  "description": "EU agents must use local processing only for GDPR compliance. No data leaves the region.",
  "type": "user",
  "category": "dynamic-compliance",
  "enabled": true,
  "priority": 100,
  "conditions": [
    {"field": "agent_id", "operator": "contains", "value": "eu-"}
  ],
  "actions": [{
    "type": "route",
    "config": {
      "preferred_provider": "ollama",
      "allowed_providers": ["ollama"],
      "reason": "GDPR compliance - EU data must stay local"
    }
  }]
}
EOF

# Policy 3: Confidential Content - No OpenAI
cat > "$POLICY_DIR/confidential-no-openai.json" << 'EOF'
{
  "name": "Confidential Content - No OpenAI",
  "description": "Confidential queries can use Anthropic or Ollama, but NOT OpenAI.",
  "type": "content",
  "category": "dynamic-compliance",
  "enabled": true,
  "priority": 90,
  "conditions": [
    {"field": "query", "operator": "contains", "value": "confidential"}
  ],
  "actions": [{
    "type": "route",
    "config": {
      "preferred_provider": "anthropic",
      "allowed_providers": ["anthropic", "ollama"],
      "reason": "Confidential data - OpenAI not permitted"
    }
  }]
}
EOF

# Policy 4: Manager Role - Full Access
cat > "$POLICY_DIR/manager-full-access.json" << 'EOF'
{
  "name": "Manager Role - Full Provider Access",
  "description": "Managers can use any provider including premium OpenAI models.",
  "type": "user",
  "category": "dynamic-access",
  "enabled": true,
  "priority": 80,
  "conditions": [
    {"field": "user_role", "operator": "equals", "value": "manager"}
  ],
  "actions": [{
    "type": "route",
    "config": {
      "preferred_provider": "openai",
      "allowed_providers": ["openai", "anthropic", "ollama"],
      "reason": "Manager role - full provider access"
    }
  }]
}
EOF

# Policy 5: Cost Control - Standard Users
cat > "$POLICY_DIR/cost-control-standard.json" << 'EOF'
{
  "name": "Cost Control - Standard Users",
  "description": "Standard users should prefer Ollama (free) with Anthropic as fallback. No OpenAI to control costs.",
  "type": "cost",
  "category": "dynamic-cost",
  "enabled": true,
  "priority": 70,
  "conditions": [
    {"field": "user_role", "operator": "equals", "value": "user"}
  ],
  "actions": [{
    "type": "route",
    "config": {
      "preferred_provider": "ollama",
      "allowed_providers": ["ollama", "anthropic"],
      "reason": "Cost control - standard users limited to Ollama/Anthropic"
    }
  }]
}
EOF

# Policy 6: High Risk - Block and Alert
cat > "$POLICY_DIR/high-risk-block.json" << 'EOF'
{
  "name": "High Risk Query - Block",
  "description": "Block queries containing credit card patterns and alert security team.",
  "type": "content",
  "category": "dynamic-security",
  "enabled": true,
  "priority": 150,
  "conditions": [
    {"field": "query", "operator": "regex", "value": "\\b\\d{4}[- ]?\\d{4}[- ]?\\d{4}[- ]?\\d{4}\\b"}
  ],
  "actions": [
    {
      "type": "block",
      "config": {
        "reason": "Credit card data detected - blocked for security"
      }
    },
    {
      "type": "modify_risk",
      "config": {
        "add": 50
      }
    }
  ]
}
EOF

# Policy 7: Healthcare Data - Local Only
cat > "$POLICY_DIR/healthcare-local.json" << 'EOF'
{
  "name": "Healthcare Data - Local Processing",
  "description": "HIPAA compliance - healthcare/medical data must be processed locally.",
  "type": "content",
  "category": "dynamic-compliance",
  "enabled": true,
  "priority": 100,
  "conditions": [
    {"field": "query", "operator": "contains", "value": "patient"},
    {"field": "query", "operator": "contains", "value": "medical"},
    {"field": "query", "operator": "contains", "value": "diagnosis"}
  ],
  "actions": [{
    "type": "route",
    "config": {
      "preferred_provider": "ollama",
      "allowed_providers": ["ollama"],
      "reason": "HIPAA compliance - healthcare data must stay local"
    }
  }]
}
EOF

# Policy 8: India Region - RBI Compliance
cat > "$POLICY_DIR/india-rbi.json" << 'EOF'
{
  "name": "India Region - RBI Compliance",
  "description": "Financial data from India must use local providers only (RBI data localization).",
  "type": "user",
  "category": "dynamic-compliance",
  "enabled": true,
  "priority": 100,
  "conditions": [
    {"field": "agent_id", "operator": "contains", "value": "india-"},
    {"field": "agent_id", "operator": "contains", "value": "-in"}
  ],
  "actions": [{
    "type": "route",
    "config": {
      "preferred_provider": "ollama",
      "allowed_providers": ["ollama"],
      "reason": "RBI compliance - Indian financial data must stay local"
    }
  }]
}
EOF

echo "=== Creating Policies ==="
echo ""

create_policy "PII Content - Ollama Only" "$POLICY_DIR/pii-ollama.json"
create_policy "GDPR EU Agent - Ollama Only" "$POLICY_DIR/gdpr-eu.json"
create_policy "Confidential Content - No OpenAI" "$POLICY_DIR/confidential-no-openai.json"
create_policy "Manager Role - Full Provider Access" "$POLICY_DIR/manager-full-access.json"
create_policy "Cost Control - Standard Users" "$POLICY_DIR/cost-control-standard.json"
create_policy "High Risk Query - Block" "$POLICY_DIR/high-risk-block.json"
create_policy "Healthcare Data - Local Processing" "$POLICY_DIR/healthcare-local.json"
create_policy "India Region - RBI Compliance" "$POLICY_DIR/india-rbi.json"

echo "=== Policy Seeding Complete ==="
echo ""
echo "Verify policies with:"
echo "  curl -s -H 'X-Tenant-ID: $TENANT_ID' '$ORCHESTRATOR_URL/api/v1/dynamic-policies' | jq '.policies[].name'"
