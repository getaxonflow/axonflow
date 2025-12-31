#!/bin/bash
# LLM Provider Routing Examples - Direct HTTP/curl
#
# This script demonstrates how AxonFlow routes requests to LLM providers.
# Provider selection is controlled SERVER-SIDE via environment variables,
# not per-request. This ensures consistent routing policies across your org.
#
# Server-side configuration (environment variables):
#   LLM_ROUTING_STRATEGY=weighted|round_robin|failover|cost_optimized*
#   PROVIDER_WEIGHTS=openai:50,anthropic:30,ollama:20
#   DEFAULT_LLM_PROVIDER=openai
#
# * cost_optimized is Enterprise only
#
# Prerequisites:
#   - AxonFlow Agent running at http://localhost:8080
#   - Valid license key (or DEPLOYMENT_MODE=community for testing)
#   - At least one LLM provider configured (OpenAI, Anthropic, Ollama, Gemini)
#
# Usage:
#   chmod +x provider-routing.sh
#   ./provider-routing.sh

set -e

# Configuration
AGENT_URL="${AXONFLOW_ENDPOINT:-http://localhost:8080}"
LICENSE_KEY="${AXONFLOW_LICENSE_KEY:-}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "=== LLM Provider Routing Examples (HTTP) ==="
echo ""
echo "Agent URL: $AGENT_URL"
echo ""
echo "Provider selection is server-side. Configure via environment variables:"
echo "  LLM_ROUTING_STRATEGY=weighted"
echo "  PROVIDER_WEIGHTS=openai:50,anthropic:30,ollama:20"
echo ""

# Helper function for making requests
make_request() {
    local description="$1"
    local data="$2"

    echo -e "${YELLOW}$description${NC}"

    response=$(curl -s -X POST "$AGENT_URL/api/request" \
        -H "Content-Type: application/json" \
        -H "X-License-Key: $LICENSE_KEY" \
        -d "$data")

    # Check if blocked
    blocked=$(echo "$response" | jq -r '.blocked // false')
    if [ "$blocked" = "true" ]; then
        reason=$(echo "$response" | jq -r '.block_reason')
        echo -e "   ${RED}Blocked: $reason${NC}"
    else
        # Extract response content
        content=$(echo "$response" | jq -r '.data.response // .data // .result // "No response"' | head -c 100)
        success=$(echo "$response" | jq -r '.success')
        echo -e "   Response: $content..."
        echo -e "   Success: ${GREEN}$success${NC}"
    fi
    echo ""
}

# Example 1: Send a request (server decides which provider to use)
echo "1. Send request (server routes based on configured strategy):"
make_request "   Sending query..." '{
    "query": "What is 2 + 2? Answer with just the number.",
    "user_token": "demo-user",
    "client_id": "http-example",
    "request_type": "llm_chat"
}'

# Example 2: Multiple requests show distribution based on weights
echo "2. Multiple requests (observe provider distribution):"
for i in 1 2 3; do
    make_request "   Request $i..." "{
        \"query\": \"Question $i: What is the capital of France?\",
        \"user_token\": \"demo-user\",
        \"client_id\": \"http-example\",
        \"request_type\": \"llm_chat\"
    }"
done

# Example 3: Health check
echo "3. Health check:"
health=$(curl -s "$AGENT_URL/health")
status=$(echo "$health" | jq -r '.status')
echo -e "   Status: ${GREEN}$status${NC}"
echo ""

# Example 4: Gateway Mode (Pre-check + Audit)
echo "4. Gateway Mode (Pre-check + Audit):"
echo "   Step 1: Pre-check request..."
precheck=$(curl -s -X POST "$AGENT_URL/api/policy/pre-check" \
    -H "Content-Type: application/json" \
    -H "X-License-Key: $LICENSE_KEY" \
    -d '{
        "query": "What is artificial intelligence?",
        "user_token": "demo-user",
        "client_id": "http-example"
    }')

approved=$(echo "$precheck" | jq -r '.approved // false')
context_id=$(echo "$precheck" | jq -r '.context_id // "none"')

if [ "$approved" = "true" ]; then
    echo -e "   Pre-check: ${GREEN}Approved${NC}"
    echo "   Context ID: $context_id"

    echo "   Step 2: (Skipped) Make direct LLM call..."
    echo "   Step 3: Audit the result..."

    audit=$(curl -s -X POST "$AGENT_URL/api/audit/llm-call" \
        -H "Content-Type: application/json" \
        -H "X-License-Key: $LICENSE_KEY" \
        -d "{
            \"context_id\": \"$context_id\",
            \"client_id\": \"http-example\",
            \"provider\": \"openai\",
            \"model\": \"gpt-4o\",
            \"token_usage\": {
                \"prompt_tokens\": 50,
                \"completion_tokens\": 100,
                \"total_tokens\": 150
            },
            \"latency_ms\": 500
        }")

    audit_success=$(echo "$audit" | jq -r '.success // false')
    audit_id=$(echo "$audit" | jq -r '.audit_id // "none"')
    echo -e "   Audit logged: ${GREEN}$audit_success${NC}"
    echo "   Audit ID: $audit_id"
else
    block_reason=$(echo "$precheck" | jq -r '.block_reason // "Unknown"')
    echo -e "   Pre-check: ${RED}Blocked - $block_reason${NC}"
fi
echo ""

echo "=== Examples Complete ==="
echo ""
echo "To change provider routing, update server environment variables:"
echo "  - LLM_ROUTING_STRATEGY: weighted, round_robin, failover"
echo "  - PROVIDER_WEIGHTS: distribution percentages"
echo "  - DEFAULT_LLM_PROVIDER: fallback for failover strategy"
echo ""
echo "For more examples, see:"
echo "  - SDK examples: ../go/, ../python/, ../typescript/, ../java/"
echo "  - Documentation: https://docs.getaxonflow.com/docs/llm/overview"
