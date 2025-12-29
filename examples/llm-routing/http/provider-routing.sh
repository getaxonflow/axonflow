#!/bin/bash
# LLM Provider Routing Examples - Direct HTTP/curl
#
# This script demonstrates LLM provider routing using direct HTTP calls.
# No SDK required - works with any HTTP client.
#
# Prerequisites:
#   - AxonFlow Agent running at http://localhost:8080
#   - Valid license key (or SELF_HOSTED_MODE=true for testing)
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

# Example 1: Default routing (server decides provider)
echo "1. Default routing (server decides provider):"
make_request "   Sending query..." '{
    "query": "What is 2 + 2? Answer with just the number.",
    "user_token": "demo-user",
    "client_id": "http-example",
    "request_type": "llm_chat"
}'

# Example 2: Request Ollama (local provider)
echo "2. Request specific provider (Ollama):"
make_request "   Sending query to Ollama..." '{
    "query": "What is the capital of France? Answer in one word.",
    "user_token": "demo-user",
    "client_id": "http-example",
    "request_type": "llm_chat",
    "context": {
        "provider": "ollama"
    }
}'

# Example 3: Request with specific model
echo "3. Request with specific model override:"
make_request "   Sending query with model override..." '{
    "query": "What is machine learning? Answer in one sentence.",
    "user_token": "demo-user",
    "client_id": "http-example",
    "request_type": "llm_chat",
    "context": {
        "provider": "ollama",
        "model": "tinyllama"
    }
}'

# Example 4: Request OpenAI (if configured)
echo "4. Request OpenAI provider:"
make_request "   Sending query to OpenAI..." '{
    "query": "What is Python? Answer in one sentence.",
    "user_token": "demo-user",
    "client_id": "http-example",
    "request_type": "llm_chat",
    "context": {
        "provider": "openai"
    }
}'

# Example 5: Request Anthropic (if configured)
echo "5. Request Anthropic provider:"
make_request "   Sending query to Anthropic..." '{
    "query": "What is JavaScript? Answer in one sentence.",
    "user_token": "demo-user",
    "client_id": "http-example",
    "request_type": "llm_chat",
    "context": {
        "provider": "anthropic"
    }
}'

# Example 6: Request Gemini (if configured)
echo "6. Request Google Gemini provider:"
make_request "   Sending query to Gemini..." '{
    "query": "What is Go programming language? Answer in one sentence.",
    "user_token": "demo-user",
    "client_id": "http-example",
    "request_type": "llm_chat",
    "context": {
        "provider": "gemini"
    }
}'

# Example 7: Health check
echo "7. Health check:"
health=$(curl -s "$AGENT_URL/health")
status=$(echo "$health" | jq -r '.status')
echo -e "   Status: ${GREEN}$status${NC}"
echo ""

# Example 8: Gateway Mode (Pre-check + Audit)
echo "8. Gateway Mode (Pre-check + Audit):"
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

    audit=$(curl -s -X POST "$AGENT_URL/api/policy/audit" \
        -H "Content-Type: application/json" \
        -H "X-License-Key: $LICENSE_KEY" \
        -d "{
            \"context_id\": \"$context_id\",
            \"response_metadata\": {
                \"provider\": \"openai\",
                \"model\": \"gpt-4o\",
                \"tokens_used\": 150,
                \"latency_ms\": 500
            }
        }")

    audit_success=$(echo "$audit" | jq -r '.success // false')
    echo -e "   Audit logged: ${GREEN}$audit_success${NC}"
else
    block_reason=$(echo "$precheck" | jq -r '.block_reason // "Unknown"')
    echo -e "   Pre-check: ${RED}Blocked - $block_reason${NC}"
fi
echo ""

echo "=== Examples Complete ==="
echo ""
echo "For more examples, see:"
echo "  - SDK examples: ../go/, ../python/, ../typescript/, ../java/"
echo "  - Documentation: https://docs.getaxonflow.com/docs/llm/overview"
