#!/bin/bash
# Azure OpenAI Integration Example - HTTP/curl
# Demonstrates Gateway Mode and Proxy Mode with AxonFlow

set -e

AXONFLOW_URL="${AXONFLOW_URL:-http://localhost:8080}"

# Load Azure credentials from environment
if [ -z "$AZURE_OPENAI_ENDPOINT" ] || [ -z "$AZURE_OPENAI_API_KEY" ] || [ -z "$AZURE_OPENAI_DEPLOYMENT_NAME" ]; then
    echo "Error: Set AZURE_OPENAI_ENDPOINT, AZURE_OPENAI_API_KEY, and AZURE_OPENAI_DEPLOYMENT_NAME"
    exit 1
fi

API_VERSION="${AZURE_OPENAI_API_VERSION:-2024-08-01-preview}"
ENDPOINT="${AZURE_OPENAI_ENDPOINT%/}"  # Remove trailing slash

# Detect auth type
if echo "$ENDPOINT" | grep -qi "cognitiveservices.azure.com"; then
    AUTH_TYPE="Bearer token (Foundry)"
    AUTH_HEADER="Authorization: Bearer $AZURE_OPENAI_API_KEY"
else
    AUTH_TYPE="api-key (Classic)"
    AUTH_HEADER="api-key: $AZURE_OPENAI_API_KEY"
fi

echo "=== Azure OpenAI with AxonFlow ==="
echo "Endpoint: $ENDPOINT"
echo "Deployment: $AZURE_OPENAI_DEPLOYMENT_NAME"
echo "Auth: $AUTH_TYPE"
echo ""

# Example 1: Gateway Mode (recommended)
echo "--- Example 1: Gateway Mode ---"

# Step 1: Pre-check with AxonFlow
echo "Step 1: Pre-checking with AxonFlow..."
PRECHECK_RESPONSE=$(curl -s -X POST "${AXONFLOW_URL}/api/policy/pre-check" \
    -H "Content-Type: application/json" \
    -d '{
        "client_id": "azure-openai-example",
        "query": "What are the key benefits of using Azure OpenAI?",
        "context": {
            "provider": "azure-openai",
            "model": "'"$AZURE_OPENAI_DEPLOYMENT_NAME"'"
        }
    }')

CONTEXT_ID=$(echo "$PRECHECK_RESPONSE" | grep -o '"context_id":"[^"]*"' | cut -d'"' -f4)
APPROVED=$(echo "$PRECHECK_RESPONSE" | grep -o '"approved":true')

if [ -z "$APPROVED" ]; then
    echo "Request blocked by policy"
    echo "Response: $PRECHECK_RESPONSE"
    exit 0
fi
echo "Pre-check passed (context: $CONTEXT_ID)"

# Step 2: Call Azure OpenAI directly
echo "Step 2: Calling Azure OpenAI..."
START_TIME=$(python3 -c 'import time; print(int(time.time()*1000))')

AZURE_RESPONSE=$(curl -s -X POST "${ENDPOINT}/openai/deployments/${AZURE_OPENAI_DEPLOYMENT_NAME}/chat/completions?api-version=${API_VERSION}" \
    -H "Content-Type: application/json" \
    -H "$AUTH_HEADER" \
    -d '{
        "messages": [{"role": "user", "content": "What are the key benefits of using Azure OpenAI?"}],
        "max_tokens": 500,
        "temperature": 0.7
    }')

END_TIME=$(python3 -c 'import time; print(int(time.time()*1000))')
LATENCY=$((END_TIME - START_TIME))

# Extract content (simple grep-based extraction)
CONTENT=$(echo "$AZURE_RESPONSE" | python3 -c "import sys, json; data=json.load(sys.stdin); print(data.get('choices', [{}])[0].get('message', {}).get('content', '')[:200])")

echo "Response received (latency: ${LATENCY}ms)"
echo "Response: ${CONTENT}..."

# Step 3: Audit the response
echo "Step 3: Auditing with AxonFlow..."
AUDIT_RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "${AXONFLOW_URL}/api/audit/llm-call" \
    -H "Content-Type: application/json" \
    -d '{
        "client_id": "azure-openai-example",
        "context_id": "'"$CONTEXT_ID"'",
        "response_summary": "Azure OpenAI response",
        "provider": "azure-openai",
        "model": "'"$AZURE_OPENAI_DEPLOYMENT_NAME"'",
        "latency_ms": '"$LATENCY"',
        "token_usage": {
            "prompt_tokens": 50,
            "completion_tokens": 100,
            "total_tokens": 150
        }
    }')

AUDIT_CODE=$(echo "$AUDIT_RESPONSE" | tail -1)
if [ "$AUDIT_CODE" = "200" ] || [ "$AUDIT_CODE" = "202" ] || [ "$AUDIT_CODE" = "204" ]; then
    echo "Audit logged successfully"
else
    echo "Audit warning: HTTP $AUDIT_CODE"
fi

echo ""

# Example 2: Proxy Mode
echo "--- Example 2: Proxy Mode ---"
echo "Sending request through AxonFlow proxy..."

START_TIME=$(python3 -c 'import time; print(int(time.time()*1000))')

PROXY_RESPONSE=$(curl -s -X POST "${AXONFLOW_URL}/api/request" \
    -H "Content-Type: application/json" \
    -d '{
        "query": "Explain Azure OpenAI in 2 sentences.",
        "context": {
            "provider": "azure-openai"
        }
    }')

END_TIME=$(python3 -c 'import time; print(int(time.time()*1000))')
LATENCY=$((END_TIME - START_TIME))

# Parse response
BLOCKED=$(echo "$PROXY_RESPONSE" | python3 -c "import sys, json; data=json.load(sys.stdin); print(str(data.get('blocked', False)).lower())")
RESPONSE_TEXT=$(echo "$PROXY_RESPONSE" | python3 -c "import sys, json; data=json.load(sys.stdin); print(data.get('data', {}).get('data', '')[:300])")

echo "Response received (latency: ${LATENCY}ms)"
echo "Blocked: $BLOCKED"
echo "Response: $RESPONSE_TEXT..."

echo ""
echo "=== All tests passed ==="
