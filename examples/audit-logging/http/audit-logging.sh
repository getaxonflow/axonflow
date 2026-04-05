#!/bin/bash
# AxonFlow Audit Logging - HTTP/curl
#
# Demonstrates the complete Gateway Mode workflow and audit log querying
# using raw HTTP requests.

set -e

AGENT_URL="${AXONFLOW_AGENT_URL:-http://localhost:8080}"
CLIENT_ID="${AXONFLOW_CLIENT_ID:-community}"
CLIENT_SECRET="${AXONFLOW_CLIENT_SECRET:-}"
USER_TOKEN="${AXONFLOW_USER_TOKEN:-audit-user}"

AUTH_HEADER=()
if [ -n "$CLIENT_SECRET" ]; then
    AUTH_B64=$(printf '%s:%s' "$CLIENT_ID" "$CLIENT_SECRET" | base64)
    AUTH_HEADER=(-H "Authorization: Basic $AUTH_B64")
fi

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# Portable millisecond timestamp (works on macOS and Linux)
get_ms() {
    if command -v gdate &> /dev/null; then
        # GNU date (Linux or macOS with coreutils)
        gdate +%s%3N
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS: use python for milliseconds
        python3 -c 'import time; print(int(time.time() * 1000))'
    else
        # Linux
        date +%s%3N
    fi
}

echo "AxonFlow Audit Logging - HTTP/curl"
echo "========================================"
echo ""
echo "Agent URL: $AGENT_URL"
echo ""

# =========================================================================
# Gateway Mode Workflow
# =========================================================================

echo -e "${CYAN}Gateway Mode Workflow${NC}"
echo "========================================"
echo ""

QUERY="What are best practices for AI model deployment?"
echo "Query: \"$QUERY\""
echo ""

# Step 1: Pre-check
echo -e "${YELLOW}Step 1: Policy Pre-Check...${NC}"
PRECHECK_START=$(get_ms)

PRECHECK_RESPONSE=$(curl -s -X POST "$AGENT_URL/api/policy/pre-check" \
    -H "Content-Type: application/json" \
    "${AUTH_HEADER[@]}" \
    -H "Authorization: Basic $AUTH_B64" \
    -d "{
        \"query\": \"$QUERY\",
        \"user_token\": \"$USER_TOKEN\",
        \"client_id\": \"$CLIENT_ID\"
    }")

PRECHECK_END=$(get_ms)
PRECHECK_LATENCY=$((PRECHECK_END - PRECHECK_START))

APPROVED=$(echo "$PRECHECK_RESPONSE" | jq -r '.approved // false')
CONTEXT_ID=$(echo "$PRECHECK_RESPONSE" | jq -r '.context_id // "none"')

echo "   Latency: ${PRECHECK_LATENCY}ms"
echo "   Context ID: $CONTEXT_ID"

if [ "$APPROVED" = "true" ]; then
    echo -e "   Status: ${GREEN}APPROVED${NC}"
else
    BLOCK_REASON=$(echo "$PRECHECK_RESPONSE" | jq -r '.block_reason // "Unknown"')
    echo -e "   Status: ${RED}BLOCKED - $BLOCK_REASON${NC}"
    exit 1
fi
echo ""

# Step 2: LLM Call (Simulated)
echo -e "${YELLOW}Step 2: LLM Call (Simulated)...${NC}"
LLM_START=$(get_ms)

# Simulate LLM latency
sleep 0.1

LLM_END=$(get_ms)
LLM_LATENCY=$((LLM_END - LLM_START))
PROMPT_TOKENS=50
COMPLETION_TOKENS=100
TOTAL_TOKENS=150

echo "   Latency: ${LLM_LATENCY}ms"
echo "   Tokens: $PROMPT_TOKENS prompt, $COMPLETION_TOKENS completion"
echo ""

# Step 3: Audit
echo -e "${YELLOW}Step 3: Audit Logging...${NC}"
AUDIT_START=$(get_ms)

AUDIT_RESPONSE=$(curl -s -X POST "$AGENT_URL/api/audit/llm-call" \
    -H "Content-Type: application/json" \
    "${AUTH_HEADER[@]}" \
    -H "Authorization: Basic $AUTH_B64" \
    -d "{
        \"context_id\": \"$CONTEXT_ID\",
        \"client_id\": \"$CLIENT_ID\",
        \"provider\": \"openai\",
        \"model\": \"gpt-4\",
        \"token_usage\": {
            \"prompt_tokens\": $PROMPT_TOKENS,
            \"completion_tokens\": $COMPLETION_TOKENS,
            \"total_tokens\": $TOTAL_TOKENS
        },
        \"latency_ms\": $LLM_LATENCY
    }")

AUDIT_END=$(get_ms)
AUDIT_LATENCY=$((AUDIT_END - AUDIT_START))

AUDIT_SUCCESS=$(echo "$AUDIT_RESPONSE" | jq -r '.success // false')
AUDIT_ID=$(echo "$AUDIT_RESPONSE" | jq -r '.audit_id // "none"')

echo "   Latency: ${AUDIT_LATENCY}ms"
echo "   Audit ID: $AUDIT_ID"
if [ "$AUDIT_SUCCESS" = "true" ]; then
    echo -e "   Status: ${GREEN}LOGGED${NC}"
else
    echo -e "   Status: ${RED}FAILED${NC}"
fi
echo ""

# Summary
GOVERNANCE=$((PRECHECK_LATENCY + AUDIT_LATENCY))
TOTAL=$((PRECHECK_LATENCY + LLM_LATENCY + AUDIT_LATENCY))

echo "Latency Breakdown:"
echo "   Pre-check:  ${PRECHECK_LATENCY}ms"
echo "   LLM call:   ${LLM_LATENCY}ms"
echo "   Audit:      ${AUDIT_LATENCY}ms"
echo "   Governance: ${GOVERNANCE}ms"
echo "   Total:      ${TOTAL}ms"
echo ""

# =========================================================================
# Tool Call Audit (Non-LLM tool tracking)
# =========================================================================

echo -e "${CYAN}Tool Call Audit${NC}"
echo "========================================"
echo ""
echo "Recording a non-LLM tool call (e.g., API call, MCP execution)..."
echo ""

TOOL_AUDIT_HTTP_CODE=$(curl -s -o /tmp/tool_audit_response.json -w "%{http_code}" \
    -X POST "$AGENT_URL/api/v1/audit/tool-call" \
    -H "Content-Type: application/json" \
    "${AUTH_HEADER[@]}" \
    -H "Authorization: Basic $AUTH_B64" \
    -d "{
        \"tool_name\": \"weather-api\",
        \"tool_type\": \"api\",
        \"input\": {\"city\": \"San Francisco\", \"units\": \"metric\"},
        \"output\": {\"temperature\": 18, \"condition\": \"sunny\"},
        \"duration_ms\": 245,
        \"success\": true,
        \"policies_applied\": [\"data-residency\", \"rate-limit\"]
    }")

if [ "$TOOL_AUDIT_HTTP_CODE" = "404" ]; then
    echo -e "   ${YELLOW}Endpoint not available (requires Platform v5.1.0+)${NC}"
elif [ "$TOOL_AUDIT_HTTP_CODE" = "201" ] || [ "$TOOL_AUDIT_HTTP_CODE" = "200" ]; then
    TOOL_AUDIT_ID=$(jq -r '.audit_id // "none"' /tmp/tool_audit_response.json)
    TOOL_AUDIT_STATUS=$(jq -r '.status // "unknown"' /tmp/tool_audit_response.json)
    echo "   Audit ID: $TOOL_AUDIT_ID"
    echo "   Status: $TOOL_AUDIT_STATUS"
    echo -e "   ${GREEN}Tool call audit recorded successfully${NC}"
else
    echo -e "   ${RED}Unexpected HTTP $TOOL_AUDIT_HTTP_CODE${NC}"
    cat /tmp/tool_audit_response.json 2>/dev/null
fi
echo ""

# =========================================================================
# Query Audit Logs
# =========================================================================

echo -e "${CYAN}Query Audit Logs${NC}"
echo "========================================"
echo ""

# Get tenant audit logs
echo -e "${YELLOW}GET /api/v1/audit/tenant/$CLIENT_ID${NC}"
echo ""

AUDIT_LOGS=$(curl -s "${AUTH_HEADER[@]}" "$AGENT_URL/api/v1/audit/tenant/$CLIENT_ID" \
    -H "Authorization: Basic $AUTH_B64" \
)

LOG_COUNT=$(echo "$AUDIT_LOGS" | jq -r '
    if type == "array" then length
    elif has("entries") and (.entries | type) == "array" then (.entries | length)
    else 0
    end
')

echo "   Found $LOG_COUNT audit log entries"
echo ""

if [ "$LOG_COUNT" -gt 0 ]; then
    echo "   Latest entries:"
    echo "$AUDIT_LOGS" | jq -r '
        if type == "array" then .[:3]
        elif has("entries") and (.entries | type) == "array" then .entries[:3]
        else []
        end
        | .[]
        | "   - \(.timestamp // \"N/A\"): \(.provider // \"N/A\")/\(.model // \"N/A\") - \(.token_usage.total_tokens // 0) tokens"
    ' 2>/dev/null || echo "   (No entries to display)"
fi
echo ""

# Search audit logs
echo -e "${YELLOW}POST /api/v1/audit/search${NC}"
echo ""

SEARCH_RESPONSE=$(curl -s -X POST "$AGENT_URL/api/v1/audit/search" \
    -H "Content-Type: application/json" \
    "${AUTH_HEADER[@]}" \
    -H "Authorization: Basic $AUTH_B64" \
    -d "{
        \"client_id\": \"$CLIENT_ID\",
        \"limit\": 5
    }")

SEARCH_COUNT=$(echo "$SEARCH_RESPONSE" | jq -r '
    if type == "array" then length
    elif has("entries") and (.entries | type) == "array" then (.entries | length)
    else 0
    end
')
echo "   Search returned $SEARCH_COUNT entries"
echo ""

echo "========================================"
echo "Audit Logging Complete!"
echo ""
echo "API Endpoints Used:"
echo "  Agent (8080):"
echo "    POST /api/policy/pre-check      - Policy validation"
echo "    POST /api/audit/llm-call        - Audit logging"
echo "    POST /api/v1/audit/tool-call    - Tool call audit"
echo "    GET  /api/v1/audit/tenant/{id}  - Get tenant logs"
echo "    POST /api/v1/audit/search       - Search logs"
