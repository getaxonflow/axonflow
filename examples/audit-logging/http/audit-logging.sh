#!/bin/bash
# AxonFlow Audit Logging - HTTP/curl
#
# Demonstrates the complete Gateway Mode workflow and audit log querying
# using raw HTTP requests.

set -e

AGENT_URL="${AXONFLOW_AGENT_URL:-http://localhost:8080}"
ORCHESTRATOR_URL="${AXONFLOW_ORCHESTRATOR_URL:-http://localhost:8081}"
LICENSE_KEY="${AXONFLOW_LICENSE_KEY:-}"
CLIENT_ID="audit-logging-demo"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo "AxonFlow Audit Logging - HTTP/curl"
echo "========================================"
echo ""
echo "Agent URL: $AGENT_URL"
echo "Orchestrator URL: $ORCHESTRATOR_URL"
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
PRECHECK_START=$(date +%s%3N)

PRECHECK_RESPONSE=$(curl -s -X POST "$AGENT_URL/api/policy/pre-check" \
    -H "Content-Type: application/json" \
    -H "X-License-Key: $LICENSE_KEY" \
    -d "{
        \"query\": \"$QUERY\",
        \"user_token\": \"audit-user\",
        \"client_id\": \"$CLIENT_ID\"
    }")

PRECHECK_END=$(date +%s%3N)
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
LLM_START=$(date +%s%3N)

# Simulate LLM latency
sleep 0.1

LLM_END=$(date +%s%3N)
LLM_LATENCY=$((LLM_END - LLM_START))
PROMPT_TOKENS=50
COMPLETION_TOKENS=100
TOTAL_TOKENS=150

echo "   Latency: ${LLM_LATENCY}ms"
echo "   Tokens: $PROMPT_TOKENS prompt, $COMPLETION_TOKENS completion"
echo ""

# Step 3: Audit
echo -e "${YELLOW}Step 3: Audit Logging...${NC}"
AUDIT_START=$(date +%s%3N)

AUDIT_RESPONSE=$(curl -s -X POST "$AGENT_URL/api/audit/llm-call" \
    -H "Content-Type: application/json" \
    -H "X-License-Key: $LICENSE_KEY" \
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

AUDIT_END=$(date +%s%3N)
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
# Query Audit Logs
# =========================================================================

echo -e "${CYAN}Query Audit Logs${NC}"
echo "========================================"
echo ""

# Get tenant audit logs
echo -e "${YELLOW}GET /api/v1/audit/tenant/$CLIENT_ID${NC}"
echo ""

AUDIT_LOGS=$(curl -s "$ORCHESTRATOR_URL/api/v1/audit/tenant/$CLIENT_ID" \
    -H "X-License-Key: $LICENSE_KEY")

LOG_COUNT=$(echo "$AUDIT_LOGS" | jq -r 'if type == "array" then length else 0 end')

echo "   Found $LOG_COUNT audit log entries"
echo ""

if [ "$LOG_COUNT" -gt 0 ]; then
    echo "   Latest entries:"
    echo "$AUDIT_LOGS" | jq -r '.[:3][] | "   - \(.timestamp // "N/A"): \(.provider // "N/A")/\(.model // "N/A") - \(.token_usage.total_tokens // 0) tokens"' 2>/dev/null || echo "   (No entries to display)"
fi
echo ""

# Search audit logs
echo -e "${YELLOW}POST /api/v1/audit/search${NC}"
echo ""

SEARCH_RESPONSE=$(curl -s -X POST "$ORCHESTRATOR_URL/api/v1/audit/search" \
    -H "Content-Type: application/json" \
    -H "X-License-Key: $LICENSE_KEY" \
    -d "{
        \"client_id\": \"$CLIENT_ID\",
        \"limit\": 5
    }")

SEARCH_COUNT=$(echo "$SEARCH_RESPONSE" | jq -r 'if type == "array" then length else 0 end')
echo "   Search returned $SEARCH_COUNT entries"
echo ""

echo "========================================"
echo "Audit Logging Complete!"
echo ""
echo "API Endpoints Used:"
echo "  Agent (8080):"
echo "    POST /api/policy/pre-check - Policy validation"
echo "    POST /api/audit/llm-call   - Audit logging"
echo "  Orchestrator (8081):"
echo "    GET  /api/v1/audit/tenant/{id} - Get tenant logs"
echo "    POST /api/v1/audit/search      - Search logs"
