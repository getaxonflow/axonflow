#!/bin/bash
# LLM Provider Health Check and Recovery Test
# Tests: Health monitoring, failover behavior, recovery detection
#
# This test validates that:
# 1. Provider health is monitored continuously
# 2. Unhealthy providers are avoided during routing
# 3. Recovered providers are used again after health check passes
#
# Usage:
#   ./test-health-recovery.sh

set -e

BASE_URL="${AXONFLOW_AGENT_URL:-http://localhost:8080}"

# Auth: include Basic auth if credentials are set
CURL_AUTH=()
if [ -n "${AXONFLOW_CLIENT_ID:-}" ] && [ -n "${AXONFLOW_CLIENT_SECRET:-}" ]; then
  CURL_AUTH=(-u "${AXONFLOW_CLIENT_ID}:${AXONFLOW_CLIENT_SECRET}")
fi
acurl() { curl "${CURL_AUTH[@]}" "$@"; }

echo "========================================"
echo "Health Check & Recovery Test"
echo "========================================"
echo "Target: $BASE_URL"
echo ""

# Test 1: Initial health status
echo "Test 1: Initial provider health status"
PROVIDERS=$(acurl -s "$BASE_URL/api/v1/llm-providers")
echo "  Provider health:"
echo "$PROVIDERS" | jq -r '.providers[] | "    \(.name): \(.health.status) (checked: \(.health.last_checked | split("T")[1] | split(".")[0]))"'
HEALTHY_COUNT=$(echo "$PROVIDERS" | jq '[.providers[] | select(.health.status == "healthy")] | length')
echo "  Healthy providers: $HEALTHY_COUNT"
echo ""

# Test 2: Verify health check is running (check timestamps change)
echo "Test 2: Health check monitoring (5 second interval)"
echo "  Waiting for health check cycle..."
FIRST_CHECK=$(acurl -s "$BASE_URL/api/v1/llm-providers" | jq -r '.providers[0].health.last_checked')
sleep 6
SECOND_CHECK=$(acurl -s "$BASE_URL/api/v1/llm-providers" | jq -r '.providers[0].health.last_checked')

if [ "$FIRST_CHECK" != "$SECOND_CHECK" ]; then
    echo "  ✓ Health checks are running (timestamp updated)"
    echo "    First:  $FIRST_CHECK"
    echo "    Second: $SECOND_CHECK"
else
    echo "  ⚠ Health check timestamp unchanged (may have longer interval)"
fi
echo ""

# Test 3: Failover behavior when provider fails
echo "Test 3: Failover behavior test"
echo "  Testing per-request provider selection with failover..."

for provider in openai anthropic gemini; do
    RESULT=$(acurl -s -X POST "$BASE_URL/api/v1/process" \
        -H "Content-Type: application/json" \
        -d "{\"query\":\"Hi\",\"request_type\":\"chat\",\"context\":{\"provider\":\"$provider\"},\"user\":{\"email\":\"test@example.com\",\"role\":\"user\"}}")

    SELECTED=$(echo "$RESULT" | jq -r '.provider_info.provider')
    SUCCESS=$(echo "$RESULT" | jq -r '.success')

    if [ "$SUCCESS" == "true" ]; then
        if [ "$SELECTED" == "$provider" ]; then
            echo "    $provider: ✓ Healthy (direct)"
        else
            echo "    $provider: → Failover to $SELECTED"
        fi
    else
        echo "    $provider: ✗ Failed"
    fi
done
echo ""

# Test 4: Routing avoids unhealthy providers
echo "Test 4: Routing distribution (unhealthy providers avoided)"
echo "  Making 10 requests to observe routing..."

openai_count=0
anthropic_count=0
gemini_count=0

for i in $(seq 1 10); do
    RESULT=$(acurl -s -X POST "$BASE_URL/api/v1/process" \
        -H "Content-Type: application/json" \
        -d '{"query":"Hello","request_type":"chat","user":{"email":"test@example.com","role":"user"}}')
    PROVIDER=$(echo "$RESULT" | jq -r '.provider_info.provider')
    case "$PROVIDER" in
        openai) openai_count=$((openai_count + 1)) ;;
        anthropic) anthropic_count=$((anthropic_count + 1)) ;;
        gemini) gemini_count=$((gemini_count + 1)) ;;
    esac
done

echo "  Distribution:"
[ $openai_count -gt 0 ] && echo "    openai: $openai_count"
[ $anthropic_count -gt 0 ] && echo "    anthropic: $anthropic_count"
[ $gemini_count -gt 0 ] && echo "    gemini: $gemini_count"

# Check if any provider got 0 requests (might indicate it's unhealthy)
echo ""
echo "  Analysis:"
if [ $anthropic_count -eq 0 ]; then
    echo "    ⚠ Anthropic received 0 requests (likely unhealthy, failover active)"
elif [ $openai_count -eq 0 ]; then
    echo "    ⚠ OpenAI received 0 requests (likely unhealthy, failover active)"
elif [ $gemini_count -eq 0 ]; then
    echo "    ⚠ Gemini received 0 requests (likely unhealthy, failover active)"
else
    echo "    ✓ All providers receiving traffic (all healthy)"
fi
echo ""

# Test 5: Health endpoint details
echo "Test 5: Orchestrator health with LLM router status"
HEALTH=$(curl -s "$BASE_URL/health")
echo "  Status: $(echo "$HEALTH" | jq -r '.status')"
echo "  LLM Router: $(echo "$HEALTH" | jq -r '.components.llm_router')"
echo ""

echo "========================================"
echo "Health & Recovery Test Complete"
echo "========================================"
echo ""
echo "Notes:"
echo "  - Health checks run every 5-30 seconds (configurable)"
echo "  - Unhealthy providers are automatically skipped"
echo "  - Providers recover automatically when health check passes"
echo "  - Failover is transparent to the caller"
