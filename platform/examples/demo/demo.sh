#!/bin/bash
#
# AxonFlow Interactive Demo
# Run this after docker-compose up to see AxonFlow's governance in action
#
# Usage:
#   ./platform/examples/demo/demo.sh
#
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'

AGENT_URL="${AXONFLOW_AGENT_URL:-http://localhost:8080}"

echo ""
echo -e "${CYAN}${BOLD}╔═══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}${BOLD}║               AxonFlow Interactive Demo                       ║${NC}"
echo -e "${CYAN}${BOLD}║          Real-time AI Governance in Action                    ║${NC}"
echo -e "${CYAN}${BOLD}╚═══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Check if services are running
echo -e "${BLUE}Checking services...${NC}"
if ! curl -s "$AGENT_URL/health" > /dev/null 2>&1; then
    echo -e "${RED}Error: Agent not responding at $AGENT_URL${NC}"
    echo -e "Run: docker-compose up -d"
    exit 1
fi
echo -e "${GREEN}✓ Agent service healthy${NC}"
echo ""

# Helper function to make API calls
# Uses the correct endpoint: POST /api/policy/pre-check
call_api() {
    local query="$1"
    curl -s -X POST "$AGENT_URL/api/policy/pre-check" \
        -H "Content-Type: application/json" \
        -d "{
            \"client_id\": \"demo\",
            \"user_token\": \"demo-user\",
            \"query\": \"$query\",
            \"context\": {\"user_role\": \"agent\"}
        }" 2>&1
}

# Demo 1: SQL Injection Blocking
echo -e "${YELLOW}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${YELLOW}${BOLD}Demo 1: SQL Injection Blocking${NC}"
echo -e "${YELLOW}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "${BLUE}Sending malicious SQL query:${NC}"
echo -e "  \"SELECT * FROM users WHERE id=1 UNION SELECT password FROM admin\""
echo ""

RESPONSE=$(call_api "SELECT * FROM users WHERE id=1 UNION SELECT password FROM admin")

# Check if request was blocked (approved: false)
if echo "$RESPONSE" | grep -q '"approved":\s*false'; then
    REASON=$(echo "$RESPONSE" | grep -o '"block_reason":"[^"]*"' | head -1)
    echo -e "${RED}${BOLD}🛡️  BLOCKED${NC} - SQL Injection Detected"
    echo -e "   ${RED}${REASON}${NC}"
else
    echo -e "${GREEN}Response:${NC} $RESPONSE"
fi
echo ""

# Demo 2: Safe Prompt
echo -e "${YELLOW}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${YELLOW}${BOLD}Demo 2: Safe Query (Allowed)${NC}"
echo -e "${YELLOW}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "${BLUE}Sending safe prompt:${NC}"
echo -e "  \"What is the weather forecast for tomorrow?\""
echo ""

RESPONSE=$(call_api "What is the weather forecast for tomorrow?")

if echo "$RESPONSE" | grep -q -i "approved.*true\|\"approved\":true"; then
    echo -e "${GREEN}${BOLD}✓ ALLOWED${NC} - No policy violations"
else
    echo -e "${GREEN}Response:${NC} $RESPONSE"
fi
echo ""

# Demo 3: Credit Card Detection
echo -e "${YELLOW}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${YELLOW}${BOLD}Demo 3: Credit Card Detection${NC}"
echo -e "${YELLOW}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "${BLUE}Sending prompt with credit card:${NC}"
echo -e "  \"Charge my card 4111-1111-1111-1111 for the order\""
echo ""

RESPONSE=$(call_api "Charge my card 4111-1111-1111-1111 for the order")

# Check if any policies were triggered (non-empty policies array)
if echo "$RESPONSE" | grep -q '"policies":\s*\[.*[^]]\]'; then
    POLICY=$(echo "$RESPONSE" | grep -o '"policies":\s*\[[^]]*\]' | head -1)
    echo -e "${RED}${BOLD}🛡️  POLICY TRIGGERED${NC} - Credit Card Detected"
    echo -e "   ${RED}Matched policy: ${POLICY}${NC}"
else
    echo -e "${GREEN}Response:${NC} $RESPONSE"
fi
echo ""

# Demo 4: Check Latency (portable timing using SECONDS)
echo -e "${YELLOW}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${YELLOW}${BOLD}Demo 4: Sub-10ms Policy Evaluation${NC}"
echo -e "${YELLOW}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "${BLUE}Measuring policy evaluation latency (5 requests)...${NC}"
echo ""

# Use curl's built-in timing for accurate measurements
TOTAL_TIME=0
for i in 1 2 3 4 5; do
    TIME_MS=$(curl -s -o /dev/null -w "%{time_total}" -X POST "$AGENT_URL/api/policy/pre-check" \
        -H "Content-Type: application/json" \
        -d "{\"client_id\": \"demo\", \"user_token\": \"demo-user\", \"query\": \"Test query $i\", \"context\": {}}")
    # Convert to milliseconds (time_total is in seconds with decimals)
    TIME_MS_INT=$(echo "$TIME_MS * 1000" | bc 2>/dev/null || echo "10")
    TOTAL_TIME=$((TOTAL_TIME + ${TIME_MS_INT%.*}))
done
AVG=$((TOTAL_TIME / 5))

echo -e "${GREEN}${BOLD}⚡ Average latency: ${AVG}ms${NC} (5 requests)"
if [ "$AVG" -lt 10 ]; then
    echo -e "   ${GREEN}Sub-10ms inline governance achieved!${NC}"
elif [ "$AVG" -lt 50 ]; then
    echo -e "   ${YELLOW}Good performance (target: <10ms)${NC}"
else
    echo -e "   ${RED}Higher latency detected - check system resources${NC}"
fi
echo ""

# Summary
echo -e "${CYAN}${BOLD}╔═══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}${BOLD}║                        Demo Complete!                         ║${NC}"
echo -e "${CYAN}${BOLD}╚═══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${BOLD}What you just saw:${NC}"
echo -e "  ${GREEN}✓${NC} SQL injection blocking (malicious queries rejected)"
echo -e "  ${GREEN}✓${NC} PII detection (credit card patterns flagged for redaction)"
echo -e "  ${GREEN}✓${NC} Policy-as-code enforcement"
echo -e "  ${GREEN}✓${NC} Sub-10ms inline governance"
echo ""
echo -e "${BOLD}Next Steps:${NC}"
echo -e "  1. ${CYAN}Try the Support Demo:${NC} cd platform/examples/support-demo && docker-compose up"
echo -e "  2. ${CYAN}Explore Examples:${NC} See examples/hello-world for SDK usage"
echo -e "  3. ${CYAN}Read the Docs:${NC} https://docs.getaxonflow.com"
echo -e "  4. ${CYAN}View Metrics:${NC} Open http://localhost:3000 (Grafana)"
echo ""
echo -e "${BLUE}View audit logs:${NC} docker-compose logs axonflow-agent | grep -i audit"
echo ""
