#!/bin/bash
# Workflow Control Plane - HTTP/curl Example
#
# Demonstrates the Workflow Control Plane using raw HTTP requests.
# "LangChain runs the workflow. AxonFlow decides when it's allowed to move forward."
#
# Prerequisites:
#   - AxonFlow Agent running at http://localhost:8080
#   - curl and jq installed
#
# Usage:
#   chmod +x workflow-control.sh
#   ./workflow-control.sh

set -e

AGENT_URL="${AXONFLOW_AGENT_URL:-http://localhost:8080}"
CLIENT_ID="${AXONFLOW_CLIENT_ID:-workflow-control-example}"
CLIENT_SECRET="${AXONFLOW_CLIENT_SECRET:-}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo "Workflow Control Plane - HTTP/curl"
echo "========================================"
echo ""
echo "Agent URL: $AGENT_URL"
echo ""

# Health check
echo -e "${YELLOW}Health Check${NC}"
health=$(curl -s "$AGENT_URL/health")
status=$(echo "$health" | jq -r '.status // "unknown"')
if [ "$status" = "healthy" ]; then
    echo -e "   Status: ${GREEN}$status${NC}"
else
    echo -e "   Status: ${RED}$status${NC}"
    echo "   AxonFlow Agent is not running. Start it with: docker compose up -d"
    exit 1
fi
echo ""

# Step 1: Create a workflow
echo -e "${BLUE}Step 1: Create Workflow${NC}"
echo "   Creating 'code-review-pipeline' workflow..."

create_response=$(curl -s -X POST "$AGENT_URL/api/v1/workflows" \
    -H "Content-Type: application/json" \
    -H "X-Client-ID: $CLIENT_ID" \
    -H "X-Client-Secret: $CLIENT_SECRET" \
    -d '{
        "workflow_name": "code-review-pipeline",
        "source": "external",
        "total_steps": 3,
        "metadata": {
            "example": "workflow-control-http"
        }
    }')

WORKFLOW_ID=$(echo "$create_response" | jq -r '.workflow_id // ""')
if [ -z "$WORKFLOW_ID" ] || [ "$WORKFLOW_ID" = "null" ]; then
    echo -e "   ${RED}Failed to create workflow${NC}"
    echo "   Response: $create_response"
    exit 1
fi

echo -e "   ${GREEN}Workflow created!${NC}"
echo "   Workflow ID: $WORKFLOW_ID"
echo ""

# Step 2: Check gate for first step (Generate Code - LLM call)
echo -e "${BLUE}Step 2: Check Gate - Generate Code${NC}"
echo "   Checking if 'generate_code' step is allowed..."

gate_response=$(curl -s -X POST "$AGENT_URL/api/v1/workflows/$WORKFLOW_ID/steps/step-1/gate" \
    -H "Content-Type: application/json" \
    -H "X-Client-ID: $CLIENT_ID" \
    -H "X-Client-Secret: $CLIENT_SECRET" \
    -d '{
        "step_name": "Generate Code",
        "step_type": "llm_call",
        "model": "gpt-4",
        "provider": "openai",
        "step_input": {
            "prompt": "Write a Python function to sort a list"
        }
    }')

decision=$(echo "$gate_response" | jq -r '.decision // "unknown"')
reason=$(echo "$gate_response" | jq -r '.reason // ""')
step_id=$(echo "$gate_response" | jq -r '.step_id // ""')

case "$decision" in
    "allow")
        echo -e "   Decision: ${GREEN}ALLOW${NC}"
        echo "   Step ID: $step_id"
        ;;
    "block")
        echo -e "   Decision: ${RED}BLOCK${NC}"
        echo "   Reason: $reason"
        echo ""
        echo "   Aborting workflow..."
        curl -s -X POST "$AGENT_URL/api/v1/workflows/$WORKFLOW_ID/abort" \
            -H "Content-Type: application/json" \
            -H "X-Client-ID: $CLIENT_ID" \
            -H "X-Client-Secret: $CLIENT_SECRET" \
            -d '{"reason": "Step blocked by policy"}'
        exit 0
        ;;
    "require_approval")
        echo -e "   Decision: ${YELLOW}REQUIRE APPROVAL${NC}"
        approval_url=$(echo "$gate_response" | jq -r '.approval_url // ""')
        echo "   Approval URL: $approval_url"
        echo "   (Enterprise feature - approval workflow would be triggered)"
        ;;
    *)
        echo -e "   Decision: ${RED}UNKNOWN ($decision)${NC}"
        echo "   Response: $gate_response"
        ;;
esac
echo ""

# Mark step 1 completed
if [ "$decision" = "allow" ]; then
    echo "   Marking step completed..."
    curl -s -X POST "$AGENT_URL/api/v1/workflows/$WORKFLOW_ID/steps/step-1/complete" \
        -H "Content-Type: application/json" \
        -H "X-Client-ID: $CLIENT_ID" \
        -H "X-Client-Secret: $CLIENT_SECRET" \
        -d '{
            "output": {
                "code": "def sort_list(items): return sorted(items)"
            }
        }' > /dev/null
    echo -e "   ${GREEN}Step completed!${NC}"
    echo ""
fi

# Step 3: Check gate for second step (Review Code - Tool call)
echo -e "${BLUE}Step 3: Check Gate - Review Code${NC}"
echo "   Checking if 'review_code' step is allowed..."

gate_response=$(curl -s -X POST "$AGENT_URL/api/v1/workflows/$WORKFLOW_ID/steps/step-2/gate" \
    -H "Content-Type: application/json" \
    -H "X-Client-ID: $CLIENT_ID" \
    -H "X-Client-Secret: $CLIENT_SECRET" \
    -d '{
        "step_name": "Review Code",
        "step_type": "tool_call",
        "step_input": {
            "tool": "code_reviewer",
            "code": "def sort_list(items): return sorted(items)"
        }
    }')

decision=$(echo "$gate_response" | jq -r '.decision // "unknown"')
case "$decision" in
    "allow")
        echo -e "   Decision: ${GREEN}ALLOW${NC}"
        curl -s -X POST "$AGENT_URL/api/v1/workflows/$WORKFLOW_ID/steps/step-2/complete" \
            -H "Content-Type: application/json" \
            -H "X-Client-ID: $CLIENT_ID" \
            -d '{"output": {"review": "LGTM"}}' > /dev/null
        echo -e "   ${GREEN}Step completed!${NC}"
        ;;
    "block")
        echo -e "   Decision: ${RED}BLOCK${NC}"
        echo "   Reason: $(echo "$gate_response" | jq -r '.reason')"
        ;;
    *)
        echo -e "   Decision: ${YELLOW}$decision${NC}"
        ;;
esac
echo ""

# Step 4: Check gate for third step (Deploy - Connector call)
echo -e "${BLUE}Step 4: Check Gate - Deploy${NC}"
echo "   Checking if 'deploy' step is allowed..."

gate_response=$(curl -s -X POST "$AGENT_URL/api/v1/workflows/$WORKFLOW_ID/steps/step-3/gate" \
    -H "Content-Type: application/json" \
    -H "X-Client-ID: $CLIENT_ID" \
    -H "X-Client-Secret: $CLIENT_SECRET" \
    -d '{
        "step_name": "Deploy to Production",
        "step_type": "connector_call",
        "step_input": {
            "connector": "github",
            "action": "create_pr"
        }
    }')

decision=$(echo "$gate_response" | jq -r '.decision // "unknown"')
case "$decision" in
    "allow")
        echo -e "   Decision: ${GREEN}ALLOW${NC}"
        curl -s -X POST "$AGENT_URL/api/v1/workflows/$WORKFLOW_ID/steps/step-3/complete" \
            -H "Content-Type: application/json" \
            -H "X-Client-ID: $CLIENT_ID" \
            -d '{"output": {"pr_url": "https://github.com/example/pr/123"}}' > /dev/null
        echo -e "   ${GREEN}Step completed!${NC}"
        ;;
    "block")
        echo -e "   Decision: ${RED}BLOCK${NC}"
        echo "   Reason: $(echo "$gate_response" | jq -r '.reason')"
        ;;
    *)
        echo -e "   Decision: ${YELLOW}$decision${NC}"
        ;;
esac
echo ""

# Step 5: Complete the workflow
echo -e "${BLUE}Step 5: Complete Workflow${NC}"
curl -s -X POST "$AGENT_URL/api/v1/workflows/$WORKFLOW_ID/complete" \
    -H "Content-Type: application/json" \
    -H "X-Client-ID: $CLIENT_ID" \
    -H "X-Client-Secret: $CLIENT_SECRET" > /dev/null
echo -e "   ${GREEN}Workflow completed!${NC}"
echo ""

# Step 6: Get final workflow status
echo -e "${BLUE}Step 6: Workflow Status${NC}"
status_response=$(curl -s "$AGENT_URL/api/v1/workflows/$WORKFLOW_ID" \
    -H "X-Client-ID: $CLIENT_ID" \
    -H "X-Client-Secret: $CLIENT_SECRET")

echo "   Workflow: $(echo "$status_response" | jq -r '.workflow_name')"
echo "   Status: $(echo "$status_response" | jq -r '.status')"
echo "   Steps: $(echo "$status_response" | jq -r '.steps | length')"
echo ""

echo "========================================"
echo -e "${GREEN}Workflow Control Plane Example Complete!${NC}"
echo ""
echo "Key concepts demonstrated:"
echo "  1. Create workflow (register with AxonFlow)"
echo "  2. Check step gates (policy evaluation)"
echo "  3. Mark steps completed (progress tracking)"
echo "  4. Complete workflow (lifecycle management)"
echo ""
echo "Next steps:"
echo "  - Try with SDK: go/, python/, typescript/, java/"
echo "  - LangGraph adapter: python/langgraph_example.py"
