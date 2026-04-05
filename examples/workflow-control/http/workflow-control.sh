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
CLIENT_ID="${AXONFLOW_CLIENT_ID:-community}"
CLIENT_SECRET="${AXONFLOW_CLIENT_SECRET:-}"
AUTH_B64=$(printf '%s:%s' "$CLIENT_ID" "$CLIENT_SECRET" | base64)

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
    -H "Authorization: Basic $AUTH_B64" \
    -d '{
        "workflow_name": "code-review-pipeline",
        "source": "external",
        "metadata": {
            "example": "workflow-control-http"
        },
        "trace_id": "example-trace-http-001"
    }')

WORKFLOW_ID=$(echo "$create_response" | jq -r '.workflow_id // ""')
if [ -z "$WORKFLOW_ID" ] || [ "$WORKFLOW_ID" = "null" ]; then
    echo -e "   ${RED}Failed to create workflow${NC}"
    echo "   Response: $create_response"
    exit 1
fi

echo -e "   ${GREEN}Workflow created!${NC}"
echo "   Workflow ID: $WORKFLOW_ID"

# Verify trace_id in create response
TRACE_ID=$(echo "$create_response" | jq -r '.trace_id // ""')
if [ "$TRACE_ID" = "example-trace-http-001" ]; then
    echo -e "   ${GREEN}trace_id returned in create response${NC}"
else
    echo -e "   ${RED}FAIL: expected trace_id 'example-trace-http-001', got '$TRACE_ID'${NC}"
fi
echo ""

# Step 2: Check gate for first step (Generate Code - LLM call)
echo -e "${BLUE}Step 2: Check Gate - Generate Code${NC}"
echo "   Checking if 'generate_code' step is allowed..."

gate_response=$(curl -s -X POST "$AGENT_URL/api/v1/workflows/$WORKFLOW_ID/steps/step-1/gate" \
    -H "Content-Type: application/json" \
    -H "Authorization: Basic $AUTH_B64" \
    -d '{
        "step_name": "Generate Code",
        "step_type": "llm_call",
        "model": "llama3.2",
        "provider": "ollama",
        "tokens_in": 200,
        "tokens_out": 450,
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
            -H "Authorization: Basic $AUTH_B64" \
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
        -H "Authorization: Basic $AUTH_B64" \
        -d '{
            "output": {
                "code": "def sort_list(items): return sorted(items)"
            },
            "tokens_in": 320,
            "tokens_out": 85,
            "cost_usd": 0.0048
        }' > /dev/null
    echo -e "   ${GREEN}Step completed!${NC}"
    echo ""
fi

# Step 3: Check gate for second step (Review Code - Tool call)
echo -e "${BLUE}Step 3: Check Gate - Review Code${NC}"
echo "   Checking if 'review_code' step is allowed..."

gate_response=$(curl -s -X POST "$AGENT_URL/api/v1/workflows/$WORKFLOW_ID/steps/step-2/gate" \
    -H "Content-Type: application/json" \
    -H "Authorization: Basic $AUTH_B64" \
    -d '{
        "step_name": "Review Code",
        "step_type": "tool_call",
        "tokens_in": 120,
        "tokens_out": 85,
        "step_input": {
            "tool": "code_reviewer",
            "code": "def sort_list(items): return sorted(items)"
        },
        "tool_context": {
            "tool_name": "code_reviewer",
            "tool_type": "function",
            "tool_input": {
                "code": "def sort_list(items): return sorted(items)"
            }
        }
    }')

decision=$(echo "$gate_response" | jq -r '.decision // "unknown"')
case "$decision" in
    "allow")
        echo -e "   Decision: ${GREEN}ALLOW${NC}"
        curl -s -X POST "$AGENT_URL/api/v1/workflows/$WORKFLOW_ID/steps/step-2/complete" \
            -H "Content-Type: application/json" \
            -H "Authorization: Basic $AUTH_B64" \
            -d '{"output": {"review": "LGTM"}, "tokens_in": 480, "tokens_out": 120, "cost_usd": 0.0071}' > /dev/null
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
    -H "Authorization: Basic $AUTH_B64" \
    -d '{
        "step_name": "Deploy to Production",
        "step_type": "connector_call",
        "tokens_in": 50,
        "tokens_out": 30,
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
            -H "Authorization: Basic $AUTH_B64" \
            -d '{"output": {"pr_url": "https://github.com/example/pr/123"}, "tokens_in": 95, "tokens_out": 30, "cost_usd": 0.0015}' > /dev/null
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
    -H "Authorization: Basic $AUTH_B64" \
 > /dev/null
echo -e "   ${GREEN}Workflow completed!${NC}"
echo ""

# Step 5b: Fail Workflow (test /fail endpoint)
echo -e "${BLUE}Step 5b: Fail Workflow${NC}"
echo "   Creating a workflow to test /fail endpoint..."

fail_create=$(curl -s -X POST "$AGENT_URL/api/v1/workflows" \
    -H "Content-Type: application/json" \
    -H "Authorization: Basic $AUTH_B64" \
    -d '{
        "workflow_name": "wcp-fail-test",
        "source": "external",
        "metadata": {
            "example": "fail-workflow-http"
        }
    }')

FAIL_WF_ID=$(echo "$fail_create" | jq -r '.workflow_id // ""')
if [ -z "$FAIL_WF_ID" ] || [ "$FAIL_WF_ID" = "null" ]; then
    echo -e "   ${RED}Failed to create fail-test workflow${NC}"
    echo "   Response: $fail_create"
else
    echo "   Workflow ID: $FAIL_WF_ID"

    # Call /fail endpoint
    fail_response=$(curl -s -X POST "$AGENT_URL/api/v1/workflows/$FAIL_WF_ID/fail" \
        -H "Content-Type: application/json" \
        -H "Authorization: Basic $AUTH_B64" \
        -d '{"reason": "LLM provider timeout"}')

    fail_status=$(echo "$fail_response" | jq -r '.status // "unknown"')
    fail_reason=$(echo "$fail_response" | jq -r '.reason // ""')
    echo -e "   ${GREEN}Workflow failed!${NC}"
    echo "   Status: $fail_status"
    echo "   Reason: $fail_reason"

    # Verify status via GET
    verify_response=$(curl -s "$AGENT_URL/api/v1/workflows/$FAIL_WF_ID" \
        -H "Authorization: Basic $AUTH_B64" \
)
    verify_status=$(echo "$verify_response" | jq -r '.status // "unknown"')
    if [ "$verify_status" = "failed" ]; then
        echo -e "   ${GREEN}Verified: workflow status is 'failed'${NC}"
    else
        echo -e "   ${RED}ERROR: expected 'failed', got '$verify_status'${NC}"
    fi
fi
echo ""

# Step 6: Get final workflow status
echo -e "${BLUE}Step 6: Workflow Status${NC}"
status_response=$(curl -s "$AGENT_URL/api/v1/workflows/$WORKFLOW_ID" \
    -H "Authorization: Basic $AUTH_B64" \
)

echo "   Workflow: $(echo "$status_response" | jq -r '.workflow_name')"
echo "   Status: $(echo "$status_response" | jq -r '.status')"
echo "   Steps: $(echo "$status_response" | jq -r '.steps | length')"

# Verify trace_id in status response
STATUS_TRACE_ID=$(echo "$status_response" | jq -r '.trace_id // ""')
if [ "$STATUS_TRACE_ID" = "example-trace-http-001" ]; then
    echo -e "   ${GREEN}trace_id returned in status response${NC}"
else
    echo -e "   ${RED}FAIL: expected trace_id 'example-trace-http-001', got '$STATUS_TRACE_ID'${NC}"
fi
echo ""

# -------------------------------------------------------
# Step Approval Tests (Enterprise Feature)
# These may return 403 in community mode — skip gracefully.
# -------------------------------------------------------

# Test 7: Step Approval Flow
echo -e "${BLUE}Step 7: Step Approval Flow${NC}"
echo "   Creating 'wcp-approval-test' workflow (3 steps)..."

approval_create=$(curl -s -w "\n%{http_code}" -X POST "$AGENT_URL/api/v1/workflows" \
    -H "Content-Type: application/json" \
    -H "Authorization: Basic $AUTH_B64" \
    -d '{
        "workflow_name": "wcp-approval-test",
        "source": "external",
        "metadata": {
            "example": "step-approval-http"
        }
    }')

approval_body=$(echo "$approval_create" | sed '$d')
approval_http=$(echo "$approval_create" | tail -n 1)

APPROVAL_WF_ID=$(echo "$approval_body" | jq -r '.workflow_id // ""')
if [ -z "$APPROVAL_WF_ID" ] || [ "$APPROVAL_WF_ID" = "null" ]; then
    echo -e "   ${RED}Failed to create approval test workflow${NC}"
    echo "   Response: $approval_body"
else
    echo -e "   ${GREEN}Workflow created!${NC}"
    echo "   Workflow ID: $APPROVAL_WF_ID"

    # Gate the first step
    echo "   Checking gate for step-1..."
    approval_gate=$(curl -s -X POST "$AGENT_URL/api/v1/workflows/$APPROVAL_WF_ID/steps/step-1/gate" \
        -H "Content-Type: application/json" \
        -H "Authorization: Basic $AUTH_B64" \
        -d '{
            "step_name": "Approval Target Step",
            "step_type": "llm_call",
            "model": "llama3.2",
            "provider": "ollama",
            "tokens_in": 180,
            "tokens_out": 290,
            "step_input": {
                "prompt": "Test step for approval"
            }
        }')

    gate_decision=$(echo "$approval_gate" | jq -r '.decision // "unknown"')
    echo "   Gate decision: $gate_decision"

    # Approve the step
    echo "   Approving step-1..."
    approve_response=$(curl -s -w "\n%{http_code}" -X POST \
        "$AGENT_URL/api/v1/workflows/$APPROVAL_WF_ID/steps/step-1/approve" \
        -H "Content-Type: application/json" \
        -H "Authorization: Basic $AUTH_B64" \
)

    approve_body=$(echo "$approve_response" | sed '$d')
    approve_http=$(echo "$approve_response" | tail -n 1)

    if [ "$approve_http" = "403" ] || [ "$approve_http" = "404" ] || echo "$approve_body" | jq -r '.error // ""' 2>/dev/null | grep -qi "enterprise\|license\|not available"; then
        echo -e "   ${YELLOW}SKIPPED: Step approval is an enterprise feature${NC}"
    else
        approve_status=$(echo "$approve_body" | jq -r '.status // "unknown"')
        echo -e "   ${GREEN}Approval status: $approve_status${NC}"
    fi

    # Check pending approvals
    echo "   Checking pending approvals..."
    pending_response=$(curl -s -w "\n%{http_code}" \
        "$AGENT_URL/api/v1/workflows/pending-approvals" \
        -H "Authorization: Basic $AUTH_B64" \
)

    pending_body=$(echo "$pending_response" | sed '$d')
    pending_http=$(echo "$pending_response" | tail -n 1)

    if [ "$pending_http" = "403" ] || [ "$pending_http" = "404" ] || echo "$pending_body" | jq -r '.error // ""' 2>/dev/null | grep -qi "enterprise\|license\|not available"; then
        echo -e "   ${YELLOW}SKIPPED: Pending approvals is an enterprise feature${NC}"
    else
        pending_count=$(echo "$pending_body" | jq -r '.items | length // 0')
        pending_total=$(echo "$pending_body" | jq -r '.total // 0')
        echo "   Pending approvals count: $pending_count"
        echo "   Total pending: $pending_total"
    fi
fi
echo ""

# Test 8: Step Rejection Flow
echo -e "${BLUE}Step 8: Step Rejection Flow${NC}"
echo "   Creating 'wcp-rejection-test' workflow (2 steps)..."

rejection_create=$(curl -s -w "\n%{http_code}" -X POST "$AGENT_URL/api/v1/workflows" \
    -H "Content-Type: application/json" \
    -H "Authorization: Basic $AUTH_B64" \
    -d '{
        "workflow_name": "wcp-rejection-test",
        "source": "external",
        "metadata": {
            "example": "step-rejection-http"
        }
    }')

rejection_body=$(echo "$rejection_create" | sed '$d')
rejection_http=$(echo "$rejection_create" | tail -n 1)

REJECTION_WF_ID=$(echo "$rejection_body" | jq -r '.workflow_id // ""')
if [ -z "$REJECTION_WF_ID" ] || [ "$REJECTION_WF_ID" = "null" ]; then
    echo -e "   ${RED}Failed to create rejection test workflow${NC}"
    echo "   Response: $rejection_body"
else
    echo -e "   ${GREEN}Workflow created!${NC}"
    echo "   Workflow ID: $REJECTION_WF_ID"

    # Gate the first step
    echo "   Checking gate for step-1..."
    rejection_gate=$(curl -s -X POST "$AGENT_URL/api/v1/workflows/$REJECTION_WF_ID/steps/step-1/gate" \
        -H "Content-Type: application/json" \
        -H "Authorization: Basic $AUTH_B64" \
        -d '{
            "step_name": "Rejection Target Step",
            "step_type": "tool_call",
            "tokens_in": 95,
            "tokens_out": 40,
            "step_input": {
                "tool": "risky_action",
                "action": "delete_all"
            },
            "tool_context": {
                "tool_name": "risky_action",
                "tool_type": "function",
                "tool_input": {
                    "action": "delete_all"
                }
            }
        }')

    gate_decision=$(echo "$rejection_gate" | jq -r '.decision // "unknown"')
    echo "   Gate decision: $gate_decision"

    # Reject the step
    echo "   Rejecting step-1..."
    reject_response=$(curl -s -w "\n%{http_code}" -X POST \
        "$AGENT_URL/api/v1/workflows/$REJECTION_WF_ID/steps/step-1/reject" \
        -H "Content-Type: application/json" \
        -H "Authorization: Basic $AUTH_B64" \
)

    reject_body=$(echo "$reject_response" | sed '$d')
    reject_http=$(echo "$reject_response" | tail -n 1)

    if [ "$reject_http" = "403" ] || [ "$reject_http" = "404" ] || echo "$reject_body" | jq -r '.error // ""' 2>/dev/null | grep -qi "enterprise\|license\|not available"; then
        echo -e "   ${YELLOW}SKIPPED: Step rejection is an enterprise feature${NC}"
    else
        reject_status=$(echo "$reject_body" | jq -r '.status // "unknown"')
        echo -e "   ${GREEN}Rejection status: $reject_status${NC}"
    fi
fi
echo ""

# Test 9: Get Pending Approvals (standalone)
echo -e "${BLUE}Step 9: Get Pending Approvals${NC}"
echo "   Fetching pending approvals list..."

all_pending_response=$(curl -s -w "\n%{http_code}" \
    "$AGENT_URL/api/v1/workflows/pending-approvals" \
    -H "Authorization: Basic $AUTH_B64" \
)

all_pending_body=$(echo "$all_pending_response" | sed '$d')
all_pending_http=$(echo "$all_pending_response" | tail -n 1)

if [ "$all_pending_http" = "403" ] || [ "$all_pending_http" = "404" ] || echo "$all_pending_body" | jq -r '.error // ""' 2>/dev/null | grep -qi "enterprise\|license\|not available"; then
    echo -e "   ${YELLOW}SKIPPED: Pending approvals is an enterprise feature${NC}"
else
    items_count=$(echo "$all_pending_body" | jq -r '.items | length // 0')
    total_count=$(echo "$all_pending_body" | jq -r '.total // 0')
    echo "   Items count: $items_count"
    echo "   Total: $total_count"
fi
echo ""

# Step 10: SSE Streaming - Real-time execution status
echo -e "${BLUE}Step 10: SSE Streaming - Real-time execution status${NC}"
echo "   Creating workflow for SSE streaming test..."

sse_create=$(curl -s -X POST "$AGENT_URL/api/v1/workflows" \
    -H "Content-Type: application/json" \
    -H "Authorization: Basic $AUTH_B64" \
    -d '{
        "workflow_name": "wcp-sse-streaming-test",
        "source": "external",
        "metadata": {
            "example": "sse-streaming-http"
        }
    }')

SSE_WF_ID=$(echo "$sse_create" | jq -r '.workflow_id // ""')
if [ -z "$SSE_WF_ID" ] || [ "$SSE_WF_ID" = "null" ]; then
    echo -e "   ${RED}Failed to create SSE test workflow${NC}"
    echo "   Response: $sse_create"
else
    echo -e "   ${GREEN}Workflow created!${NC}"
    echo "   Workflow ID: $SSE_WF_ID"

    # Run a step gate and complete a step to generate execution events
    echo "   Checking gate for sse-step-1..."
    sse_gate=$(curl -s -X POST "$AGENT_URL/api/v1/workflows/$SSE_WF_ID/steps/sse-step-1/gate" \
        -H "Content-Type: application/json" \
        -H "Authorization: Basic $AUTH_B64" \
        -d '{
            "step_name": "SSE Test Step",
            "step_type": "llm_call",
            "model": "llama3.2",
            "provider": "ollama",
            "tokens_in": 65,
            "tokens_out": 110,
            "step_input": {
                "prompt": "test SSE streaming"
            }
        }')

    sse_decision=$(echo "$sse_gate" | jq -r '.decision // "unknown"')
    echo "   Gate decision: $sse_decision"

    if [ "$sse_decision" = "allow" ]; then
        curl -s -X POST "$AGENT_URL/api/v1/workflows/$SSE_WF_ID/steps/sse-step-1/complete" \
            -H "Content-Type: application/json" \
            -H "Authorization: Basic $AUTH_B64" \
            -d '{"output": {"result": "sse test output"}, "tokens_in": 200, "tokens_out": 60, "cost_usd": 0.0031}' > /dev/null
        echo -e "   ${GREEN}Step completed!${NC}"
    fi

    # Verify SSE execution streaming endpoint is available
    SSE_URL="$AGENT_URL/api/v1/unified/executions/$SSE_WF_ID/stream"
    echo "   SSE URL: $SSE_URL"
    echo "   Verifying SSE endpoint is registered..."

    # Use --max-time 3 for SSE (streaming endpoint never closes).
    # Curl exits with code 28 (timeout) even after a successful 200 response.
    # The || true prevents set -e from killing the script.
    SSE_HTTP_CODE=$(curl -s -o /tmp/sse_body.txt -w "%{http_code}" --max-time 3 \
      -H "Authorization: Basic $AUTH_B64" \

      -H "Accept: text/event-stream" \
      "$SSE_URL" 2>/dev/null || true)
    SSE_HTTP_CODE=${SSE_HTTP_CODE:-000}
    SSE_BODY=$(cat /tmp/sse_body.txt 2>/dev/null || echo "")

    if [ "$SSE_HTTP_CODE" = "200" ]; then
        echo -e "   ${GREEN}SSE endpoint available (HTTP 200 — active stream)${NC}"
    elif [ "$SSE_HTTP_CODE" = "404" ]; then
        HAS_NOT_FOUND=$(echo "$SSE_BODY" | grep -c '"NOT_FOUND"' 2>/dev/null || echo "0")
        if [ "$HAS_NOT_FOUND" -ge 1 ]; then
            echo -e "   ${GREEN}SSE endpoint available (JSON 404 NOT_FOUND — execution already completed)${NC}"
            echo "   Note: Connect during active execution for real-time SSE events"
        else
            echo -e "   ${RED}SSE endpoint returned plain text 404 (handler not registered)${NC}"
            echo "   Body: $SSE_BODY"
        fi
    else
        echo -e "   ${YELLOW}SSE endpoint returned HTTP $SSE_HTTP_CODE${NC}"
        echo "   Body: $SSE_BODY"
    fi
    echo "   Tip: For real-time SSE events, connect DURING workflow execution:"
    echo "     curl -N -H 'Accept: text/event-stream' $SSE_URL"

    # Cleanup SSE workflow
    curl -s -X POST "$AGENT_URL/api/v1/workflows/$SSE_WF_ID/abort" \
        -H "Content-Type: application/json" \
        -H "Authorization: Basic $AUTH_B64" \
        -d '{"reason": "test cleanup"}' > /dev/null 2>&1 || true
fi
echo ""

echo "========================================"
echo -e "${GREEN}Workflow Control Plane Example Complete!${NC}"
echo ""
echo "Key concepts demonstrated:"
echo "  1. Create workflow (register with AxonFlow)"
echo "  2. Check step gates (policy evaluation)"
echo "  3. Mark steps completed (progress tracking)"
echo "  4. Complete workflow (lifecycle management)"
echo "  5. Approve steps (enterprise approval flow)"
echo "  6. Reject steps (enterprise rejection flow)"
echo "  7. List pending approvals (enterprise)"
echo " 10. SSE Streaming (real-time execution status)"
echo ""
echo "Next steps:"
echo "  - Try with SDK: go/, python/, typescript/, java/"
echo "  - LangGraph adapter: python/langgraph_example.py"
