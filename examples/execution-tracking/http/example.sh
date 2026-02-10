#!/bin/bash
# AxonFlow Unified Execution Tracking Example - HTTP/cURL
#
# This example demonstrates execution tracking for both MAP plans and WCP workflows,
# including cancellation and SSE streaming.
#
# Issue #1075 - EPIC #1074: Unified Workflow Infrastructure

set -e

ORCHESTRATOR_URL="${AXONFLOW_ORCHESTRATOR_URL:-http://localhost:8081}"
AGENT_URL="${AXONFLOW_AGENT_URL:-http://localhost:8080}"
CLIENT_ID="${AXONFLOW_CLIENT_ID:-demo-org}"
CLIENT_SECRET="${AXONFLOW_CLIENT_SECRET:-demo}"

# Build Basic auth header
AUTH_HEADER="Authorization: Basic $(echo -n "${CLIENT_ID}:${CLIENT_SECRET}" | base64)"

echo "AxonFlow Unified Execution Tracking Example - HTTP/cURL"
echo "========================================================"
echo ""
echo "Agent URL: $AGENT_URL"
echo "Orchestrator URL: $ORCHESTRATOR_URL"
echo ""

# =============================================
# Part 1: MAP Plan Execution
# =============================================
echo -e "\033[1;34m=== Part 1: MAP Plan Execution ===\033[0m"
echo ""

echo "Creating MAP plan via /api/request..."
PLAN_RESPONSE=$(curl -s -X POST "${AGENT_URL}/api/request" \
  -H "Content-Type: application/json" \
  -H "$AUTH_HEADER" \
  -d "{
    \"query\": \"Create a greeting message for a new user\",
    \"user_token\": \"${CLIENT_ID}\",
    \"client_id\": \"${CLIENT_ID}\",
    \"request_type\": \"multi-agent-plan\",
    \"context\": {\"domain\": \"generic\"}
  }")

# Check for success
SUCCESS=$(echo "$PLAN_RESPONSE" | jq -r '.success // false')
if [ "$SUCCESS" != "true" ]; then
  echo "Error: Failed to create MAP plan"
  echo "$PLAN_RESPONSE" | jq .
  exit 1
fi

PLAN_ID=$(echo "$PLAN_RESPONSE" | jq -r '.plan_id // .data.plan_id // empty')
echo -e "   \033[0;32mMAP Plan created!\033[0m"
echo "   Plan ID: $PLAN_ID"
echo ""

# =============================================
# Part 2: WCP Workflow Execution (Full Tracking)
# =============================================
echo -e "\033[1;34m=== Part 2: WCP Workflow Execution ===\033[0m"
echo ""

# Step 1: Create workflow
echo "Creating WCP workflow..."
WF_RESPONSE=$(curl -s -X POST "${ORCHESTRATOR_URL}/api/v1/workflows" \
  -H "Content-Type: application/json" \
  -H "$AUTH_HEADER" \
  -d '{
    "workflow_name": "execution-tracking-demo",
    "source": "external",
    "total_steps": 3,
    "metadata": {"example": "http-execution-tracking"}
  }')

WORKFLOW_ID=$(echo "$WF_RESPONSE" | jq -r '.workflow_id // empty')
if [ -z "$WORKFLOW_ID" ]; then
  echo "Error: Failed to create workflow"
  echo "$WF_RESPONSE" | jq .
  exit 1
fi

echo -e "   \033[0;32mWorkflow created!\033[0m"
echo "   Workflow ID: $WORKFLOW_ID"
echo ""

# Step 2: Execute steps with gate checks
echo "Executing workflow steps..."

for STEP_NUM in 1 2 3; do
  STEP_ID="step-${STEP_NUM}"

  # Check gate
  GATE_RESPONSE=$(curl -s -X POST "${ORCHESTRATOR_URL}/api/v1/workflows/${WORKFLOW_ID}/steps/${STEP_ID}/gate" \
    -H "Content-Type: application/json" \
    -H "$AUTH_HEADER" \
    -d "{
      \"step_name\": \"Step ${STEP_NUM}\",
      \"step_type\": \"action\",
      \"step_input\": {\"action\": \"process-${STEP_NUM}\"}
    }")

  DECISION=$(echo "$GATE_RESPONSE" | jq -r '.decision // "unknown"')

  if [ "$DECISION" = "allow" ] || [ "$DECISION" = "ALLOW" ]; then
    # Mark step completed
    curl -s -X POST "${ORCHESTRATOR_URL}/api/v1/workflows/${WORKFLOW_ID}/steps/${STEP_ID}/complete" \
      -H "Content-Type: application/json" \
      -H "$AUTH_HEADER" \
      -d "{\"output\": {\"result\": \"step-${STEP_NUM}-done\"}}" > /dev/null

    echo -e "   Step ${STEP_NUM}: \033[0;32m${DECISION}\033[0m - completed"
  else
    echo -e "   Step ${STEP_NUM}: \033[0;31m${DECISION}\033[0m"
  fi
done

echo ""

# Step 3: Complete workflow
echo "Completing workflow..."
curl -s -X POST "${ORCHESTRATOR_URL}/api/v1/workflows/${WORKFLOW_ID}/complete" \
  -H "Content-Type: application/json" \
  -H "$AUTH_HEADER" > /dev/null

echo -e "   \033[0;32mWorkflow completed!\033[0m"
echo ""

# Step 4: Get final status
echo "Getting workflow status..."
STATUS_RESPONSE=$(curl -s "${ORCHESTRATOR_URL}/api/v1/workflows/${WORKFLOW_ID}" \
  -H "$AUTH_HEADER")

WF_NAME=$(echo "$STATUS_RESPONSE" | jq -r '.workflow_name // "unknown"')
WF_STATUS=$(echo "$STATUS_RESPONSE" | jq -r '.status // "unknown"')
WF_STEPS=$(echo "$STATUS_RESPONSE" | jq -r '.steps | length // 0')

echo "   Workflow: $WF_NAME"
echo "   Status: $WF_STATUS"
echo "   Steps: $WF_STEPS"
echo ""

# =============================================
# Part 3: Cancel Execution
# =============================================
echo -e "\033[1;34m=== Part 3: Cancel Execution ===\033[0m"
echo ""

# Create a workflow to cancel
echo "Creating workflow to test cancellation..."
CANCEL_WF_RESPONSE=$(curl -s -X POST "${ORCHESTRATOR_URL}/api/v1/workflows" \
  -H "Content-Type: application/json" \
  -H "$AUTH_HEADER" \
  -d '{
    "workflow_name": "cancel-test-demo",
    "source": "external",
    "total_steps": 2
  }')

CANCEL_WF_ID=$(echo "$CANCEL_WF_RESPONSE" | jq -r '.workflow_id // empty')
if [ -n "$CANCEL_WF_ID" ]; then
  echo "   Created workflow: $CANCEL_WF_ID"

  # Cancel via unified API
  echo "   Cancelling via POST /api/v1/unified/executions/{id}/cancel..."
  CANCEL_RESPONSE=$(curl -s -X POST "${ORCHESTRATOR_URL}/api/v1/unified/executions/${CANCEL_WF_ID}/cancel" \
    -H "Content-Type: application/json" \
    -H "$AUTH_HEADER" \
    -d '{"reason": "testing unified cancel endpoint"}')

  CANCEL_STATUS=$(echo "$CANCEL_RESPONSE" | jq -r '.status // .error.code // "unknown"')
  echo "   Cancel response status: $CANCEL_STATUS"
else
  echo "   Note: Could not create workflow for cancel test"
fi
echo ""

# =============================================
# Part 4: SSE Streaming (example curl command)
# =============================================
echo -e "\033[1;34m=== Part 4: SSE Streaming ===\033[0m"
echo ""
echo "SSE streaming endpoint:"
echo "   GET /api/v1/unified/executions/{id}/stream"
echo ""
echo "Example curl command (use with a running execution):"
echo "   curl -N '${ORCHESTRATOR_URL}/api/v1/unified/executions/EXECUTION_ID/stream' \\"
echo "     -H '$AUTH_HEADER'"
echo ""
echo "Events: execution.started, execution.completed, execution.failed,"
echo "        execution.cancelled, step.started, step.completed,"
echo "        step.failed, step.decision"
echo ""

# =============================================
# Part 5: List Workflows
# =============================================
echo -e "\033[1;34m=== Part 5: List Workflows ===\033[0m"
echo ""

LIST_RESPONSE=$(curl -s "${ORCHESTRATOR_URL}/api/v1/workflows?limit=5" \
  -H "$AUTH_HEADER")

TOTAL=$(echo "$LIST_RESPONSE" | jq -r '.total // 0')
COUNT=$(echo "$LIST_RESPONSE" | jq -r '.workflows | length // 0')

echo "Found $TOTAL workflows (showing $COUNT)"
echo "$LIST_RESPONSE" | jq -r '.workflows[]? | "   - \(.workflow_id): \(.workflow_name) (\(.status))"' 2>/dev/null || echo "   (no workflows)"
echo ""

# =============================================
# Summary
# =============================================
echo "========================================================"
if [ "$WF_STATUS" = "completed" ]; then
  echo -e "\033[0;32mUnified Execution Tracking Test: PASS\033[0m"
  echo ""
  echo "Demonstrated:"
  echo "  1. MAP plan creation via /api/request"
  echo "  2. WCP workflow creation, step gates, completion"
  echo "  3. Workflow status tracking"
  echo "  4. Cancel execution via POST /api/v1/unified/executions/{id}/cancel"
  echo "  5. SSE streaming via GET /api/v1/unified/executions/{id}/stream"
  echo "  6. Workflow listing"
else
  echo -e "\033[0;31mUnified Execution Tracking Test: FAIL\033[0m"
  echo "Final workflow status: $WF_STATUS (expected: completed)"
  exit 1
fi
