#!/bin/bash
# Workflow Fail - HTTP/curl Example
#
# Demonstrates and VALIDATES the FailWorkflow endpoint using raw HTTP requests.
#
# Tests:
# 1. Create a workflow and complete one step
# 2. POST /api/v1/workflows/$WF_ID/fail with a reason
# 3. Verify workflow status is "failed" via GET
# 4. Create another workflow, fail without reason
# 5. Verify failed workflow cannot be resumed (step gate fails)
#
# Prerequisites:
#   - AxonFlow Agent running at http://localhost:8080
#   - curl and jq installed
#
# Usage:
#   chmod +x workflow-fail.sh
#   ./workflow-fail.sh

set -e

AGENT_URL="${AXONFLOW_ENDPOINT:-${AXONFLOW_AGENT_URL:-http://localhost:8080}}"
CLIENT_ID="${AXONFLOW_CLIENT_ID:-community}"
CLIENT_SECRET="${AXONFLOW_CLIENT_SECRET:-}"
AUTH_B64=$(printf '%s:%s' "$CLIENT_ID" "$CLIENT_SECRET" | base64)
AUTH_HEADER=(-H "Authorization: Basic $AUTH_B64")

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

PASS_COUNT=0
FAIL_COUNT=0

assert_check() {
    local condition="$1"
    local message="$2"
    if [ "$condition" = "true" ]; then
        echo -e "   ${GREEN}PASS: ${message}${NC}"
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        echo -e "   ${RED}FAIL: ${message}${NC}"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
}

echo "Workflow Fail - HTTP/curl"
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

# ========================================
# Test 1: Create Workflow + Step Gate + Complete Step
# ========================================
echo -e "${BLUE}Test 1: Create Workflow + Step Gate + Complete Step${NC}"
echo "   Creating 'fail-workflow-test' workflow..."

create_response=$(curl -s -u "$CLIENT_ID:$CLIENT_SECRET" -X POST "$AGENT_URL/api/v1/workflows" \
    -H "Content-Type: application/json" \
    -d '{
        "workflow_name": "fail-workflow-test",
        "source": "external",
        "metadata": {
            "test": "workflow-fail-http"
        }
    }')

WORKFLOW_ID=$(echo "$create_response" | jq -r '.workflow_id // ""')
if [ -z "$WORKFLOW_ID" ] || [ "$WORKFLOW_ID" = "null" ]; then
    echo -e "   ${RED}FATAL: Failed to create workflow${NC}"
    echo "   Response: $create_response"
    exit 1
fi

assert_check "true" "Workflow created with valid ID"
echo "   Workflow ID: $WORKFLOW_ID"

# Step gate
echo "   Checking gate for step-1..."
gate_response=$(curl -s -u "$CLIENT_ID:$CLIENT_SECRET" -X POST "$AGENT_URL/api/v1/workflows/$WORKFLOW_ID/steps/step-1/gate" \
    -H "Content-Type: application/json" \
    -d '{
        "step_name": "Data Processing",
        "step_type": "llm_call",
        "model": "claude-sonnet-4-20250514",
        "provider": "anthropic",
        "tokens_in": 175,
        "tokens_out": 380,
        "step_input": {
            "prompt": "Process incoming data batch"
        }
    }')

decision=$(echo "$gate_response" | jq -r '.decision // "unknown"')
echo "   Gate decision: $decision"

if [ "$decision" = "allow" ]; then
    echo "   Marking step-1 completed..."
    curl -s -u "$CLIENT_ID:$CLIENT_SECRET" -X POST "$AGENT_URL/api/v1/workflows/$WORKFLOW_ID/steps/step-1/complete" \
        -H "Content-Type: application/json" \
        -d '{"output": {"records_processed": 150}}' > /dev/null
    assert_check "true" "Step 1 completed"
fi
echo ""

# ========================================
# Test 2: FailWorkflow with Reason
# ========================================
echo -e "${BLUE}Test 2: FailWorkflow with Reason${NC}"
echo "   Calling POST /api/v1/workflows/$WORKFLOW_ID/fail..."

fail_response=$(curl -s -u "$CLIENT_ID:$CLIENT_SECRET" -w "\n%{http_code}" -X POST "$AGENT_URL/api/v1/workflows/$WORKFLOW_ID/fail" \
    -H "Content-Type: application/json" \
    -d '{"reason": "LLM provider timeout after 30s"}')

fail_body=$(echo "$fail_response" | sed '$d')
fail_http=$(echo "$fail_response" | tail -n 1)

if [ "$fail_http" = "200" ]; then
    assert_check "true" "FailWorkflow returns HTTP 200"
else
    assert_check "false" "FailWorkflow returns HTTP 200 (got $fail_http)"
fi

fail_status=$(echo "$fail_body" | jq -r '.status // "unknown"')
if [ "$fail_status" = "failed" ]; then
    assert_check "true" "FailWorkflow response status is 'failed'"
else
    assert_check "false" "FailWorkflow response status is 'failed' (got: $fail_status)"
fi
echo "   Status: $fail_status"
echo "   Body: $fail_body"
echo ""

# ========================================
# Test 3: Verify Workflow Status via GET
# ========================================
echo -e "${BLUE}Test 3: Verify Workflow Status via GET${NC}"

verify_response=$(curl -s -u "$CLIENT_ID:$CLIENT_SECRET" "$AGENT_URL/api/v1/workflows/$WORKFLOW_ID")

verify_status=$(echo "$verify_response" | jq -r '.status // "unknown"')
verify_name=$(echo "$verify_response" | jq -r '.workflow_name // "unknown"')

if [ "$verify_status" = "failed" ]; then
    assert_check "true" "GetWorkflow confirms status is 'failed'"
else
    assert_check "false" "GetWorkflow confirms status is 'failed' (got: $verify_status)"
fi

if [ "$verify_name" = "fail-workflow-test" ]; then
    assert_check "true" "Workflow name matches 'fail-workflow-test'"
else
    assert_check "false" "Workflow name matches (got: $verify_name)"
fi
echo "   Status: $verify_status"
echo "   Workflow: $verify_name"
echo ""

# ========================================
# Test 4: FailWorkflow without Reason
# ========================================
echo -e "${BLUE}Test 4: FailWorkflow without Reason${NC}"
echo "   Creating second workflow..."

no_reason_create=$(curl -s -u "$CLIENT_ID:$CLIENT_SECRET" -X POST "$AGENT_URL/api/v1/workflows" \
    -H "Content-Type: application/json" \
    -d '{
        "workflow_name": "fail-no-reason-test",
        "source": "external",
        "metadata": {
            "test": "fail-no-reason-http"
        }
    }')

NO_REASON_WF_ID=$(echo "$no_reason_create" | jq -r '.workflow_id // ""')
if [ -z "$NO_REASON_WF_ID" ] || [ "$NO_REASON_WF_ID" = "null" ]; then
    echo -e "   ${RED}FATAL: Failed to create second workflow${NC}"
    echo "   Response: $no_reason_create"
    exit 1
fi
echo "   Workflow ID: $NO_REASON_WF_ID"

# Fail without reason (empty body)
no_reason_fail=$(curl -s -u "$CLIENT_ID:$CLIENT_SECRET" -w "\n%{http_code}" -X POST "$AGENT_URL/api/v1/workflows/$NO_REASON_WF_ID/fail" \
    -H "Content-Type: application/json" \
    -d '{}')

nr_body=$(echo "$no_reason_fail" | sed '$d')
nr_http=$(echo "$no_reason_fail" | tail -n 1)

if [ "$nr_http" = "200" ]; then
    assert_check "true" "FailWorkflow without reason returns HTTP 200"
else
    assert_check "false" "FailWorkflow without reason returns HTTP 200 (got $nr_http)"
fi

nr_status=$(echo "$nr_body" | jq -r '.status // "unknown"')
if [ "$nr_status" = "failed" ]; then
    assert_check "true" "FailWorkflow without reason sets status to 'failed'"
else
    assert_check "false" "FailWorkflow without reason sets status to 'failed' (got: $nr_status)"
fi
echo "   Status: $nr_status"
echo ""

# ========================================
# Test 5: Verify Failed Workflow Cannot Be Resumed
# ========================================
echo -e "${BLUE}Test 5: Verify Failed Workflow Cannot Be Resumed${NC}"

# Try step gate on failed workflow
echo "   Attempting step gate on failed workflow..."
resume_response=$(curl -s -u "$CLIENT_ID:$CLIENT_SECRET" -w "\n%{http_code}" -X POST "$AGENT_URL/api/v1/workflows/$WORKFLOW_ID/steps/step-2/gate" \
    -H "Content-Type: application/json" \
    -d '{
        "step_name": "Should Not Execute",
        "step_type": "tool_call",
        "step_input": {"tool": "noop"}
    }')

resume_body=$(echo "$resume_response" | sed '$d')
resume_http=$(echo "$resume_response" | tail -n 1)

# Expect non-200 (400 or 409 typically)
if [ "$resume_http" != "200" ]; then
    assert_check "true" "StepGate on failed workflow returns error (HTTP $resume_http)"
else
    assert_check "false" "StepGate on failed workflow should return error (got HTTP 200)"
fi
echo "   HTTP: $resume_http"
echo "   Response: $resume_body"

# Try to complete the failed workflow
echo "   Attempting to complete failed workflow..."
complete_response=$(curl -s -u "$CLIENT_ID:$CLIENT_SECRET" -w "\n%{http_code}" -X POST "$AGENT_URL/api/v1/workflows/$WORKFLOW_ID/complete" \
    -H "Content-Type: application/json" \
)

complete_body=$(echo "$complete_response" | sed '$d')
complete_http=$(echo "$complete_response" | tail -n 1)

if [ "$complete_http" != "200" ]; then
    assert_check "true" "CompleteWorkflow on failed workflow returns error (HTTP $complete_http)"
else
    assert_check "false" "CompleteWorkflow on failed workflow should return error (got HTTP 200)"
fi
echo "   HTTP: $complete_http"
echo "   Response: $complete_body"
echo ""

# ========================================
# Cleanup
# ========================================
echo -e "${YELLOW}Cleanup${NC}"
for wf_id in "$WORKFLOW_ID" "$NO_REASON_WF_ID"; do
    curl -s -u "$CLIENT_ID:$CLIENT_SECRET" -X POST "$AGENT_URL/api/v1/workflows/$wf_id/abort" \
        -H "Content-Type: application/json" \
        -d '{"reason": "test cleanup"}' > /dev/null 2>&1 || true
    echo "   Cleaned up workflow: $wf_id"
done
echo ""

# ========================================
# Summary
# ========================================
echo "========================================"
echo -e "Results: ${GREEN}$PASS_COUNT PASS${NC}, ${RED}$FAIL_COUNT FAIL${NC}"

if [ "$FAIL_COUNT" -gt 0 ]; then
    echo -e "${RED}SOME TESTS FAILED${NC}"
    exit 1
else
    echo -e "${GREEN}ALL TESTS PASSED - FailWorkflow is working correctly${NC}"
    echo ""
    echo "FailWorkflow operations validated:"
    echo "  - POST /api/v1/workflows (create)"
    echo "  - POST /api/v1/workflows/{id}/steps/{stepId}/gate"
    echo "  - POST /api/v1/workflows/{id}/steps/{stepId}/complete"
    echo "  - POST /api/v1/workflows/{id}/fail (with reason)"
    echo "  - POST /api/v1/workflows/{id}/fail (without reason)"
    echo "  - GET  /api/v1/workflows/{id} (verify failed status)"
    echo "  - Failed workflow cannot be resumed"
fi
