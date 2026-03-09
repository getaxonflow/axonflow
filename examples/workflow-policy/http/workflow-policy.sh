#!/bin/bash
# Workflow Policy Enforcement Examples - HTTP/curl
#
# This script demonstrates:
# 1. MAP policy enforcement (policy_info in execute response)
# 2. WCP policy enforcement (policies_evaluated/matched in step gate response)
# 3. Audit log verification to confirm operations are logged

set -e

# Configuration
AGENT_URL="${AXONFLOW_ENDPOINT:-http://localhost:8080}"
ORCHESTRATOR_URL="${AXONFLOW_ORCHESTRATOR_URL:-http://localhost:8081}"
CLIENT_ID="${AXONFLOW_CLIENT_ID:-demo}"
CLIENT_SECRET="${AXONFLOW_CLIENT_SECRET:-secret}"

# Auth header
AUTH_HEADER="Authorization: Basic $(echo -n "${CLIENT_ID}:${CLIENT_SECRET}" | base64)"

echo "=========================================="
echo "Workflow Policy Enforcement - HTTP Examples"
echo "=========================================="
echo ""
echo "Agent URL: ${AGENT_URL}"
echo "Orchestrator URL: ${ORCHESTRATOR_URL}"
echo ""

# ==========================================
# Part 1: MAP Policy Enforcement
# ==========================================

echo "Part 1: MAP (Multi-Agent Planning) Policy Enforcement"
echo "------------------------------------------------------"
echo ""

# 1.1 Create a plan first
echo "1.1 Creating a plan..."
PLAN_RESPONSE=$(curl -s -X POST "${ORCHESTRATOR_URL}/api/v1/plan" \
  -H "Content-Type: application/json" \
  -H "${AUTH_HEADER}" \
  -d '{
    "query": "Analyze customer feedback and generate a summary report",
    "domain": "generic",
    "user": {
      "id": 1,
      "email": "test@example.com"
    }
  }')

PLAN_ID=$(echo "${PLAN_RESPONSE}" | jq -r '.plan_id // empty')
if [ -z "${PLAN_ID}" ]; then
  echo "   Note: Plan creation may require LLM configuration"
  echo "   Using mock plan_id for demonstration"
  PLAN_ID="plan_demo_123"
fi
echo "   Plan ID: ${PLAN_ID}"
echo ""

# 1.2 Execute plan - demonstrates policy_info in response
echo "1.2 Executing plan (demonstrates policy_info in response)..."
EXEC_RESPONSE=$(curl -s -X POST "${ORCHESTRATOR_URL}/api/v1/plan/execute" \
  -H "Content-Type: application/json" \
  -H "${AUTH_HEADER}" \
  -d "{
    \"query\": \"Analyze customer feedback\",
    \"user\": {
      \"id\": 1,
      \"email\": \"test@example.com\"
    },
    \"context\": {
      \"plan_id\": \"${PLAN_ID}\"
    }
  }")

echo "   Response:"
echo "${EXEC_RESPONSE}" | jq '.'
echo ""

# Check if policy_info is present
POLICY_INFO=$(echo "${EXEC_RESPONSE}" | jq '.policy_info // empty')
if [ -n "${POLICY_INFO}" ]; then
  echo "   Policy Info found in response:"
  echo "${POLICY_INFO}" | jq '.'
else
  echo "   Note: policy_info will be present when dynamic policies are configured"
fi
echo ""

# ==========================================
# Part 2: WCP Policy Enforcement
# ==========================================

echo "Part 2: WCP (Workflow Control Plane) Policy Enforcement"
echo "--------------------------------------------------------"
echo ""

# 2.1 Create a workflow
echo "2.1 Creating workflow..."
WF_RESPONSE=$(curl -s -X POST "${ORCHESTRATOR_URL}/api/v1/workflows" \
  -H "Content-Type: application/json" \
  -H "${AUTH_HEADER}" \
  -d '{
    "workflow_name": "policy-demo-workflow",
    "source": "external",
    "metadata": {
      "example": "workflow-policy-http"
    }
  }')

WORKFLOW_ID=$(echo "${WF_RESPONSE}" | jq -r '.workflow_id')
echo "   Workflow ID: ${WORKFLOW_ID}"
echo ""

# 2.2 Check step gate - demonstrates policies_evaluated and policies_matched
echo "2.2 Checking step gate (demonstrates policies_evaluated/matched)..."
GATE_RESPONSE=$(curl -s -X POST "${ORCHESTRATOR_URL}/api/v1/workflows/${WORKFLOW_ID}/steps/step-1/gate" \
  -H "Content-Type: application/json" \
  -H "${AUTH_HEADER}" \
  -d '{
    "step_name": "Generate Analysis",
    "step_type": "llm_call",
    "model": "gpt-4",
    "provider": "azure",
    "tokens_in": 150,
    "tokens_out": 320,
    "step_input": {
      "prompt": "Analyze this customer feedback: Great product!"
    }
  }')

echo "   Step Gate Response:"
echo "${GATE_RESPONSE}" | jq '.'
echo ""

# Highlight policy fields
DECISION=$(echo "${GATE_RESPONSE}" | jq -r '.decision')
POLICIES_EVALUATED=$(echo "${GATE_RESPONSE}" | jq '.policies_evaluated // empty')
POLICIES_MATCHED=$(echo "${GATE_RESPONSE}" | jq '.policies_matched // empty')

echo "   Decision: ${DECISION}"
if [ -n "${POLICIES_EVALUATED}" ]; then
  echo "   Policies Evaluated:"
  echo "${POLICIES_EVALUATED}" | jq '.'
fi
if [ -n "${POLICIES_MATCHED}" ]; then
  echo "   Policies Matched:"
  echo "${POLICIES_MATCHED}" | jq '.'
fi
echo ""

# 2.3 Test with potentially blocked content
echo "2.3 Testing with potentially sensitive content..."
GATE_RESPONSE_2=$(curl -s -X POST "${ORCHESTRATOR_URL}/api/v1/workflows/${WORKFLOW_ID}/steps/step-2/gate" \
  -H "Content-Type: application/json" \
  -H "${AUTH_HEADER}" \
  -d '{
    "step_name": "Process Data",
    "step_type": "tool_call",
    "tokens_in": 85,
    "tokens_out": 42,
    "step_input": {
      "query": "SELECT * FROM users WHERE id = 1"
    }
  }')

echo "   Response:"
echo "${GATE_RESPONSE_2}" | jq '.'
echo ""

# 2.4 Complete the workflow
echo "2.4 Completing workflow..."
curl -s -X POST "${ORCHESTRATOR_URL}/api/v1/workflows/${WORKFLOW_ID}/complete" \
  -H "${AUTH_HEADER}" > /dev/null
echo "   Workflow completed"
echo ""

# ==========================================
# Part 3: Audit Log Verification
# ==========================================

echo "Part 3: Audit Log Verification"
echo "------------------------------"
echo ""

# Delay to ensure audit logs are flushed (batch writer flushes every 5-10 seconds)
echo "   Waiting for audit log batch flush..."
sleep 6

# 3.1 Search for workflow audit logs
echo "3.1 Searching for workflow audit logs..."

# Get current timestamp minus 60 seconds in ISO format
START_TIME=$(date -u -v-60S +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || date -u -d '60 seconds ago' +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || echo "")

AUDIT_RESPONSE=$(curl -s -X POST "${ORCHESTRATOR_URL}/api/v1/audit/search" \
  -H "Content-Type: application/json" \
  -H "${AUTH_HEADER}" \
  -d "{
    \"start_time\": \"${START_TIME}\",
    \"limit\": 50
  }")

# Count entries for this workflow
WORKFLOW_CREATED_COUNT=$(echo "${AUDIT_RESPONSE}" | jq --arg wf "${WORKFLOW_ID}" '[.entries[] | select(.request_id == $wf and .request_type == "workflow_created")] | length')
WORKFLOW_STEP_GATE_COUNT=$(echo "${AUDIT_RESPONSE}" | jq --arg wf "${WORKFLOW_ID}" '[.entries[] | select(.request_id == $wf and .request_type == "workflow_step_gate")] | length')
WORKFLOW_COMPLETED_COUNT=$(echo "${AUDIT_RESPONSE}" | jq --arg wf "${WORKFLOW_ID}" '[.entries[] | select(.request_id == $wf and .request_type == "workflow_completed")] | length')

TOTAL_COUNT=$((WORKFLOW_CREATED_COUNT + WORKFLOW_STEP_GATE_COUNT + WORKFLOW_COMPLETED_COUNT))

if [ "${TOTAL_COUNT}" -gt 0 ]; then
  echo "   ✅ Found ${TOTAL_COUNT} audit log entries for workflow ${WORKFLOW_ID}:"
  [ "${WORKFLOW_CREATED_COUNT}" -gt 0 ] && echo "      - workflow_created: ${WORKFLOW_CREATED_COUNT}"
  [ "${WORKFLOW_STEP_GATE_COUNT}" -gt 0 ] && echo "      - workflow_step_gate: ${WORKFLOW_STEP_GATE_COUNT}"
  [ "${WORKFLOW_COMPLETED_COUNT}" -gt 0 ] && echo "      - workflow_completed: ${WORKFLOW_COMPLETED_COUNT}"
else
  echo "   ⚠️  No audit logs found for this workflow"
  echo "      (Audit logs may take a moment to flush)"
fi
echo ""

# 3.2 Verify expected audit entries
echo "3.2 Verifying expected audit entries..."
ALL_FOUND=true

if [ "${WORKFLOW_CREATED_COUNT}" -gt 0 ]; then
  echo "   ✅ workflow_created: FOUND"
else
  echo "   ❌ workflow_created: NOT FOUND"
  ALL_FOUND=false
fi

if [ "${WORKFLOW_STEP_GATE_COUNT}" -gt 0 ]; then
  echo "   ✅ workflow_step_gate: FOUND"
else
  echo "   ❌ workflow_step_gate: NOT FOUND"
  ALL_FOUND=false
fi

if [ "${WORKFLOW_COMPLETED_COUNT}" -gt 0 ]; then
  echo "   ✅ workflow_completed: FOUND"
else
  echo "   ❌ workflow_completed: NOT FOUND"
  ALL_FOUND=false
fi
echo ""

if [ "${ALL_FOUND}" = true ]; then
  echo "   ✅ All expected audit log entries verified!"
else
  echo "   ⚠️  Some audit log entries were not found"
fi
echo ""

# ==========================================
# Summary
# ==========================================

echo "=========================================="
echo "Summary"
echo "=========================================="
echo ""
echo "MAP Policy Enforcement (Issue #1020):"
echo "  - Execute plan response includes 'policy_info' field"
echo "  - Shows: allowed, applied_policies, risk_score"
echo "  - Returns 403 if policy blocks execution"
echo ""
echo "WCP Policy Enforcement (Issue #1021):"
echo "  - Step gate response includes policy details"
echo "  - 'policies_evaluated': all policies that were checked"
echo "  - 'policies_matched': policies that triggered the decision"
echo "  - Each match includes: policy_id, policy_name, action, reason"
echo ""
echo "Audit Logging (Issue #1019):"
echo "  - workflow_created: logged when workflow is registered"
echo "  - workflow_step_gate: logged for each step gate check"
echo "  - workflow_completed: logged when workflow completes"
echo "  - workflow_aborted: logged when workflow is aborted"
echo ""
echo "=========================================="
