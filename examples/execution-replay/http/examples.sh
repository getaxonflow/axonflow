#!/bin/bash
#
# AxonFlow Execution Replay API - HTTP Examples
#
# Validates the Execution Replay API endpoints via curl with assertions.
# The Execution Replay feature captures every step of workflow execution
# for debugging, auditing, and compliance purposes.
#
# Tested endpoints:
#   GET /api/v1/executions                 - List executions
#   GET /api/v1/executions/{id}            - Get execution details
#   GET /api/v1/executions/{id}/steps      - Get all execution steps
#   GET /api/v1/executions/{id}/steps/{n}  - Get specific step
#   GET /api/v1/executions/{id}/timeline   - Get execution timeline
#   GET /api/v1/executions/{id}/export     - Export execution for compliance
#
# Usage: ./examples.sh
#
# Environment:
#   AXONFLOW_AGENT_URL - Agent URL (default: http://localhost:8080)

set -e

AGENT_URL="${AXONFLOW_AGENT_URL:-http://localhost:8080}"
CLIENT_ID="${AXONFLOW_CLIENT_ID:-community}"
CLIENT_SECRET="${AXONFLOW_CLIENT_SECRET:-}"
AUTH=(-u "$CLIENT_ID:$CLIENT_SECRET")

echo "=============================================="
echo "AxonFlow Execution Replay API - HTTP Examples"
echo "=============================================="
echo "Base URL: $AGENT_URL"
echo ""

PASS=0
FAIL=0

check_result() {
    local test_name="$1"
    local condition="$2"
    if [ "$condition" = "true" ]; then
        echo "   PASS: $test_name"
        PASS=$((PASS + 1))
    else
        echo "   FAIL: $test_name"
        FAIL=$((FAIL + 1))
    fi
}

# ========================================
# 1. List executions
# ========================================
echo "1. List Executions"
echo "   GET ${AGENT_URL}/api/v1/executions?limit=10"

LIST_RESPONSE=$(curl -s "${AUTH[@]}" --max-time 15 "${AGENT_URL}/api/v1/executions?limit=10" 2>/dev/null || echo '{}')
LIST_VALID=$(echo "$LIST_RESPONSE" | jq 'has("executions")' 2>/dev/null || echo "false")
check_result "List executions returns valid JSON with 'executions' field" "$LIST_VALID"
echo ""

# Get first execution ID if available
EXECUTION_ID=$(echo "$LIST_RESPONSE" | jq -r '.executions[0].request_id // empty' 2>/dev/null || echo "")

if [ -z "$EXECUTION_ID" ]; then
    echo "No executions found. Run a workflow first to generate execution data."
    echo ""
    echo "=============================================="
    echo "Execution Replay Examples - Summary"
    echo "=============================================="
    echo "Passed: $PASS"
    echo "Failed: $FAIL"
    echo ""
    if [ "$FAIL" -gt 0 ]; then
        echo "$FAIL assertion(s) FAILED"
        exit 1
    else
        echo "All assertions passed! (limited — no executions available)"
        exit 0
    fi
fi

echo "   Found execution: $EXECUTION_ID"
echo ""

# ========================================
# 2. Get execution details
# ========================================
echo "2. Get Execution Details"
echo "   GET ${AGENT_URL}/api/v1/executions/${EXECUTION_ID}"

DETAIL_RESPONSE=$(curl -s "${AUTH[@]}" --max-time 15 "${AGENT_URL}/api/v1/executions/${EXECUTION_ID}" 2>/dev/null || echo '{}')
# Detail response is {"summary": {...}, "steps": [...]}
DETAIL_HAS_ID=$(echo "$DETAIL_RESPONSE" | jq 'has("request_id") or (.summary | has("request_id"))' 2>/dev/null || echo "false")
check_result "Execution detail returns request_id" "$DETAIL_HAS_ID"

# Validate cost fields exist
DETAIL_HAS_COST=$(echo "$DETAIL_RESPONSE" | jq 'has("total_cost_usd") or (.summary | has("total_cost_usd"))' 2>/dev/null || echo "false")
check_result "Execution detail contains total_cost_usd field" "$DETAIL_HAS_COST"

DETAIL_HAS_STATUS=$(echo "$DETAIL_RESPONSE" | jq 'has("status") or (.summary | has("status"))' 2>/dev/null || echo "false")
check_result "Execution detail contains status field" "$DETAIL_HAS_STATUS"
echo ""

# ========================================
# 3. Get execution steps
# ========================================
echo "3. Get Execution Steps"
echo "   GET ${AGENT_URL}/api/v1/executions/${EXECUTION_ID}/steps"

STEPS_RESPONSE=$(curl -s "${AUTH[@]}" --max-time 15 "${AGENT_URL}/api/v1/executions/${EXECUTION_ID}/steps" 2>/dev/null || echo '[]')
# Steps endpoint returns a JSON array directly (not wrapped in {"steps": [...]})
STEPS_IS_ARRAY=$(echo "$STEPS_RESPONSE" | jq 'type == "array"' 2>/dev/null || echo "false")
check_result "Steps endpoint returns JSON array" "$STEPS_IS_ARRAY"

STEPS_COUNT=$(echo "$STEPS_RESPONSE" | jq 'length' 2>/dev/null || echo "0")
check_result "Steps array is non-empty (got $STEPS_COUNT)" "$([ "$STEPS_COUNT" -gt 0 ] && echo true || echo false)"

# Validate step-level cost_usd field exists on first step
STEP_HAS_COST=$(echo "$STEPS_RESPONSE" | jq '.[0] | has("cost_usd")' 2>/dev/null || echo "false")
check_result "Step contains cost_usd field" "$STEP_HAS_COST"
echo ""

# ========================================
# 4. Get specific step
# ========================================
echo "4. Get Specific Step"
echo "   GET ${AGENT_URL}/api/v1/executions/${EXECUTION_ID}/steps/0"

STEP0_RESPONSE=$(curl -s "${AUTH[@]}" --max-time 15 "${AGENT_URL}/api/v1/executions/${EXECUTION_ID}/steps/0" 2>/dev/null || echo '{}')
STEP0_HAS_NAME=$(echo "$STEP0_RESPONSE" | jq 'has("step_name") or has("name")' 2>/dev/null || echo "false")
check_result "Specific step returns step name" "$STEP0_HAS_NAME"
echo ""

# ========================================
# 5. Get execution timeline
# ========================================
echo "5. Get Execution Timeline"
echo "   GET ${AGENT_URL}/api/v1/executions/${EXECUTION_ID}/timeline"

TIMELINE_RESPONSE=$(curl -s "${AUTH[@]}" --max-time 15 "${AGENT_URL}/api/v1/executions/${EXECUTION_ID}/timeline" 2>/dev/null || echo '[]')
TIMELINE_VALID=$(echo "$TIMELINE_RESPONSE" | jq 'type == "array" or has("timeline") or has("events")' 2>/dev/null || echo "false")
check_result "Timeline returns valid JSON response" "$TIMELINE_VALID"
echo ""

# ========================================
# 6. Export execution
# ========================================
echo "6. Export Execution"
echo "   GET ${AGENT_URL}/api/v1/executions/${EXECUTION_ID}/export?include_input=true&include_output=true"

EXPORT_RESPONSE=$(curl -s "${AUTH[@]}" --max-time 15 "${AGENT_URL}/api/v1/executions/${EXECUTION_ID}/export?include_input=true&include_output=true" 2>/dev/null || echo '{}')
EXPORT_VALID=$(echo "$EXPORT_RESPONSE" | jq 'type == "object"' 2>/dev/null || echo "false")
check_result "Export returns valid JSON object" "$EXPORT_VALID"
echo ""

# ========================================
# SUMMARY
# ========================================
echo "=============================================="
echo "Execution Replay Examples - Summary"
echo "=============================================="
echo ""
echo "API Endpoints Tested:"
echo "  GET /api/v1/executions                 - List executions"
echo "  GET /api/v1/executions/{id}            - Get execution details"
echo "  GET /api/v1/executions/{id}/steps      - Get all execution steps"
echo "  GET /api/v1/executions/{id}/steps/{n}  - Get specific step"
echo "  GET /api/v1/executions/{id}/timeline   - Get execution timeline"
echo "  GET /api/v1/executions/{id}/export     - Export execution"
echo ""
echo "Passed: $PASS"
echo "Failed: $FAIL"
echo ""

if [ "$FAIL" -gt 0 ]; then
    echo "$FAIL assertion(s) FAILED"
    exit 1
else
    echo "All assertions passed!"
    exit 0
fi
