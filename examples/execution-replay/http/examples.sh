#!/bin/bash
#
# AxonFlow Execution Replay API - HTTP Examples
#
# This script demonstrates how to use the Execution Replay API via curl.
# The Execution Replay feature captures every step of workflow execution
# for debugging, auditing, and compliance purposes.
#
# Usage: ./examples.sh
#

set -e

ORCHESTRATOR_URL="${AXONFLOW_ORCHESTRATOR_URL:-http://localhost:8081}"

echo "AxonFlow Execution Replay API - HTTP Examples"
echo "=========================================="
echo ""
echo "Base URL: $ORCHESTRATOR_URL"
echo ""

# 1. List executions
echo "1. List Executions"
echo "-------------------"
echo "GET ${ORCHESTRATOR_URL}/api/v1/executions?limit=10"
echo ""
echo "Response:"
curl -s "${ORCHESTRATOR_URL}/api/v1/executions?limit=10" | jq .
echo ""

# 2. List executions with filters
echo "2. List Executions with Filters"
echo "--------------------------------"
echo "Filter by status:"
echo "  GET ${ORCHESTRATOR_URL}/api/v1/executions?status=completed"
echo ""
echo "Filter by workflow:"
echo "  GET ${ORCHESTRATOR_URL}/api/v1/executions?workflow_id=my-workflow"
echo ""
echo "Filter by time range:"
echo "  GET ${ORCHESTRATOR_URL}/api/v1/executions?start_time=2025-01-01T00:00:00Z&end_time=2025-12-31T23:59:59Z"
echo ""
echo "Pagination:"
echo "  GET ${ORCHESTRATOR_URL}/api/v1/executions?limit=20&offset=0"
echo ""
echo "With tenant/org headers:"
echo '  curl -H "X-Tenant-ID: my-tenant" -H "X-Org-ID: my-org" ${ORCHESTRATOR_URL}/api/v1/executions'
echo ""

# Get first execution ID if available
EXECUTION_ID=$(curl -s "${ORCHESTRATOR_URL}/api/v1/executions?limit=1" | jq -r '.executions[0].request_id // empty')

if [ -n "$EXECUTION_ID" ]; then
    echo "Found execution: $EXECUTION_ID"
    echo ""

    # 3. Get execution details
    echo "3. Get Execution Details"
    echo "-------------------------"
    echo "GET ${ORCHESTRATOR_URL}/api/v1/executions/${EXECUTION_ID}"
    echo ""
    echo "Response:"
    curl -s "${ORCHESTRATOR_URL}/api/v1/executions/${EXECUTION_ID}" | jq .
    echo ""

    # 4. Get execution steps
    echo "4. Get Execution Steps"
    echo "----------------------"
    echo "GET ${ORCHESTRATOR_URL}/api/v1/executions/${EXECUTION_ID}/steps"
    echo ""
    echo "Response:"
    curl -s "${ORCHESTRATOR_URL}/api/v1/executions/${EXECUTION_ID}/steps" | jq .
    echo ""

    # 5. Get specific step
    echo "5. Get Specific Step"
    echo "--------------------"
    echo "GET ${ORCHESTRATOR_URL}/api/v1/executions/${EXECUTION_ID}/steps/0"
    echo ""
    echo "Response:"
    curl -s "${ORCHESTRATOR_URL}/api/v1/executions/${EXECUTION_ID}/steps/0" | jq .
    echo ""

    # 6. Get execution timeline
    echo "6. Get Execution Timeline"
    echo "--------------------------"
    echo "GET ${ORCHESTRATOR_URL}/api/v1/executions/${EXECUTION_ID}/timeline"
    echo ""
    echo "Response:"
    curl -s "${ORCHESTRATOR_URL}/api/v1/executions/${EXECUTION_ID}/timeline" | jq .
    echo ""

    # 7. Export execution
    echo "7. Export Execution"
    echo "-------------------"
    echo "GET ${ORCHESTRATOR_URL}/api/v1/executions/${EXECUTION_ID}/export"
    echo ""
    echo "With options:"
    echo "  ?format=json"
    echo "  ?include_input=true"
    echo "  ?include_output=true"
    echo "  ?include_policies=true"
    echo ""
    echo "Response (truncated):"
    curl -s "${ORCHESTRATOR_URL}/api/v1/executions/${EXECUTION_ID}/export?include_input=true&include_output=true" | jq . | head -30
    echo "  ... (truncated)"
    echo ""

    # 8. Delete execution (commented out to prevent accidental deletion)
    echo "8. Delete Execution"
    echo "-------------------"
    echo "DELETE ${ORCHESTRATOR_URL}/api/v1/executions/${EXECUTION_ID}"
    echo ""
    echo "# Uncomment to delete:"
    echo "# curl -X DELETE ${ORCHESTRATOR_URL}/api/v1/executions/${EXECUTION_ID}"
    echo ""

else
    echo "No executions found. Run a workflow to generate execution data."
    echo ""
    echo "Example API calls (replace {id} with actual execution ID):"
    echo ""
    echo "# Get execution details"
    echo "curl ${ORCHESTRATOR_URL}/api/v1/executions/{id}"
    echo ""
    echo "# Get execution steps"
    echo "curl ${ORCHESTRATOR_URL}/api/v1/executions/{id}/steps"
    echo ""
    echo "# Get execution timeline"
    echo "curl ${ORCHESTRATOR_URL}/api/v1/executions/{id}/timeline"
    echo ""
    echo "# Export execution"
    echo "curl ${ORCHESTRATOR_URL}/api/v1/executions/{id}/export"
    echo ""
    echo "# Delete execution"
    echo "curl -X DELETE ${ORCHESTRATOR_URL}/api/v1/executions/{id}"
    echo ""
fi

echo "=========================================="
echo "Execution Replay API Examples Complete!"
echo ""
echo "API Summary:"
echo "  GET    /api/v1/executions                 - List executions"
echo "  GET    /api/v1/executions/{id}            - Get execution details"
echo "  GET    /api/v1/executions/{id}/steps      - Get all execution steps"
echo "  GET    /api/v1/executions/{id}/steps/{n}  - Get specific step"
echo "  GET    /api/v1/executions/{id}/timeline   - Get execution timeline"
echo "  GET    /api/v1/executions/{id}/export     - Export execution for compliance"
echo "  DELETE /api/v1/executions/{id}            - Delete execution"
