#!/bin/bash
# Health Check Example - HTTP/cURL
#
# Demonstrates how to check the health of AxonFlow Agent and Orchestrator services
# using direct HTTP calls.
#
# Usage:
#   ./health-check.sh
#
# Environment:
#   AXONFLOW_ENDPOINT - Agent URL (default: http://localhost:8080)

set -e

ENDPOINT="${AXONFLOW_ENDPOINT:-http://localhost:8080}"
ORCHESTRATOR_PORT="${ORCHESTRATOR_PORT:-8081}"

# Derive orchestrator URL from agent endpoint
ORCH_ENDPOINT=$(echo "$ENDPOINT" | sed "s/:8080/:$ORCHESTRATOR_PORT/")

echo "=== AxonFlow Health Check Example ==="
echo ""

# 1. Check Agent health
echo "1. Checking Agent health..."
AGENT_HEALTH=$(curl -s "${ENDPOINT}/health" || echo '{"error": "connection failed"}')
echo "   Response: $AGENT_HEALTH"

if echo "$AGENT_HEALTH" | grep -q '"status":"healthy"'; then
    echo "   Agent: HEALTHY"
else
    echo "   Agent: UNHEALTHY"
fi

echo ""

# 2. Check Orchestrator health
echo "2. Checking Orchestrator health..."
ORCH_HEALTH=$(curl -s "${ORCH_ENDPOINT}/health" || echo '{"error": "connection failed"}')
echo "   Response: $ORCH_HEALTH"

if echo "$ORCH_HEALTH" | grep -q '"status":"healthy"'; then
    echo "   Orchestrator: HEALTHY"
else
    echo "   Orchestrator: UNHEALTHY"
fi

echo ""
echo "=== Health Check Complete ==="
