#!/bin/bash
# Version Check Example — HTTP
#
# Queries the /health endpoint and validates version discovery fields:
# version, capabilities, sdk_compatibility.
#
# Prerequisites:
#   - Docker Compose running: docker compose up -d
#
# Run: bash check-version.sh

set -e

AGENT_URL="${AXONFLOW_AGENT_URL:-http://localhost:8080}"
PASS=0
FAIL=0

check() {
    local label="$1" condition="$2"
    if [ "$condition" = "true" ]; then
        echo "  PASS: $label"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: $label"
        FAIL=$((FAIL + 1))
    fi
}

echo "Version Discovery — HTTP"
echo "========================"
echo ""

# ---------------------------------------------------------------
# Test 1: Health endpoint returns version and capabilities
# ---------------------------------------------------------------
echo "Test 1: GET /health — Version and Capabilities"
echo "------------------------------------------------"

resp=$(curl -s "${AGENT_URL}/health")

version=$(echo "$resp" | jq -r '.version')
status=$(echo "$resp" | jq -r '.status')
caps_count=$(echo "$resp" | jq '.capabilities | length')
min_sdk=$(echo "$resp" | jq -r '.sdk_compatibility.min_sdk_version')
rec_sdk=$(echo "$resp" | jq -r '.sdk_compatibility.recommended_sdk_version')

echo "  Platform version: $version"
echo "  Status: $status"
echo "  Capabilities: $caps_count"
echo "  Min SDK version: $min_sdk"
echo "  Recommended SDK: $rec_sdk"

check "version is non-empty" "$([ "$version" != "null" ] && [ -n "$version" ] && echo true || echo false)"
check "status is healthy or starting" "$([ "$status" = "healthy" ] || [ "$status" = "starting" ] && echo true || echo false)"
check "capabilities array is non-empty" "$([ "$caps_count" -gt 0 ] && echo true || echo false)"
check "min_sdk_version is non-empty" "$([ "$min_sdk" != "null" ] && [ -n "$min_sdk" ] && echo true || echo false)"
check "recommended_sdk_version is non-empty" "$([ "$rec_sdk" != "null" ] && [ -n "$rec_sdk" ] && echo true || echo false)"
echo ""

# ---------------------------------------------------------------
# Test 2: health_check capability exists
# ---------------------------------------------------------------
echo "Test 2: Capability — health_check"
echo "-----------------------------------"

has_health=$(echo "$resp" | jq '[.capabilities[] | select(.name == "health_check")] | length')
check "health_check capability exists" "$([ "$has_health" -gt 0 ] && echo true || echo false)"
echo ""

# ---------------------------------------------------------------
# Test 3: version_discovery capability exists
# ---------------------------------------------------------------
echo "Test 3: Capability — version_discovery"
echo "----------------------------------------"

has_vd=$(echo "$resp" | jq '[.capabilities[] | select(.name == "version_discovery")] | length')
check "version_discovery capability exists" "$([ "$has_vd" -gt 0 ] && echo true || echo false)"
echo ""

# ---------------------------------------------------------------
# Test 4: List all capabilities
# ---------------------------------------------------------------
echo "Test 4: All Capabilities"
echo "-------------------------"

echo "$resp" | jq -r '.capabilities[] | "  - \(.name) (since \(.since)): \(.description)"'
echo ""

# ---------------------------------------------------------------
# Summary
# ---------------------------------------------------------------
echo "========================"
echo "Results: $PASS passed, $FAIL failed"
echo ""

if [ "$FAIL" -gt 0 ]; then
    echo "FAILED"
    exit 1
else
    echo "ALL PASSED"
    exit 0
fi
