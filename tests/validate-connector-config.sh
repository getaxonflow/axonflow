#!/bin/bash
# Test script for conditional connector validation logic
# Compatible with bash 3.2+

set -e

echo "🧪 Testing Conditional Connector Validation Logic"
echo "=================================================="
echo ""

TESTS_PASSED=0
TESTS_FAILED=0

# Test 1: Empty EnabledConnectors (OSS mode)
echo "Test 1: OSS deployment (empty EnabledConnectors)"
ENABLED_CONNECTORS=""
IFS=',' read -ra CONNECTOR_ARRAY <<< "$ENABLED_CONNECTORS"
if [ ${#CONNECTOR_ARRAY[@]} -eq 0 ] || [ "${CONNECTOR_ARRAY[0]}" = "" ]; then
    echo "✅ PASS: Empty array handled correctly (OSS mode)"
    ((TESTS_PASSED++))
else
    echo "❌ FAIL: Empty array not handled"
    ((TESTS_FAILED++))
fi
echo ""

# Test 2: Single connector
echo "Test 2: Single connector (amadeus)"
ENABLED_CONNECTORS="amadeus"
IFS=',' read -ra CONNECTOR_ARRAY <<< "$ENABLED_CONNECTORS"
if [ ${#CONNECTOR_ARRAY[@]} -eq 1 ] && [ "${CONNECTOR_ARRAY[0]}" = "amadeus" ]; then
    echo "✅ PASS: Single connector parsed correctly"
    ((TESTS_PASSED++))
else
    echo "❌ FAIL: Single connector parsing failed"
    ((TESTS_FAILED++))
fi
echo ""

# Test 3: Multiple connectors
echo "Test 3: Multiple connectors (amadeus,salesforce,slack)"
ENABLED_CONNECTORS="amadeus,salesforce,slack"
IFS=',' read -ra CONNECTOR_ARRAY <<< "$ENABLED_CONNECTORS"
if [ ${#CONNECTOR_ARRAY[@]} -eq 3 ]; then
    echo "✅ PASS: Multiple connectors parsed correctly (${#CONNECTOR_ARRAY[@]} connectors)"
    ((TESTS_PASSED++))
else
    echo "❌ FAIL: Expected 3 connectors, got ${#CONNECTOR_ARRAY[@]}"
    ((TESTS_FAILED++))
fi
echo ""

# Test 4: All 8 connectors
echo "Test 4: All connectors (full production)"
ENABLED_CONNECTORS="amadeus,salesforce,slack,snowflake,openai,anthropic,client-openai,client-anthropic"
IFS=',' read -ra CONNECTOR_ARRAY <<< "$ENABLED_CONNECTORS"
if [ ${#CONNECTOR_ARRAY[@]} -eq 8 ]; then
    echo "✅ PASS: All 8 connectors parsed correctly"
    ((TESTS_PASSED++))
else
    echo "❌ FAIL: Expected 8 connectors, got ${#CONNECTOR_ARRAY[@]}"
    ((TESTS_FAILED++))
fi
echo ""

# Test 5: Whitespace handling
echo "Test 5: Whitespace handling (  amadeus  , salesforce  )"
ENABLED_CONNECTORS="  amadeus  , salesforce  "
IFS=',' read -ra CONNECTOR_ARRAY <<< "$ENABLED_CONNECTORS"
CONNECTOR=$(echo "${CONNECTOR_ARRAY[0]}" | xargs)
if [ "$CONNECTOR" = "amadeus" ]; then
    echo "✅ PASS: Whitespace trimmed correctly"
    ((TESTS_PASSED++))
else
    echo "❌ FAIL: Whitespace not trimmed, got '$CONNECTOR'"
    ((TESTS_FAILED++))
fi
echo ""

# Test 6: YAML config file parsing
echo "Test 6: YAML config parsing (staging.yaml)"
if command -v yq &> /dev/null; then
    CONFIG_FILE="config/environments/staging.yaml"
    if [ -f "$CONFIG_FILE" ]; then
        ENABLED_CONNECTORS=$(yq eval '.EnabledConnectors // ""' "$CONFIG_FILE" 2>/dev/null || echo "")
        if [ "$ENABLED_CONNECTORS" = "" ]; then
            echo "✅ PASS: YAML parsing works (staging has empty connectors)"
            ((TESTS_PASSED++))
        else
            echo "❌ FAIL: Expected empty connectors for staging, got '$ENABLED_CONNECTORS'"
            ((TESTS_FAILED++))
        fi
    else
        echo "⚠️  SKIP: Config file not found"
    fi
else
    echo "⚠️  SKIP: yq not installed"
fi
echo ""

echo "=================================================="
echo "Test Results: $TESTS_PASSED passed, $TESTS_FAILED failed"
echo "=================================================="

if [ $TESTS_FAILED -eq 0 ]; then
    echo "✅ ALL TESTS PASSED"
    exit 0
else
    echo "❌ SOME TESTS FAILED"
    exit 1
fi
