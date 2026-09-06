#!/bin/bash
#
# Test all policy management examples across all SDKs
#
# Prerequisites:
# - AxonFlow running locally (docker compose up -d)
# - Node.js 18+, Python 3.10+, Go 1.21+, Java 17+
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PASSED=0
FAILED=0

echo "=========================================="
echo "AxonFlow Policy Examples - Test All"
echo "=========================================="
echo ""

# Check if AxonFlow is running
echo "Checking AxonFlow connectivity..."
if ! curl -s -o /dev/null -w "" http://localhost:8080/health 2>/dev/null; then
    echo "ERROR: AxonFlow is not running on localhost:8080"
    echo "Start it with: docker compose up -d"
    exit 1
fi
echo "AxonFlow is running."
echo ""

# TypeScript Examples
echo "=========================================="
echo "Testing TypeScript Examples"
echo "=========================================="
cd "$SCRIPT_DIR/typescript"

if [ ! -d "node_modules" ]; then
    echo "Installing dependencies..."
    npm install --silent
fi

echo "Running create-custom-policy.ts..."
if npx tsx create-custom-policy.ts; then
    echo "PASS: create-custom-policy.ts"
    ((PASSED++))
else
    echo "FAIL: create-custom-policy.ts"
    ((FAILED++))
fi

echo "Running list-and-filter.ts..."
if npx tsx list-and-filter.ts; then
    echo "PASS: list-and-filter.ts"
    ((PASSED++))
else
    echo "FAIL: list-and-filter.ts"
    ((FAILED++))
fi

echo "Running test-pattern.ts..."
if npx tsx test-pattern.ts; then
    echo "PASS: test-pattern.ts"
    ((PASSED++))
else
    echo "FAIL: test-pattern.ts"
    ((FAILED++))
fi

# Python Examples
echo ""
echo "=========================================="
echo "Testing Python Examples"
echo "=========================================="
cd "$SCRIPT_DIR/python"

PYTHON_CMD="${PYTHON:-python3}"
echo "Installing dependencies..."
$PYTHON_CMD -m pip install -q -r requirements.txt 2>/dev/null || $PYTHON_CMD -m pip install -r requirements.txt

echo "Running create_custom_policy.py..."
if $PYTHON_CMD create_custom_policy.py; then
    echo "PASS: create_custom_policy.py"
    ((PASSED++))
else
    echo "FAIL: create_custom_policy.py"
    ((FAILED++))
fi

echo "Running list_and_filter.py..."
if $PYTHON_CMD list_and_filter.py; then
    echo "PASS: list_and_filter.py"
    ((PASSED++))
else
    echo "FAIL: list_and_filter.py"
    ((FAILED++))
fi

echo "Running test_pattern.py..."
if $PYTHON_CMD test_pattern.py; then
    echo "PASS: test_pattern.py"
    ((PASSED++))
else
    echo "FAIL: test_pattern.py"
    ((FAILED++))
fi

# Go Examples
echo ""
echo "=========================================="
echo "Testing Go Examples"
echo "=========================================="
cd "$SCRIPT_DIR/go"

echo "Running create_custom_policy.go..."
if go run create_custom_policy.go; then
    echo "PASS: create_custom_policy.go"
    ((PASSED++))
else
    echo "FAIL: create_custom_policy.go"
    ((FAILED++))
fi

echo "Running list_and_filter.go..."
if go run list_and_filter.go; then
    echo "PASS: list_and_filter.go"
    ((PASSED++))
else
    echo "FAIL: list_and_filter.go"
    ((FAILED++))
fi

echo "Running test_pattern.go..."
if go run test_pattern.go; then
    echo "PASS: test_pattern.go"
    ((PASSED++))
else
    echo "FAIL: test_pattern.go"
    ((FAILED++))
fi

# Java Examples
echo ""
echo "=========================================="
echo "Testing Java Examples"
echo "=========================================="
cd "$SCRIPT_DIR/java"

echo "Compiling Java examples..."
mvn -q compile

echo "Running CreateCustomPolicy..."
if mvn -q exec:java -Dexec.mainClass="com.getaxonflow.examples.policies.CreateCustomPolicy"; then
    echo "PASS: CreateCustomPolicy.java"
    ((PASSED++))
else
    echo "FAIL: CreateCustomPolicy.java"
    ((FAILED++))
fi

echo "Running ListAndFilter..."
if mvn -q exec:java -Dexec.mainClass="com.getaxonflow.examples.policies.ListAndFilter"; then
    echo "PASS: ListAndFilter.java"
    ((PASSED++))
else
    echo "FAIL: ListAndFilter.java"
    ((FAILED++))
fi

echo "Running TestPattern..."
if mvn -q exec:java -Dexec.mainClass="com.getaxonflow.examples.policies.TestPattern"; then
    echo "PASS: TestPattern.java"
    ((PASSED++))
else
    echo "FAIL: TestPattern.java"
    ((FAILED++))
fi

# Summary
echo ""
echo "=========================================="
echo "Test Summary"
echo "=========================================="
echo "Passed: $PASSED"
echo "Failed: $FAILED"
echo ""

if [ $FAILED -gt 0 ]; then
    echo "Some tests failed!"
    exit 1
else
    echo "All tests passed!"
    exit 0
fi
