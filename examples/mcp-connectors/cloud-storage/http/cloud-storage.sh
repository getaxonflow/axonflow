#!/bin/bash
# Cloud Storage Connector - HTTP API Example
#
# Tests S3 cloud storage connector operations via the Agent MCP endpoints.
# Uses MinIO as S3-compatible backend (started by docker compose).
#
# VALIDATION: This example exits with code 1 if any assertion fails.
#
# Usage:
#   docker compose up -d
#   cd examples/mcp-connectors/cloud-storage/http
#   ./cloud-storage.sh

set -euo pipefail

AGENT_URL="${AXONFLOW_AGENT_URL:-${AGENT_URL:-http://localhost:8080}}"
CLIENT_ID="${AXONFLOW_CLIENT_ID:-community}"
CLIENT_SECRET="${AXONFLOW_CLIENT_SECRET:-}"
AUTH=$(echo -n "${CLIENT_ID}:${CLIENT_SECRET}" | base64)

echo "=============================================="
echo "Cloud Storage Connector - HTTP API Example"
echo "=============================================="
echo "Agent URL: $AGENT_URL"
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

# Generate unique test key to avoid collisions
TEST_KEY="test-object-$(date +%s).txt"
TEST_CONTENT="Hello from AxonFlow cloud storage example - $(date -u +%Y-%m-%dT%H:%M:%SZ)"
BUCKET="axonflow-test-bucket"

# -----------------------------------------------
# Test 1: Verify S3 connector is registered and healthy
# -----------------------------------------------
echo "Test 1: Verify S3 connector is registered..."
echo "----------------------------------------------"

RESPONSE=$(curl -s -X GET "${AGENT_URL}/mcp/connectors" \
  -H "Authorization: Basic ${AUTH}" \
  -H "Content-Type: application/json")

HAS_S3=$(echo "$RESPONSE" | python3 -c "
import sys, json
data = json.load(sys.stdin)
connectors = data if isinstance(data, list) else data.get('connectors', [])
s3_conns = [c for c in connectors if c.get('type') == 's3']
print('true' if s3_conns else 'false')
" 2>/dev/null || echo "false")
check_result "S3 connector is registered" "$HAS_S3"

S3_HEALTHY=$(echo "$RESPONSE" | python3 -c "
import sys, json
data = json.load(sys.stdin)
connectors = data if isinstance(data, list) else data.get('connectors', [])
s3_conns = [c for c in connectors if c.get('type') == 's3']
print('true' if s3_conns and s3_conns[0].get('healthy') else 'false')
" 2>/dev/null || echo "false")
check_result "S3 connector is healthy" "$S3_HEALTHY"
echo ""

# -----------------------------------------------
# Test 2: List buckets
# -----------------------------------------------
echo "Test 2: List buckets..."
echo "----------------------------------------------"

RESPONSE=$(curl -s -X POST "${AGENT_URL}/mcp/resources/query" \
  -H "Authorization: Basic ${AUTH}" \
  -H "Content-Type: application/json" \
  -d '{"connector": "s3", "statement": "list_buckets"}')

BUCKET_FOUND=$(echo "$RESPONSE" | python3 -c "
import sys, json
data = json.load(sys.stdin)
rows = data.get('data', [])
names = [r.get('name', '') for r in rows if isinstance(r, dict)]
print('true' if '${BUCKET}' in names else 'false')
" 2>/dev/null || echo "false")
check_result "Test bucket exists in MinIO" "$BUCKET_FOUND"

HAS_POLICY_INFO=$(echo "$RESPONSE" | python3 -c "
import sys, json
data = json.load(sys.stdin)
pi = data.get('policy_info', {})
print('true' if pi.get('policies_evaluated', 0) > 0 else 'false')
" 2>/dev/null || echo "false")
check_result "Policy enforcement active on S3 queries" "$HAS_POLICY_INFO"
echo ""

# -----------------------------------------------
# Test 3: Put object
# -----------------------------------------------
echo "Test 3: Put object to S3..."
echo "----------------------------------------------"

RESPONSE=$(curl -s -X POST "${AGENT_URL}/mcp/tools/execute" \
  -H "Authorization: Basic ${AUTH}" \
  -H "Content-Type: application/json" \
  -d "{
    \"connector\": \"s3\",
    \"action\": \"put_object\",
    \"parameters\": {
      \"bucket\": \"${BUCKET}\",
      \"key\": \"${TEST_KEY}\",
      \"content\": \"${TEST_CONTENT}\",
      \"content_type\": \"text/plain\"
    }
  }")

PUT_SUCCESS=$(echo "$RESPONSE" | python3 -c "
import sys, json
data = json.load(sys.stdin)
print('true' if data.get('success') else 'false')
" 2>/dev/null || echo "false")
check_result "Put object succeeded" "$PUT_SUCCESS"

PUT_MSG=$(echo "$RESPONSE" | python3 -c "
import sys, json
data = json.load(sys.stdin)
msg = data.get('message', '')
print('true' if 'uploaded' in msg.lower() or 'success' in msg.lower() else 'false')
" 2>/dev/null || echo "false")
check_result "Put response confirms upload" "$PUT_MSG"
echo ""

# -----------------------------------------------
# Test 4: Get object and verify content integrity
# -----------------------------------------------
echo "Test 4: Get object and verify content..."
echo "----------------------------------------------"

RESPONSE=$(curl -s -X POST "${AGENT_URL}/mcp/resources/query" \
  -H "Authorization: Basic ${AUTH}" \
  -H "Content-Type: application/json" \
  -d "{
    \"connector\": \"s3\",
    \"statement\": \"get_object\",
    \"parameters\": {
      \"bucket\": \"${BUCKET}\",
      \"key\": \"${TEST_KEY}\"
    }
  }")

GET_HAS_DATA=$(echo "$RESPONSE" | python3 -c "
import sys, json
data = json.load(sys.stdin)
rows = data.get('data', [])
print('true' if len(rows) > 0 else 'false')
" 2>/dev/null || echo "false")
check_result "Get object returned data" "$GET_HAS_DATA"

CONTENT_MATCHES=$(echo "$RESPONSE" | python3 -c "
import sys, json
data = json.load(sys.stdin)
rows = data.get('data', [])
if rows and isinstance(rows[0], dict):
    content = rows[0].get('content', '')
    print('true' if 'Hello from AxonFlow cloud storage example' in content else 'false')
else:
    print('false')
" 2>/dev/null || echo "false")
check_result "Content matches what was uploaded" "$CONTENT_MATCHES"

GET_CONTENT_TYPE=$(echo "$RESPONSE" | python3 -c "
import sys, json
data = json.load(sys.stdin)
rows = data.get('data', [])
if rows and isinstance(rows[0], dict):
    ct = rows[0].get('content_type', '')
    print('true' if 'text/plain' in ct else 'false')
else:
    print('false')
" 2>/dev/null || echo "false")
check_result "Content-Type preserved as text/plain" "$GET_CONTENT_TYPE"

GET_SIZE=$(echo "$RESPONSE" | python3 -c "
import sys, json
data = json.load(sys.stdin)
rows = data.get('data', [])
if rows and isinstance(rows[0], dict):
    size = rows[0].get('content_length', 0)
    print('true' if int(size) > 0 else 'false')
else:
    print('false')
" 2>/dev/null || echo "false")
check_result "Content length is non-zero" "$GET_SIZE"
echo ""

# -----------------------------------------------
# Test 5: List objects and verify uploaded key
# -----------------------------------------------
echo "Test 5: List objects and verify key exists..."
echo "----------------------------------------------"

RESPONSE=$(curl -s -X POST "${AGENT_URL}/mcp/resources/query" \
  -H "Authorization: Basic ${AUTH}" \
  -H "Content-Type: application/json" \
  -d "{
    \"connector\": \"s3\",
    \"statement\": \"list_objects\",
    \"parameters\": {
      \"bucket\": \"${BUCKET}\",
      \"prefix\": \"test-object-\"
    }
  }")

LIST_HAS_DATA=$(echo "$RESPONSE" | python3 -c "
import sys, json
data = json.load(sys.stdin)
rows = data.get('data', [])
print('true' if len(rows) > 0 else 'false')
" 2>/dev/null || echo "false")
check_result "List objects returned results" "$LIST_HAS_DATA"

KEY_IN_LIST=$(echo "$RESPONSE" | python3 -c "
import sys, json
data = json.load(sys.stdin)
rows = data.get('data', [])
keys = [r.get('key', '') if isinstance(r, dict) else '' for r in rows]
print('true' if '${TEST_KEY}' in keys else 'false')
" 2>/dev/null || echo "false")
check_result "Uploaded object key found in listing" "$KEY_IN_LIST"
echo ""

# -----------------------------------------------
# Test 6: Head object metadata
# -----------------------------------------------
echo "Test 6: Head object metadata..."
echo "----------------------------------------------"

RESPONSE=$(curl -s -X POST "${AGENT_URL}/mcp/resources/query" \
  -H "Authorization: Basic ${AUTH}" \
  -H "Content-Type: application/json" \
  -d "{
    \"connector\": \"s3\",
    \"statement\": \"head_object\",
    \"parameters\": {
      \"bucket\": \"${BUCKET}\",
      \"key\": \"${TEST_KEY}\"
    }
  }")

HEAD_CT=$(echo "$RESPONSE" | python3 -c "
import sys, json
data = json.load(sys.stdin)
rows = data.get('data', [])
if rows and isinstance(rows[0], dict):
    ct = rows[0].get('content_type', '')
    print('true' if 'text/plain' in ct else 'false')
else:
    print('false')
" 2>/dev/null || echo "false")
check_result "Head object Content-Type is text/plain" "$HEAD_CT"

HEAD_ETAG=$(echo "$RESPONSE" | python3 -c "
import sys, json
data = json.load(sys.stdin)
rows = data.get('data', [])
if rows and isinstance(rows[0], dict):
    etag = rows[0].get('etag', '')
    print('true' if len(etag) > 0 else 'false')
else:
    print('false')
" 2>/dev/null || echo "false")
check_result "Head object has ETag" "$HEAD_ETAG"
echo ""

# -----------------------------------------------
# Test 7: Delete object
# -----------------------------------------------
echo "Test 7: Delete object..."
echo "----------------------------------------------"

RESPONSE=$(curl -s -X POST "${AGENT_URL}/mcp/tools/execute" \
  -H "Authorization: Basic ${AUTH}" \
  -H "Content-Type: application/json" \
  -d "{
    \"connector\": \"s3\",
    \"action\": \"delete_object\",
    \"parameters\": {
      \"bucket\": \"${BUCKET}\",
      \"key\": \"${TEST_KEY}\"
    }
  }")

DEL_SUCCESS=$(echo "$RESPONSE" | python3 -c "
import sys, json
data = json.load(sys.stdin)
print('true' if data.get('success') else 'false')
" 2>/dev/null || echo "false")
check_result "Delete object succeeded" "$DEL_SUCCESS"
echo ""

# -----------------------------------------------
# Test 8: Verify deletion
# -----------------------------------------------
echo "Test 8: Verify object was deleted..."
echo "----------------------------------------------"

RESPONSE=$(curl -s -X POST "${AGENT_URL}/mcp/resources/query" \
  -H "Authorization: Basic ${AUTH}" \
  -H "Content-Type: application/json" \
  -d "{
    \"connector\": \"s3\",
    \"statement\": \"list_objects\",
    \"parameters\": {
      \"bucket\": \"${BUCKET}\",
      \"prefix\": \"${TEST_KEY}\"
    }
  }")

KEY_NOT_IN_LIST=$(echo "$RESPONSE" | python3 -c "
import sys, json
data = json.load(sys.stdin)
rows = data.get('data', [])
keys = [r.get('key', '') if isinstance(r, dict) else '' for r in rows]
print('true' if '${TEST_KEY}' not in keys else 'false')
" 2>/dev/null || echo "false")
check_result "Deleted object no longer in listing" "$KEY_NOT_IN_LIST"
echo ""

# -----------------------------------------------
# Test 9: Enterprise connector guard
# -----------------------------------------------
echo "Test 9: Enterprise connectors not available in community..."
echo "----------------------------------------------"

RESPONSE=$(curl -s -X POST "${AGENT_URL}/mcp/resources/query" \
  -H "Authorization: Basic ${AUTH}" \
  -H "Content-Type: application/json" \
  -d '{"connector": "salesforce", "statement": "list"}')

SALESFORCE_BLOCKED=$(echo "$RESPONSE" | python3 -c "
import sys, json
data = json.load(sys.stdin)
error = data.get('error', '')
success = data.get('success', True)
print('true' if not success or 'enterprise' in error.lower() or 'not found' in error.lower() or 'no creator' in error.lower() else 'false')
" 2>/dev/null || echo "true")
check_result "Salesforce connector blocked in community" "$SALESFORCE_BLOCKED"
echo ""

# -----------------------------------------------
# Results
# -----------------------------------------------
echo "=============================================="
TOTAL=$((PASS + FAIL))
echo "Results: ${PASS}/${TOTAL} assertions passed"

if [ "$FAIL" -gt 0 ]; then
    echo "FAILED: ${FAIL} assertions failed"
    exit 1
fi

echo "ALL ASSERTIONS PASSED"
echo "=============================================="
