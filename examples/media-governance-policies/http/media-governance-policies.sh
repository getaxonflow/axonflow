#!/bin/bash
# AxonFlow Media Governance Policies - HTTP/curl
#
# Demonstrates media governance policy management using raw HTTP requests:
#   - Listing system media policies
#   - Creating and deleting custom media policies
#   - Policy toggle lifecycle (enable/disable)
#   - Per-tenant media governance configuration (Enterprise)
#   - Verifying non-media requests are unaffected
#
# Prerequisites:
#   - AxonFlow Agent running at http://localhost:8080
#   - AxonFlow Agent running at http://localhost:8080
#   - curl and jq installed
#
# API Endpoints demonstrated:
#   GET    /api/v1/policies/dynamic?type=media  - List dynamic policies (inc. system media)
#   POST   /api/v1/policies                    - Create media policy
#   PUT    /api/v1/policies/{id}               - Update policy (enable/disable)
#   DELETE /api/v1/policies/{id}               - Delete policy
#   GET    /api/v1/media-governance/status      - Feature availability
#   GET    /api/v1/media-governance/config      - Tenant media config
#   PUT    /api/v1/media-governance/config      - Update tenant media config
#   POST   /api/request                         - Process request (Agent)
#
# Usage:
#   chmod +x media-governance-policies.sh
#   ./media-governance-policies.sh

set -e

# Configuration
AGENT_URL="${AXONFLOW_AGENT_URL:-${AXONFLOW_ENDPOINT:-http://localhost:8080}}"
CLIENT_ID="${AXONFLOW_CLIENT_ID:-community}"
CLIENT_SECRET="${AXONFLOW_CLIENT_SECRET:-demo-secret}"
AUTH_B64=$(printf '%s:%s' "$CLIENT_ID" "$CLIENT_SECRET" | base64)
TENANT_ID="${AXONFLOW_TENANT:-demo}"

# Auth: include Basic auth if credentials are set
CURL_AUTH=()
if [ -n "${AXONFLOW_CLIENT_ID:-}" ] && [ -n "${AXONFLOW_CLIENT_SECRET:-}" ]; then
  CURL_AUTH=(-u "${AXONFLOW_CLIENT_ID}:${AXONFLOW_CLIENT_SECRET}")
fi
acurl() { curl "${CURL_AUTH[@]}" "$@"; }

# Minimal valid 1x1 white pixel JPEG encoded as base64
TEST_IMAGE_BASE64="/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAgGBgcGBQgHBwcJCQgKDBQNDAsLDBkSEw8UHRofHh0aHBwgJC4nICIsIxwcKDcpLDAxNDQ0Hyc5PTgyPC4zNDL/2wBDAQkJCQwLDBgNDRgyIRwhMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjL/wAARCAABAAEDASIAAhEBAxEB/8QAFAABAAAAAAAAAAAAAAAAAAAACf/EABQQAQAAAAAAAAAAAAAAAAAAAAD/xAAUAQEAAAAAAAAAAAAAAAAAAAAA/8QAFBEBAAAAAAAAAAAAAAAAAAAAAP/aAAwDAQACEQMRAD8AbwA//9k="

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

FAILURES=0

echo "AxonFlow Media Governance Policies - HTTP/curl"
echo "================================================"
echo ""
echo "Agent URL:        $AGENT_URL"
echo "Tenant ID:        $TENANT_ID"
echo ""

assert_pass() {
    local condition="$1"
    local message="$2"
    if [ "$condition" = "true" ]; then
        echo -e "   ${GREEN}PASS:${NC} $message"
    else
        echo -e "   ${RED}FAIL:${NC} $message"
        FAILURES=$((FAILURES + 1))
    fi
}

# ========================================
# Test 1: Verify system media policies exist
# ========================================
echo -e "${CYAN}Test 1: Verify system media policies exist${NC}"
echo "  GET $AGENT_URL/api/v1/policies/dynamic?type=media&limit=100"
echo ""

RESPONSE=$(acurl -s -w "\n%{http_code}" -X GET \
    "$AGENT_URL/api/v1/policies/dynamic?type=media&limit=100" \
)

HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | sed '$d')

assert_pass "$([ "$HTTP_CODE" = "200" ] && echo true || echo false)" \
    "HTTP status is 200 (got $HTTP_CODE)"

# Count policies with sys_media_ prefix
SYS_MEDIA_COUNT=$(echo "$BODY" | jq '[.[] | select(.id | startswith("sys_media_"))] | length')
assert_pass "$([ "$SYS_MEDIA_COUNT" -ge 5 ] && echo true || echo false)" \
    "At least 5 system media policies found (got $SYS_MEDIA_COUNT)"

# Verify expected categories
MEDIA_SAFETY_COUNT=$(echo "$BODY" | jq '[.[] | select(.id | startswith("sys_media_")) | select(.category == "media-safety")] | length')
assert_pass "$([ "$MEDIA_SAFETY_COUNT" -ge 2 ] && echo true || echo false)" \
    "media-safety category has >= 2 policies (got $MEDIA_SAFETY_COUNT)"

MEDIA_BIOMETRIC_COUNT=$(echo "$BODY" | jq '[.[] | select(.id | startswith("sys_media_")) | select(.category == "media-biometric")] | length')
assert_pass "$([ "$MEDIA_BIOMETRIC_COUNT" -ge 1 ] && echo true || echo false)" \
    "media-biometric category has >= 1 policy (got $MEDIA_BIOMETRIC_COUNT)"

MEDIA_PII_COUNT=$(echo "$BODY" | jq '[.[] | select(.id | startswith("sys_media_")) | select(.category == "media-pii")] | length')
assert_pass "$([ "$MEDIA_PII_COUNT" -ge 1 ] && echo true || echo false)" \
    "media-pii category has >= 1 policy (got $MEDIA_PII_COUNT)"

MEDIA_DOCUMENT_COUNT=$(echo "$BODY" | jq '[.[] | select(.id | startswith("sys_media_")) | select(.category == "media-document")] | length')
assert_pass "$([ "$MEDIA_DOCUMENT_COUNT" -ge 1 ] && echo true || echo false)" \
    "media-document category has >= 1 policy (got $MEDIA_DOCUMENT_COUNT)"

# Print discovered policies
echo ""
echo "  System media policies:"
echo "$BODY" | jq -r '.[] | select(.id | startswith("sys_media_")) | "    - \(.id): \(.name) [\(.category)]"' 2>/dev/null || echo "    (none found)"
echo ""

# ========================================
# Test 2: System NSFW policy — clean image passes
# ========================================
echo -e "${CYAN}Test 2: System NSFW policy evaluation -- clean image passes${NC}"
echo "  POST $AGENT_URL/api/request (1x1 white JPEG + query)"
echo ""

RESPONSE2=$(curl -s -w "\n%{http_code}" -X POST "$AGENT_URL/api/request" \
    -H "Content-Type: application/json" \
    -H "Authorization: Basic $AUTH_B64" \
    -d "{
        \"query\": \"Describe this image\",
        \"user_token\": \"media-policy-user\",
        \"client_id\": \"$CLIENT_ID\",
        \"request_type\": \"chat\",
        \"media\": [{
            \"source\": \"base64\",
            \"mime_type\": \"image/jpeg\",
            \"base64_data\": \"$TEST_IMAGE_BASE64\"
        }]
    }")

HTTP_CODE2=$(echo "$RESPONSE2" | tail -1)
BODY2=$(echo "$RESPONSE2" | sed '$d')

SUCCESS2=$(echo "$BODY2" | jq -r '.success // false')
assert_pass "$SUCCESS2" "Response is successful (HTTP $HTTP_CODE2)"

BLOCKED2=$(echo "$BODY2" | jq -r '.blocked // false')
assert_pass "$([ "$BLOCKED2" = "false" ] && echo true || echo false)" \
    "Clean image is NOT blocked (blocked=$BLOCKED2)"

HAS_MEDIA_ANALYSIS2=$(echo "$BODY2" | jq 'has("media_analysis") and .media_analysis != null')
if [ "$HAS_MEDIA_ANALYSIS2" = "true" ]; then
    echo -e "   ${GREEN}PASS:${NC} media_analysis present (pipeline active)"
    echo "   NSFW score: $(echo "$BODY2" | jq -r '.media_analysis.results[0].nsfw_score // "N/A"')"
    echo "   Content safe: $(echo "$BODY2" | jq -r '.media_analysis.results[0].content_safe // "N/A"')"
else
    echo -e "   ${YELLOW}WARNING: media_analysis absent -- media governance pipeline not active (requires platform v4.4.0+ with analyzers)${NC}"
fi
echo ""

# ========================================
# Test 3: Custom media policy — create and verify
# ========================================
echo -e "${CYAN}Test 3: Custom media policy -- create and verify${NC}"
echo ""

# 3a. Create a custom media policy: block if has_faces == true
echo "  3a. Creating custom media policy: block if media.has_faces == true"
CREATE_RESPONSE=$(acurl -s -w "\n%{http_code}" -X POST "$AGENT_URL/api/v1/policies" \
    -H "Content-Type: application/json" \
    -d '{
        "name": "test-face-block-http-example",
        "description": "Blocks images containing faces (HTTP example test policy)",
        "type": "media",
        "category": "media-safety",
        "conditions": [
            {
                "field": "media.has_faces",
                "operator": "equals",
                "value": true
            }
        ],
        "actions": [
            {
                "type": "block",
                "config": {
                    "message": "Media blocked: faces detected in image"
                }
            }
        ],
        "priority": 100,
        "enabled": true
    }')

CREATE_HTTP_CODE=$(echo "$CREATE_RESPONSE" | tail -1)
CREATE_BODY=$(echo "$CREATE_RESPONSE" | sed '$d')

CREATED_POLICY_ID=$(echo "$CREATE_BODY" | jq -r '.policy.id // empty')
assert_pass "$([ "$CREATE_HTTP_CODE" = "201" ] && echo true || echo false)" \
    "Policy created (HTTP $CREATE_HTTP_CODE)"
assert_pass "$([ -n "$CREATED_POLICY_ID" ] && echo true || echo false)" \
    "Policy ID returned: ${CREATED_POLICY_ID:-<none>}"

# 3b. Verify it appears in the list
echo ""
echo "  3b. Verifying policy appears in list"
LIST_RESPONSE=$(acurl -s "$AGENT_URL/api/v1/policies/dynamic?type=media&limit=100" \
)

if [ -n "$CREATED_POLICY_ID" ]; then
    FOUND_IN_LIST=$(echo "$LIST_RESPONSE" | jq --arg id "$CREATED_POLICY_ID" '[.[] | select(.id == $id)] | length')
    assert_pass "$([ "$FOUND_IN_LIST" -ge 1 ] && echo true || echo false)" \
        "Created policy found in list (count=$FOUND_IN_LIST)"
else
    echo -e "   ${YELLOW}SKIP: No policy ID to verify${NC}"
fi

# 3c. Send a 1x1 image request — should NOT be blocked (no faces in a 1px image)
echo ""
echo "  3c. Sending 1x1 image request (no faces expected)"
PROCESS_RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$AGENT_URL/api/request" \
    -H "Content-Type: application/json" \
    -H "Authorization: Basic $AUTH_B64" \
    -d "{
        \"query\": \"Describe this image\",
        \"user_token\": \"media-policy-user\",
        \"client_id\": \"$CLIENT_ID\",
        \"request_type\": \"chat\",
        \"media\": [{
            \"source\": \"base64\",
            \"mime_type\": \"image/jpeg\",
            \"base64_data\": \"$TEST_IMAGE_BASE64\"
        }]
    }")

PROCESS_HTTP_CODE=$(echo "$PROCESS_RESPONSE" | tail -1)
PROCESS_BODY=$(echo "$PROCESS_RESPONSE" | sed '$d')

PROCESS_SUCCESS=$(echo "$PROCESS_BODY" | jq -r '.success // false')
assert_pass "$PROCESS_SUCCESS" "1x1 image request succeeded (HTTP $PROCESS_HTTP_CODE)"

PROCESS_BLOCKED=$(echo "$PROCESS_BODY" | jq -r '.blocked // false')
assert_pass "$([ "$PROCESS_BLOCKED" = "false" ] && echo true || echo false)" \
    "1x1 image NOT blocked by face policy (no faces in 1px image)"

# 3d. Cleanup — delete the custom policy
echo ""
echo "  3d. Cleaning up: deleting custom policy"
if [ -n "$CREATED_POLICY_ID" ]; then
    DELETE_RESPONSE=$(acurl -s -w "\n%{http_code}" -X DELETE \
        "$AGENT_URL/api/v1/policies/$CREATED_POLICY_ID" \
    )
    DELETE_HTTP_CODE=$(echo "$DELETE_RESPONSE" | tail -1)
    assert_pass "$([ "$DELETE_HTTP_CODE" = "204" ] && echo true || echo false)" \
        "Policy deleted (HTTP $DELETE_HTTP_CODE)"
else
    echo -e "   ${YELLOW}SKIP: No policy to delete${NC}"
fi
echo ""

# ========================================
# Test 4: Media governance config — read status
# ========================================
echo -e "${CYAN}Test 4: Media governance config -- read status${NC}"
echo ""

# 4a. GET /api/v1/media-governance/status
echo "  4a. GET $AGENT_URL/api/v1/media-governance/status"
STATUS_RESPONSE=$(acurl -s -w "\n%{http_code}" -X GET \
    "$AGENT_URL/api/v1/media-governance/status" \
)

STATUS_HTTP_CODE=$(echo "$STATUS_RESPONSE" | tail -1)
STATUS_BODY=$(echo "$STATUS_RESPONSE" | sed '$d')

assert_pass "$([ "$STATUS_HTTP_CODE" = "200" ] && echo true || echo false)" \
    "Status endpoint returned HTTP 200 (got $STATUS_HTTP_CODE)"

HAS_AVAILABLE=$(echo "$STATUS_BODY" | jq 'has("available")')
assert_pass "$HAS_AVAILABLE" "Response contains 'available' field"

HAS_TIER=$(echo "$STATUS_BODY" | jq 'has("tier")')
assert_pass "$HAS_TIER" "Response contains 'tier' field"

TIER_VALUE=$(echo "$STATUS_BODY" | jq -r '.tier // "unknown"')
AVAILABLE_VALUE=$(echo "$STATUS_BODY" | jq -r 'if .available == null then "unknown" else (.available | tostring) end')
PER_TENANT=$(echo "$STATUS_BODY" | jq -r 'if .per_tenant_control == null then "unknown" else (.per_tenant_control | tostring) end')
echo "   Tier: $TIER_VALUE | Available: $AVAILABLE_VALUE | Per-tenant control: $PER_TENANT"

# 4b. GET /api/v1/media-governance/config
echo ""
echo "  4b. GET $AGENT_URL/api/v1/media-governance/config"
CONFIG_RESPONSE=$(acurl -s -w "\n%{http_code}" -X GET \
    "$AGENT_URL/api/v1/media-governance/config" \
)

CONFIG_HTTP_CODE=$(echo "$CONFIG_RESPONSE" | tail -1)
CONFIG_BODY=$(echo "$CONFIG_RESPONSE" | sed '$d')

assert_pass "$([ "$CONFIG_HTTP_CODE" = "200" ] && echo true || echo false)" \
    "Config endpoint returned HTTP 200 (got $CONFIG_HTTP_CODE)"

HAS_ENABLED=$(echo "$CONFIG_BODY" | jq 'has("enabled")')
assert_pass "$HAS_ENABLED" "Response contains 'enabled' field"

HAS_TENANT=$(echo "$CONFIG_BODY" | jq 'has("tenant_id")')
assert_pass "$HAS_TENANT" "Response contains 'tenant_id' field"

CONFIG_ENABLED=$(echo "$CONFIG_BODY" | jq -r 'if .enabled == null then "unknown" else (.enabled | tostring) end')
CONFIG_TENANT=$(echo "$CONFIG_BODY" | jq -r '.tenant_id // "unknown"')
echo "   Tenant: $CONFIG_TENANT | Enabled: $CONFIG_ENABLED"
echo ""

# ========================================
# Test 5: Policy toggle lifecycle
# ========================================
echo -e "${CYAN}Test 5: Policy toggle lifecycle (create -> disable -> re-enable -> delete)${NC}"
echo ""

# 5a. Create a media policy
echo "  5a. Creating media policy: media.nsfw_score > 0.5 -> block"
TOGGLE_CREATE_RESPONSE=$(acurl -s -w "\n%{http_code}" -X POST "$AGENT_URL/api/v1/policies" \
    -H "Content-Type: application/json" \
    -d '{
        "name": "test-nsfw-toggle-http-example",
        "description": "NSFW threshold policy for toggle lifecycle test",
        "type": "media",
        "category": "media-safety",
        "conditions": [
            {
                "field": "media.nsfw_score",
                "operator": "greater_than",
                "value": 0.5
            }
        ],
        "actions": [
            {
                "type": "block",
                "config": {
                    "message": "Media blocked: NSFW score exceeds threshold (> 0.5)"
                }
            }
        ],
        "priority": 200,
        "enabled": true
    }')

TOGGLE_CREATE_HTTP=$(echo "$TOGGLE_CREATE_RESPONSE" | tail -1)
TOGGLE_CREATE_BODY=$(echo "$TOGGLE_CREATE_RESPONSE" | sed '$d')
TOGGLE_POLICY_ID=$(echo "$TOGGLE_CREATE_BODY" | jq -r '.policy.id // empty')

assert_pass "$([ "$TOGGLE_CREATE_HTTP" = "201" ] && echo true || echo false)" \
    "Policy created (HTTP $TOGGLE_CREATE_HTTP)"
assert_pass "$([ -n "$TOGGLE_POLICY_ID" ] && echo true || echo false)" \
    "Policy ID: ${TOGGLE_POLICY_ID:-<none>}"

TOGGLE_ENABLED=$(echo "$TOGGLE_CREATE_BODY" | jq -r 'if .policy.enabled == null then "unknown" else (.policy.enabled | tostring) end')
assert_pass "$([ "$TOGGLE_ENABLED" = "true" ] && echo true || echo false)" \
    "Policy initially enabled ($TOGGLE_ENABLED)"

# 5b. Disable the policy
echo ""
echo "  5b. Disabling policy (PUT enabled=false)"
if [ -n "$TOGGLE_POLICY_ID" ]; then
    DISABLE_RESPONSE=$(acurl -s -w "\n%{http_code}" -X PUT \
        "$AGENT_URL/api/v1/policies/$TOGGLE_POLICY_ID" \
        -H "Content-Type: application/json" \
        -d '{"enabled": false}')

    DISABLE_HTTP=$(echo "$DISABLE_RESPONSE" | tail -1)
    DISABLE_BODY=$(echo "$DISABLE_RESPONSE" | sed '$d')

    assert_pass "$([ "$DISABLE_HTTP" = "200" ] && echo true || echo false)" \
        "Update returned HTTP 200 (got $DISABLE_HTTP)"

    DISABLED_STATE=$(echo "$DISABLE_BODY" | jq -r 'if .policy.enabled == null then "unknown" else (.policy.enabled | tostring) end')
    assert_pass "$([ "$DISABLED_STATE" = "false" ] && echo true || echo false)" \
        "Policy is now disabled (enabled=$DISABLED_STATE)"
else
    echo -e "   ${YELLOW}SKIP: No policy ID for toggle test${NC}"
fi

# 5c. Re-enable the policy
echo ""
echo "  5c. Re-enabling policy (PUT enabled=true)"
if [ -n "$TOGGLE_POLICY_ID" ]; then
    ENABLE_RESPONSE=$(acurl -s -w "\n%{http_code}" -X PUT \
        "$AGENT_URL/api/v1/policies/$TOGGLE_POLICY_ID" \
        -H "Content-Type: application/json" \
        -d '{"enabled": true}')

    ENABLE_HTTP=$(echo "$ENABLE_RESPONSE" | tail -1)
    ENABLE_BODY=$(echo "$ENABLE_RESPONSE" | sed '$d')

    assert_pass "$([ "$ENABLE_HTTP" = "200" ] && echo true || echo false)" \
        "Update returned HTTP 200 (got $ENABLE_HTTP)"

    ENABLED_STATE=$(echo "$ENABLE_BODY" | jq -r 'if .policy.enabled == null then "unknown" else (.policy.enabled | tostring) end')
    assert_pass "$([ "$ENABLED_STATE" = "true" ] && echo true || echo false)" \
        "Policy is now re-enabled (enabled=$ENABLED_STATE)"
else
    echo -e "   ${YELLOW}SKIP: No policy ID for toggle test${NC}"
fi

# 5d. Cleanup
echo ""
echo "  5d. Cleaning up: deleting toggle test policy"
if [ -n "$TOGGLE_POLICY_ID" ]; then
    TOGGLE_DELETE_RESPONSE=$(acurl -s -w "\n%{http_code}" -X DELETE \
        "$AGENT_URL/api/v1/policies/$TOGGLE_POLICY_ID" \
    )
    TOGGLE_DELETE_HTTP=$(echo "$TOGGLE_DELETE_RESPONSE" | tail -1)
    assert_pass "$([ "$TOGGLE_DELETE_HTTP" = "204" ] && echo true || echo false)" \
        "Policy deleted (HTTP $TOGGLE_DELETE_HTTP)"
else
    echo -e "   ${YELLOW}SKIP: No policy to delete${NC}"
fi
echo ""

# ========================================
# Test 6: Media governance disable/enable (Enterprise only)
# ========================================
echo -e "${CYAN}Test 6: Media governance disable/enable (per-tenant config)${NC}"
echo ""

# Check if per-tenant control is available (Enterprise only)
if [ "$PER_TENANT" = "true" ]; then
    echo "  Enterprise mode detected -- testing per-tenant media governance toggle"
    echo ""

    # 6a. Disable media governance for this tenant
    echo "  6a. Disabling media governance (PUT enabled=false)"
    MG_DISABLE_RESPONSE=$(acurl -s -w "\n%{http_code}" -X PUT \
        "$AGENT_URL/api/v1/media-governance/config" \
        -H "Content-Type: application/json" \
        -d '{"enabled": false}')

    MG_DISABLE_HTTP=$(echo "$MG_DISABLE_RESPONSE" | tail -1)
    MG_DISABLE_BODY=$(echo "$MG_DISABLE_RESPONSE" | sed '$d')

    assert_pass "$([ "$MG_DISABLE_HTTP" = "200" ] && echo true || echo false)" \
        "Config update returned HTTP 200 (got $MG_DISABLE_HTTP)"

    MG_DISABLED_STATE=$(echo "$MG_DISABLE_BODY" | jq -r 'if .enabled == null then "unknown" else (.enabled | tostring) end')
    assert_pass "$([ "$MG_DISABLED_STATE" = "false" ] && echo true || echo false)" \
        "Media governance disabled (enabled=$MG_DISABLED_STATE)"

    # 6b. Process request with media — media_analysis should be absent
    echo ""
    echo "  6b. Sending image request with media governance disabled"
    MG_OFF_RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$AGENT_URL/api/request" \
        -H "Content-Type: application/json" \
        -H "Authorization: Basic $AUTH_B64" \
        -d "{
            \"query\": \"Describe this image\",
            \"user_token\": \"media-policy-user\",
            \"client_id\": \"$CLIENT_ID\",
            \"request_type\": \"chat\",
            \"media\": [{
                \"source\": \"base64\",
                \"mime_type\": \"image/jpeg\",
                \"base64_data\": \"$TEST_IMAGE_BASE64\"
            }]
        }")

    MG_OFF_HTTP=$(echo "$MG_OFF_RESPONSE" | tail -1)
    MG_OFF_BODY=$(echo "$MG_OFF_RESPONSE" | sed '$d')

    MG_OFF_SUCCESS=$(echo "$MG_OFF_BODY" | jq -r '.success // false')
    assert_pass "$MG_OFF_SUCCESS" "Request still succeeds (HTTP $MG_OFF_HTTP)"

    MG_OFF_HAS_ANALYSIS=$(echo "$MG_OFF_BODY" | jq 'has("media_analysis") and .media_analysis != null')
    assert_pass "$([ "$MG_OFF_HAS_ANALYSIS" != "true" ] && echo true || echo false)" \
        "media_analysis absent when governance disabled"

    # 6c. Re-enable media governance
    echo ""
    echo "  6c. Re-enabling media governance (PUT enabled=true)"
    MG_ENABLE_RESPONSE=$(acurl -s -w "\n%{http_code}" -X PUT \
        "$AGENT_URL/api/v1/media-governance/config" \
        -H "Content-Type: application/json" \
        -d '{"enabled": true}')

    MG_ENABLE_HTTP=$(echo "$MG_ENABLE_RESPONSE" | tail -1)
    MG_ENABLE_BODY=$(echo "$MG_ENABLE_RESPONSE" | sed '$d')

    assert_pass "$([ "$MG_ENABLE_HTTP" = "200" ] && echo true || echo false)" \
        "Config update returned HTTP 200 (got $MG_ENABLE_HTTP)"

    MG_ENABLED_STATE=$(echo "$MG_ENABLE_BODY" | jq -r 'if .enabled == null then "unknown" else (.enabled | tostring) end')
    assert_pass "$([ "$MG_ENABLED_STATE" = "true" ] && echo true || echo false)" \
        "Media governance re-enabled (enabled=$MG_ENABLED_STATE)"

    # 6d. Verify media_analysis returns after re-enable
    echo ""
    echo "  6d. Sending image request with media governance re-enabled"
    MG_ON_RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$AGENT_URL/api/request" \
        -H "Content-Type: application/json" \
        -H "Authorization: Basic $AUTH_B64" \
        -d "{
            \"query\": \"Describe this image\",
            \"user_token\": \"media-policy-user\",
            \"client_id\": \"$CLIENT_ID\",
            \"request_type\": \"chat\",
            \"media\": [{
                \"source\": \"base64\",
                \"mime_type\": \"image/jpeg\",
                \"base64_data\": \"$TEST_IMAGE_BASE64\"
            }]
        }")

    MG_ON_HTTP=$(echo "$MG_ON_RESPONSE" | tail -1)
    MG_ON_BODY=$(echo "$MG_ON_RESPONSE" | sed '$d')

    MG_ON_SUCCESS=$(echo "$MG_ON_BODY" | jq -r '.success // false')
    assert_pass "$MG_ON_SUCCESS" "Request succeeds after re-enable (HTTP $MG_ON_HTTP)"

    MG_ON_HAS_ANALYSIS=$(echo "$MG_ON_BODY" | jq 'has("media_analysis") and .media_analysis != null')
    if [ "$MG_ON_HAS_ANALYSIS" = "true" ]; then
        echo -e "   ${GREEN}PASS:${NC} media_analysis present after re-enable"
    else
        echo -e "   ${YELLOW}WARNING: media_analysis absent after re-enable (analyzers may not be active in this environment)${NC}"
    fi
else
    echo -e "  ${YELLOW}SKIP: Per-tenant media governance control requires Enterprise license.${NC}"
    echo "  Community/Evaluation tiers use the global media governance setting."
    echo "  To test this, run with an Enterprise license key set in AXONFLOW_LICENSE_KEY."
fi
echo ""

# ========================================
# Test 7: Non-media request unaffected
# ========================================
echo -e "${CYAN}Test 7: Non-media request unaffected by media policies${NC}"
echo "  POST $AGENT_URL/api/request (text only, no media)"
echo ""

RESPONSE7=$(curl -s -w "\n%{http_code}" -X POST "$AGENT_URL/api/request" \
    -H "Content-Type: application/json" \
    -H "Authorization: Basic $AUTH_B64" \
    -d "{
        \"query\": \"What is the capital of France?\",
        \"user_token\": \"media-policy-user\",
        \"client_id\": \"$CLIENT_ID\",
        \"request_type\": \"chat\"
    }")

HTTP_CODE7=$(echo "$RESPONSE7" | tail -1)
BODY7=$(echo "$RESPONSE7" | sed '$d')

SUCCESS7=$(echo "$BODY7" | jq -r '.success // false')
assert_pass "$SUCCESS7" "Text-only request is successful (HTTP $HTTP_CODE7)"

HAS_MEDIA_ANALYSIS7=$(echo "$BODY7" | jq 'has("media_analysis") and .media_analysis != null')
assert_pass "$([ "$HAS_MEDIA_ANALYSIS7" != "true" ] && echo true || echo false)" \
    "No media_analysis present for text-only request"
echo ""

# ========================================
# Summary
# ========================================
echo "================================================"
echo ""
if [ "$FAILURES" -eq 0 ]; then
    echo -e "${GREEN}ALL TESTS PASSED${NC}"
    echo ""
    echo "Media governance policy capabilities validated:"
    echo "  - System media policies (NSFW, violence, biometric, PII, documents)"
    echo "  - Clean image passes system policies"
    echo "  - Custom media policy CRUD (create, verify, process, delete)"
    echo "  - Media governance config & status endpoints"
    echo "  - Policy toggle lifecycle (create, disable, re-enable, delete)"
    if [ "$PER_TENANT" = "true" ]; then
        echo "  - Per-tenant media governance disable/enable (Enterprise)"
    fi
    echo "  - Non-media requests unaffected by media policies"
else
    echo -e "${RED}$FAILURES TEST(S) FAILED${NC}"
    exit 1
fi
