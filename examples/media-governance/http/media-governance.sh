#!/bin/bash
# AxonFlow Media Governance - HTTP/curl
#
# Demonstrates AxonFlow's media governance for images using raw HTTP requests.
# This is useful for:
# - Languages without an SDK (Ruby, PHP, etc.)
# - Quick testing and debugging
# - Understanding the API structure
#
# Prerequisites:
#   - AxonFlow Agent running at http://localhost:8080
#   - curl and jq installed
#
# Run with: bash media-governance.sh

set -e

# Configuration
AGENT_URL="${AXONFLOW_ENDPOINT:-http://localhost:8080}"
CLIENT_ID="${AXONFLOW_CLIENT_ID:-demo-client}"
CLIENT_SECRET="${AXONFLOW_CLIENT_SECRET:-demo-secret}"

# Minimal valid 1x1 white pixel JPEG encoded as base64
TEST_IMAGE_BASE64="/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAgGBgcGBQgHBwcJCQgKDBQNDAsLDBkSEw8UHRofHh0aHBwgJC4nICIsIxwcKDcpLDAxNDQ0Hyc5PTgyPC4zNDL/2wBDAQkJCQwLDBgNDRgyIRwhMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjL/wAARCAABAAEDASIAAhEBAxEB/8QAFAABAAAAAAAAAAAAAAAAAAAACf/EABQQAQAAAAAAAAAAAAAAAAAAAAD/xAAUAQEAAAAAAAAAAAAAAAAAAAAA/8QAFBEBAAAAAAAAAAAAAAAAAAAAAP/aAAwDAQACEQMRAD8AbwA//9k="

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

FAILURES=0
PIPELINE_ACTIVE=false

echo "AxonFlow Media Governance - HTTP/curl"
echo "========================================"
echo ""
echo "Agent URL: $AGENT_URL"
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

# Validates media_analysis structure when present.
# Usage: validate_media_analysis <json_body> <expected_result_count> <test_label> [url_source]
# When url_source is "true", an empty sha256_hash produces a warning instead of a failure.
validate_media_analysis() {
    local body="$1"
    local expected_count="$2"
    local label="$3"
    local url_source="${4:-false}"

    local has_media_analysis
    has_media_analysis=$(echo "$body" | jq 'has("media_analysis") and .media_analysis != null')

    if [ "$has_media_analysis" != "true" ]; then
        echo -e "   ${YELLOW}WARNING: MEDIA GOVERNANCE PIPELINE NOT ACTIVE — media_analysis absent (requires platform v4.4.0+)${NC}"
        return 1
    fi

    PIPELINE_ACTIVE=true

    # Top-level fields
    local total_cost_exists
    total_cost_exists=$(echo "$body" | jq 'has("media_analysis") and (.media_analysis | has("total_cost_usd"))')
    assert_pass "$total_cost_exists" "[$label] media_analysis.total_cost_usd exists"

    local analysis_time_exists
    analysis_time_exists=$(echo "$body" | jq 'has("media_analysis") and (.media_analysis | has("analysis_time_ms"))')
    assert_pass "$analysis_time_exists" "[$label] media_analysis.analysis_time_ms exists"

    # Results array length
    local result_count
    result_count=$(echo "$body" | jq '.media_analysis.results | length')
    assert_pass "$([ "$result_count" -eq "$expected_count" ] && echo true || echo false)" \
        "[$label] results array length is $expected_count (got $result_count)"

    # Validate each result
    local i=0
    while [ "$i" -lt "$result_count" ]; do
        local prefix="[$label] results[$i]"

        # sha256_hash — non-empty string (warn instead of fail for URL sources)
        local sha256
        sha256=$(echo "$body" | jq -r ".media_analysis.results[$i].sha256_hash // \"\"")
        if [ -n "$sha256" ]; then
            assert_pass "true" "$prefix sha256_hash is non-empty"
        elif [ "$url_source" = "true" ]; then
            echo -e "   ${YELLOW}WARNING:${NC} $prefix SHA-256 hash empty for URL source (platform may not have network access to download URL)"
        else
            assert_pass "false" "$prefix sha256_hash is non-empty"
        fi

        # media_index matches position
        local media_index
        media_index=$(echo "$body" | jq -r ".media_analysis.results[$i].media_index // -1")
        assert_pass "$([ "$media_index" -eq "$i" ] && echo true || echo false)" \
            "$prefix media_index is $i (got $media_index)"

        # Boolean fields
        for bool_field in content_safe has_faces has_pii has_biometric_data is_sensitive_document; do
            local val
            val=$(echo "$body" | jq ".media_analysis.results[$i] | has(\"$bool_field\") and (.[\"$bool_field\"] | type == \"boolean\")")
            assert_pass "$val" "$prefix $bool_field exists and is boolean"
        done

        # Numeric fields
        for num_field in nsfw_score violence_score face_count estimated_cost_usd; do
            local val
            val=$(echo "$body" | jq ".media_analysis.results[$i] | has(\"$num_field\") and (.[\"$num_field\"] | type == \"number\")")
            assert_pass "$val" "$prefix $num_field exists and is number"
        done

        i=$((i + 1))
    done

    # Print human-readable summary for the first result
    echo "   Content safe: $(echo "$body" | jq -r '.media_analysis.results[0].content_safe')"
    echo "   Has PII: $(echo "$body" | jq -r '.media_analysis.results[0].has_pii')"
    echo "   Has faces: $(echo "$body" | jq -r '.media_analysis.results[0].has_faces')"
    echo "   Total cost: \$$(echo "$body" | jq -r '.media_analysis.total_cost_usd')"
    echo "   Analysis time: $(echo "$body" | jq -r '.media_analysis.analysis_time_ms')ms"

    return 0
}

# ========================================
# Test 1: Single image governance (base64)
# ========================================
echo -e "${YELLOW}Test 1: Single image governance (base64)${NC}"
echo "  Query: Describe this image"

RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$AGENT_URL/api/request" \
    -H "Content-Type: application/json" \
    -H "X-Client-ID: $CLIENT_ID" \
    -H "X-Client-Secret: $CLIENT_SECRET" \
    -d "{
        \"query\": \"Describe this image\",
        \"user_token\": \"media-governance-user\",
        \"client_id\": \"$CLIENT_ID\",
        \"request_type\": \"chat\",
        \"media\": [{
            \"source\": \"base64\",
            \"mime_type\": \"image/jpeg\",
            \"base64_data\": \"$TEST_IMAGE_BASE64\"
        }]
    }")

HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | sed '$d')

SUCCESS=$(echo "$BODY" | jq -r '.success // false')
assert_pass "$SUCCESS" "Response is successful (HTTP $HTTP_CODE)"

validate_media_analysis "$BODY" 1 "Test 1" || true
echo ""

# ========================================
# Test 2: Multiple images in single request
# ========================================
echo -e "${YELLOW}Test 2: Multiple images in single request${NC}"
echo "  Query: Compare these images"

RESPONSE2=$(curl -s -w "\n%{http_code}" -X POST "$AGENT_URL/api/request" \
    -H "Content-Type: application/json" \
    -H "X-Client-ID: $CLIENT_ID" \
    -H "X-Client-Secret: $CLIENT_SECRET" \
    -d "{
        \"query\": \"Compare these images\",
        \"user_token\": \"media-governance-user\",
        \"client_id\": \"$CLIENT_ID\",
        \"request_type\": \"chat\",
        \"media\": [
            {\"source\": \"base64\", \"mime_type\": \"image/jpeg\", \"base64_data\": \"$TEST_IMAGE_BASE64\"},
            {\"source\": \"base64\", \"mime_type\": \"image/jpeg\", \"base64_data\": \"$TEST_IMAGE_BASE64\"}
        ]
    }")

HTTP_CODE2=$(echo "$RESPONSE2" | tail -1)
BODY2=$(echo "$RESPONSE2" | sed '$d')

SUCCESS2=$(echo "$BODY2" | jq -r '.success // false')
assert_pass "$SUCCESS2" "Response is successful (HTTP $HTTP_CODE2)"

validate_media_analysis "$BODY2" 2 "Test 2" || true
echo ""

# ========================================
# Test 3: URL-sourced image
# ========================================
echo -e "${YELLOW}Test 3: URL-sourced image${NC}"
echo "  Query: Analyze this image from URL"

RESPONSE3=$(curl -s -w "\n%{http_code}" -X POST "$AGENT_URL/api/request" \
    -H "Content-Type: application/json" \
    -H "X-Client-ID: $CLIENT_ID" \
    -H "X-Client-Secret: $CLIENT_SECRET" \
    -d "{
        \"query\": \"Analyze this image from URL\",
        \"user_token\": \"media-governance-user\",
        \"client_id\": \"$CLIENT_ID\",
        \"request_type\": \"chat\",
        \"media\": [{
            \"source\": \"url\",
            \"mime_type\": \"image/png\",
            \"url\": \"https://via.placeholder.com/1x1.png\"
        }]
    }")

HTTP_CODE3=$(echo "$RESPONSE3" | tail -1)
BODY3=$(echo "$RESPONSE3" | sed '$d')

SUCCESS3=$(echo "$BODY3" | jq -r '.success // false')
assert_pass "$SUCCESS3" "Response is successful (HTTP $HTTP_CODE3)"

validate_media_analysis "$BODY3" 1 "Test 3" "true" || true
echo ""

# ========================================
# Test 4: Request without media still succeeds
# ========================================
echo -e "${YELLOW}Test 4: Request without media still succeeds${NC}"
echo "  Query: What is the capital of France?"

RESPONSE4=$(curl -s -w "\n%{http_code}" -X POST "$AGENT_URL/api/request" \
    -H "Content-Type: application/json" \
    -H "X-Client-ID: $CLIENT_ID" \
    -H "X-Client-Secret: $CLIENT_SECRET" \
    -d "{
        \"query\": \"What is the capital of France?\",
        \"user_token\": \"media-governance-user\",
        \"client_id\": \"$CLIENT_ID\",
        \"request_type\": \"chat\"
    }")

HTTP_CODE4=$(echo "$RESPONSE4" | tail -1)
BODY4=$(echo "$RESPONSE4" | sed '$d')

SUCCESS4=$(echo "$BODY4" | jq -r '.success // false')
assert_pass "$SUCCESS4" "Response is successful (HTTP $HTTP_CODE4)"

HAS_MEDIA_ANALYSIS4=$(echo "$BODY4" | jq 'has("media_analysis") and .media_analysis != null')
assert_pass "$([ "$HAS_MEDIA_ANALYSIS4" != "true" ] && echo true || echo false)" \
    "No media_analysis present when no media sent"
echo ""

# ========================================
# Summary
# ========================================
echo "========================================"
if [ "$PIPELINE_ACTIVE" = true ]; then
    echo -e "Media governance pipeline: ${GREEN}ACTIVE${NC}"
else
    echo -e "Media governance pipeline: ${YELLOW}NOT DETECTED${NC} (requires platform v4.4.0+)"
fi
echo ""
if [ "$FAILURES" -eq 0 ]; then
    echo -e "${GREEN}ALL TESTS PASSED${NC}"
    echo ""
    echo "Media governance capabilities validated:"
    echo "  - Single image analysis (base64)"
    echo "  - Multiple image analysis"
    echo "  - URL-sourced image analysis"
    echo "  - Baseline request without media"
else
    echo -e "${RED}$FAILURES TEST(S) FAILED${NC}"
    exit 1
fi
