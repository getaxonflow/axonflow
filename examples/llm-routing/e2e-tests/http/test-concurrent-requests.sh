#!/bin/bash
# LLM Provider Concurrent Requests Load Test
# Tests: Parallel request handling, response times under load, routing distribution
#
# This test validates that:
# 1. Multiple concurrent requests are handled correctly
# 2. Response times remain acceptable under load
# 3. Routing distribution works across parallel requests
#
# Usage:
#   ./test-concurrent-requests.sh
#   CONCURRENT=20 TOTAL=100 ./test-concurrent-requests.sh

BASE_URL="${AXONFLOW_AGENT_URL:-http://localhost:8080}"
CONCURRENT="${CONCURRENT:-10}"
TOTAL="${TOTAL:-30}"
RESULTS_DIR="/tmp/llm-load-test-$$"

# Auth: include Basic auth if credentials are set
CURL_AUTH=()
if [ -n "${AXONFLOW_CLIENT_ID:-}" ] && [ -n "${AXONFLOW_CLIENT_SECRET:-}" ]; then
  CURL_AUTH=(-u "${AXONFLOW_CLIENT_ID}:${AXONFLOW_CLIENT_SECRET}")
fi
acurl() { curl "${CURL_AUTH[@]}" "$@"; }

echo "========================================"
echo "Concurrent Requests Load Test"
echo "========================================"
echo "Target: $BASE_URL"
echo "Concurrent: $CONCURRENT"
echo "Total requests: $TOTAL"
echo ""

# Create results directory
mkdir -p "$RESULTS_DIR"

# Test 1: Baseline single request
echo "Test 1: Baseline (single request)"
START=$(date +%s%N)
RESULT=$(acurl -s -X POST "$BASE_URL/api/v1/process" \
    -H "Content-Type: application/json" \
    -d '{"query":"Hello","request_type":"chat","user":{"email":"test@example.com","role":"user"}}')
END=$(date +%s%N)
BASELINE_MS=$(( (END - START) / 1000000 ))
echo "  Response time: ${BASELINE_MS}ms"
echo "  Provider: $(echo "$RESULT" | jq -r '.provider_info.provider')"
echo ""

# Test 2: Concurrent requests burst
echo "Test 2: Concurrent burst ($CONCURRENT parallel requests)"
START=$(date +%s%N)

# Launch concurrent requests
for i in $(seq 1 $CONCURRENT); do
    acurl -s -X POST "$BASE_URL/api/v1/process" \
        -H "Content-Type: application/json" \
        -d '{"query":"Concurrent test","request_type":"chat","user":{"email":"test@example.com","role":"user"}}' \
        > "$RESULTS_DIR/result_$i.json" &
done

# Wait for all to complete
wait

END=$(date +%s%N)
BURST_MS=$(( (END - START) / 1000000 ))

# Count results
SUCCESS=0
FAILED=0
for i in $(seq 1 $CONCURRENT); do
    if [ -f "$RESULTS_DIR/result_$i.json" ]; then
        if [ "$(cat "$RESULTS_DIR/result_$i.json" | jq -r '.success')" == "true" ]; then
            SUCCESS=$((SUCCESS + 1))
        else
            FAILED=$((FAILED + 1))
        fi
    else
        FAILED=$((FAILED + 1))
    fi
done

echo "  Total time: ${BURST_MS}ms"
echo "  Avg per request: $((BURST_MS / CONCURRENT))ms"
echo "  Successful: $SUCCESS / $CONCURRENT"
echo "  Failed: $FAILED"
echo ""

# Test 3: Sustained load
echo "Test 3: Sustained load ($TOTAL requests, $CONCURRENT concurrent)"
START=$(date +%s%N)

# Clear results
rm -f "$RESULTS_DIR"/*.json

# Run requests in batches
BATCH=0
TOTAL_SUCCESS=0
TOTAL_FAILED=0

for batch_start in $(seq 1 $CONCURRENT $TOTAL); do
    BATCH=$((BATCH + 1))
    batch_end=$((batch_start + CONCURRENT - 1))
    if [ $batch_end -gt $TOTAL ]; then
        batch_end=$TOTAL
    fi

    # Launch batch
    for i in $(seq $batch_start $batch_end); do
        acurl -s -X POST "$BASE_URL/api/v1/process" \
            -H "Content-Type: application/json" \
            -d '{"query":"Load test","request_type":"chat","user":{"email":"test@example.com","role":"user"}}' \
            > "$RESULTS_DIR/result_$i.json" &
    done
    wait
done

END=$(date +%s%N)
TOTAL_MS=$(( (END - START) / 1000000 ))

# Count final results and distribution
openai_count=0
anthropic_count=0
gemini_count=0

for i in $(seq 1 $TOTAL); do
    if [ -f "$RESULTS_DIR/result_$i.json" ]; then
        if [ "$(cat "$RESULTS_DIR/result_$i.json" | jq -r '.success')" == "true" ]; then
            TOTAL_SUCCESS=$((TOTAL_SUCCESS + 1))
            PROVIDER=$(cat "$RESULTS_DIR/result_$i.json" | jq -r '.provider_info.provider')
            case "$PROVIDER" in
                openai) openai_count=$((openai_count + 1)) ;;
                anthropic) anthropic_count=$((anthropic_count + 1)) ;;
                gemini) gemini_count=$((gemini_count + 1)) ;;
            esac
        else
            TOTAL_FAILED=$((TOTAL_FAILED + 1))
        fi
    else
        TOTAL_FAILED=$((TOTAL_FAILED + 1))
    fi
done

echo "  Total time: ${TOTAL_MS}ms"
echo "  Throughput: $(echo "scale=2; $TOTAL * 1000 / $TOTAL_MS" | bc) req/sec"
echo "  Successful: $TOTAL_SUCCESS / $TOTAL"
echo "  Failed: $TOTAL_FAILED"
echo ""
echo "  Provider distribution:"
[ $openai_count -gt 0 ] && echo "    openai: $openai_count ($((openai_count * 100 / TOTAL))%)"
[ $anthropic_count -gt 0 ] && echo "    anthropic: $anthropic_count ($((anthropic_count * 100 / TOTAL))%)"
[ $gemini_count -gt 0 ] && echo "    gemini: $gemini_count ($((gemini_count * 100 / TOTAL))%)"
echo ""

# Test 4: Response time distribution
echo "Test 4: Response time analysis"
TIMES=""
for i in $(seq 1 $TOTAL); do
    if [ -f "$RESULTS_DIR/result_$i.json" ]; then
        TIME=$(cat "$RESULTS_DIR/result_$i.json" | jq -r '.provider_info.response_time_ms // 0')
        if [ "$TIME" != "0" ] && [ "$TIME" != "null" ]; then
            TIMES="$TIMES $TIME"
        fi
    fi
done

if [ -n "$TIMES" ]; then
    # Calculate min, max, avg
    MIN=$(echo $TIMES | tr ' ' '\n' | sort -n | head -1)
    MAX=$(echo $TIMES | tr ' ' '\n' | sort -n | tail -1)
    SUM=$(echo $TIMES | tr ' ' '\n' | paste -sd+ | bc)
    COUNT=$(echo $TIMES | wc -w | tr -d ' ')
    AVG=$((SUM / COUNT))

    echo "  Min response time: ${MIN}ms"
    echo "  Max response time: ${MAX}ms"
    echo "  Avg response time: ${AVG}ms"
else
    echo "  Response times not available in response"
fi
echo ""

# Cleanup
rm -rf "$RESULTS_DIR"

echo "========================================"
echo "Load Test Complete"
echo "========================================"
echo ""
echo "Summary:"
echo "  Baseline: ${BASELINE_MS}ms"
echo "  Under load: $((TOTAL_MS / TOTAL))ms avg"
echo "  Success rate: $((TOTAL_SUCCESS * 100 / TOTAL))%"
if [ $TOTAL_SUCCESS -eq $TOTAL ]; then
    echo "  ✓ All requests successful"
else
    echo "  ⚠ Some requests failed ($TOTAL_FAILED failures)"
fi
