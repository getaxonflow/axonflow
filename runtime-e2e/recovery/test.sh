#!/usr/bin/env bash
# Runtime E2E test for the W3 free-tier email-recovery flow — HAPPY PATH.
#
# Asserts the full end-to-end recovery flow against a live community-saas
# docker stack:
#   1. Register a tenant WITH email (uses the email-field addition from the
#      W3 critical-fix PR — pre-fix, registration didn't accept email and
#      the recovery flow was effectively unreachable for any real user).
#   2. POST /api/v1/recover for that email.
#   3. Read the captured magic link from the noop sender's capture file
#      (AXONFLOW_RECOVERY_TEST_CAPTURE_FILE — env var must be set on the
#      agent container; production never has this set).
#   4. GET /api/v1/recover/verify?token=<extracted> — should succeed with
#      a fresh tenant_id bound to the same email.
#   5. Use the recovered credentials to make an audit/tool-call write —
#      asserts the new credentials actually work end-to-end.
#   6. Replay the same token — asserts the consumed-once invariant.
#   7. Assert original tenant credentials still work (audit history preserved).
#
# Per FEATURE_RUNTIME_COVERAGE.md methodology: this is the runtime-path test
# the W3 PR ships with. SDK-import tests are a different category.
#
# PREREQ: agent container must be started with AXONFLOW_RECOVERY_TEST_CAPTURE_FILE
#         pointing at a path readable from this script. Easiest setup:
#           docker compose -f docker-compose.yml -f docker-compose.community-saas.yml \
#             run -e AXONFLOW_RECOVERY_TEST_CAPTURE_FILE=/tmp/recovery-captures.txt \
#             -v /tmp:/tmp axonflow-agent
#         OR set in the docker-compose.community-saas.yml override file's
#         agent service env: section.

set -euo pipefail

AGENT_URL="${AGENT_URL:-http://localhost:8080}"
CAPTURE_FILE="${AXONFLOW_RECOVERY_TEST_CAPTURE_FILE:-/tmp/axonflow-recovery-captures.txt}"
TEST_EMAIL="${TEST_EMAIL:-w3-runtime-test-$$-$(date +%s)@axonflow-test.invalid}"
JQ="${JQ:-jq}"

# Ensure capture file is empty at start so we don't pick up stale tokens
> "$CAPTURE_FILE" 2>/dev/null || {
    echo "  ! Cannot write to $CAPTURE_FILE — must be writable by the agent container."
    echo "  ! Re-run with AXONFLOW_RECOVERY_TEST_CAPTURE_FILE pointing at a shared path,"
    echo "  ! and ensure the agent has the same env var set."
    exit 2
}

cleanup() {
    echo ""
    echo "=== Cleanup ==="
    rm -f "$CAPTURE_FILE" 2>/dev/null || true
}
trap cleanup EXIT

echo "=== W3 runtime-e2e: free email-recovery HAPPY PATH ==="
echo "Agent URL: $AGENT_URL"
echo "Test email: $TEST_EMAIL"
echo "Capture file: $CAPTURE_FILE"
echo ""

# -----------------------------------------------------------------------------
# Step 1: register a fresh tenant WITH email binding (critical fix #1 in PR A)
# -----------------------------------------------------------------------------
echo "Step 1: register fresh tenant WITH email"
REGISTER_RESP=$(curl -fsS -X POST "$AGENT_URL/api/v1/register" \
  -H "Content-Type: application/json" \
  -d "{\"label\":\"w3-recovery-test\",\"email\":\"$TEST_EMAIL\"}")
ORIGINAL_TENANT_ID=$(echo "$REGISTER_RESP" | $JQ -r '.tenant_id')
ORIGINAL_SECRET=$(echo "$REGISTER_RESP" | $JQ -r '.secret')
if [ -z "$ORIGINAL_TENANT_ID" ] || [ "$ORIGINAL_TENANT_ID" == "null" ]; then
    echo "  ✗ FAIL: registration did not return a tenant_id"
    echo "    response: $REGISTER_RESP"
    exit 1
fi
echo "  ✓ PASS: original tenant_id = $ORIGINAL_TENANT_ID (bound to $TEST_EMAIL)"

# -----------------------------------------------------------------------------
# Step 2: simulate lost local credentials (we just discard them mentally) and
# request recovery for the bound email
# -----------------------------------------------------------------------------
echo ""
echo "Step 2: POST /api/v1/recover (anti-enum: returns 202 always)"
RECOVER_RESP=$(curl -fsS -X POST "$AGENT_URL/api/v1/recover" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$TEST_EMAIL\"}" \
  -w "\n%{http_code}")
RECOVER_CODE=$(echo "$RECOVER_RESP" | tail -n1)

if [ "$RECOVER_CODE" != "202" ]; then
    echo "  ✗ FAIL: expected 202, got $RECOVER_CODE"
    echo "    body: $(echo "$RECOVER_RESP" | sed '$d')"
    exit 1
fi
echo "  ✓ PASS: 202 returned"

# -----------------------------------------------------------------------------
# Step 3: extract magic-link token from noop sender's capture file
# -----------------------------------------------------------------------------
echo ""
echo "Step 3: extract magic-link token from capture file"
# Wait briefly for async capture write to land
for i in 1 2 3 4 5; do
    if [ -s "$CAPTURE_FILE" ] && grep -q "to=$TEST_EMAIL" "$CAPTURE_FILE"; then
        break
    fi
    sleep 0.5
done

if ! grep -q "to=$TEST_EMAIL" "$CAPTURE_FILE"; then
    echo "  ✗ FAIL: no captured magic link for $TEST_EMAIL after 2.5s"
    echo "    Capture file contents:"
    cat "$CAPTURE_FILE" 2>/dev/null | head -10
    echo "    Possible causes:"
    echo "      - AXONFLOW_RECOVERY_TEST_CAPTURE_FILE env var not set on agent container"
    echo "      - Agent and test script see different paths for the capture file"
    echo "      - Email binding wasn't picked up at registration time"
    exit 1
fi

# Extract the token from the most recent capture line for this email.
# Captured line format: "to=<email> link=<url>?token=<hex>"
TOKEN=$(grep "to=$TEST_EMAIL" "$CAPTURE_FILE" | tail -1 | sed 's|.*token=||')
if [ -z "$TOKEN" ] || [ ${#TOKEN} -lt 32 ]; then
    echo "  ✗ FAIL: extracted token looks malformed (length=${#TOKEN})"
    echo "    line: $(grep "to=$TEST_EMAIL" "$CAPTURE_FILE" | tail -1)"
    exit 1
fi
echo "  ✓ PASS: extracted token (length=${#TOKEN})"

# -----------------------------------------------------------------------------
# Step 4a: GET the confirmation page (post-PR-B: GET no longer consumes,
# just renders an HTML page. Email previewers fetching the link see this page,
# don't consume the token.) Asserts the page renders and contains the form.
# -----------------------------------------------------------------------------
echo ""
echo "Step 4a: GET confirmation page (NO consume; safe for email prefetchers)"
CONFIRM_PAGE=$(curl -fsS -X GET "$AGENT_URL/api/v1/recover/verify?token=$TOKEN" \
  -H "Accept: text/html" -w "\n%{http_code}\n%{content_type}")
CONFIRM_BODY=$(echo "$CONFIRM_PAGE" | sed '$d' | sed '$d')
CONFIRM_CODE=$(echo "$CONFIRM_PAGE" | sed -n '$ s/.*//p; $!p' | tail -2 | head -1)
CONFIRM_CT=$(echo "$CONFIRM_PAGE" | tail -1)
if [ "$CONFIRM_CODE" != "200" ]; then
    echo "  ✗ FAIL: confirmation page should return 200, got $CONFIRM_CODE"
    exit 1
fi
if [[ "$CONFIRM_CT" != text/html* ]]; then
    echo "  ✗ FAIL: confirmation page should have Content-Type text/html, got '$CONFIRM_CT'"
    exit 1
fi
if ! echo "$CONFIRM_BODY" | grep -q 'method="POST"'; then
    echo "  ✗ FAIL: confirmation page missing POST form"
    exit 1
fi
echo "  ✓ PASS: GET returned HTML confirmation page (no consume)"

# -----------------------------------------------------------------------------
# Step 4b: POST to consume the token (simulates user clicking Confirm button)
# -----------------------------------------------------------------------------
echo ""
echo "Step 4b: POST /api/v1/recover/verify (consumes token + returns credentials)"
VERIFY_RESP=$(curl -fsS -X POST "$AGENT_URL/api/v1/recover/verify" \
  -H "Content-Type: application/json" \
  -d "{\"token\":\"$TOKEN\"}")
NEW_TENANT_ID=$(echo "$VERIFY_RESP" | $JQ -r '.tenant_id')
NEW_SECRET=$(echo "$VERIFY_RESP" | $JQ -r '.secret')
RECOVERED_EMAIL=$(echo "$VERIFY_RESP" | $JQ -r '.email')

if [ -z "$NEW_TENANT_ID" ] || [ "$NEW_TENANT_ID" == "null" ]; then
    echo "  ✗ FAIL: verify did not return a tenant_id"
    echo "    response: $VERIFY_RESP"
    exit 1
fi
if [ "$NEW_TENANT_ID" == "$ORIGINAL_TENANT_ID" ]; then
    echo "  ✗ FAIL: recovery should produce a NEW tenant_id; got same as original"
    exit 1
fi
if [ "$RECOVERED_EMAIL" != "$TEST_EMAIL" ]; then
    echo "  ✗ FAIL: recovered tenant email mismatch: got '$RECOVERED_EMAIL', expected '$TEST_EMAIL'"
    exit 1
fi
echo "  ✓ PASS: verify returned new tenant_id $NEW_TENANT_ID bound to $TEST_EMAIL"

# -----------------------------------------------------------------------------
# Step 5: use the new credentials to make a real authenticated call
# -----------------------------------------------------------------------------
echo ""
echo "Step 5: use recovered credentials to POST /api/v1/audit/tool-call"
AUTH_HEADER=$(echo -n "$NEW_TENANT_ID:$NEW_SECRET" | base64 | tr -d '\n')
AUDIT_RESP=$(curl -fsS -X POST "$AGENT_URL/api/v1/audit/tool-call" \
  -H "Content-Type: application/json" \
  -H "Authorization: Basic $AUTH_HEADER" \
  -d '{"tool_name":"w3-runtime-e2e-test","blocked":false,"redacted":false,"exfil":false}' \
  -w "\n%{http_code}")
AUDIT_CODE=$(echo "$AUDIT_RESP" | tail -n1)

if [ "$AUDIT_CODE" != "201" ] && [ "$AUDIT_CODE" != "200" ]; then
    echo "  ✗ FAIL: recovered credentials should authenticate; got $AUDIT_CODE"
    echo "    body: $(echo "$AUDIT_RESP" | sed '$d')"
    exit 1
fi
echo "  ✓ PASS: recovered credentials work end-to-end (HTTP $AUDIT_CODE)"

# -----------------------------------------------------------------------------
# Step 6a: GET the consumed token's confirmation page — should now show the
# "already used" error page (not the confirmation form).
# -----------------------------------------------------------------------------
echo ""
echo "Step 6a: GET consumed token's confirmation page (should show error, not form)"
REPLAY_GET=$(curl -sS -X GET "$AGENT_URL/api/v1/recover/verify?token=$TOKEN" -w "\n%{http_code}")
REPLAY_GET_CODE=$(echo "$REPLAY_GET" | tail -n1)
REPLAY_GET_BODY=$(echo "$REPLAY_GET" | sed '$d')
if [ "$REPLAY_GET_CODE" != "401" ]; then
    echo "  ✗ FAIL: GET on consumed token should return 401, got $REPLAY_GET_CODE"
    exit 1
fi
if ! echo "$REPLAY_GET_BODY" | grep -q "already been used"; then
    echo "  ✗ FAIL: error page should mention 'already been used'"
    exit 1
fi
echo "  ✓ PASS: GET on consumed token shows error page with 401"

# -----------------------------------------------------------------------------
# Step 6b: POST replay — also rejected (consumed-once invariant)
# -----------------------------------------------------------------------------
echo ""
echo "Step 6b: POST replay (consumed-once invariant on POST path too)"
REPLAY_RESP=$(curl -sS -X POST "$AGENT_URL/api/v1/recover/verify" \
  -H "Content-Type: application/json" \
  -d "{\"token\":\"$TOKEN\"}" \
  -w "\n%{http_code}")
REPLAY_CODE=$(echo "$REPLAY_RESP" | tail -n1)

if [ "$REPLAY_CODE" != "401" ]; then
    echo "  ✗ FAIL: replayed token POST should return 401, got $REPLAY_CODE"
    echo "    body: $(echo "$REPLAY_RESP" | sed '$d')"
    exit 1
fi
echo "  ✓ PASS: POST replay rejected with 401 (consumed-once invariant holds on both methods)"

# -----------------------------------------------------------------------------
# Step 7: verify the original tenant still works (audit history preserved)
# -----------------------------------------------------------------------------
echo ""
echo "Step 7: verify original tenant still works (audit history preserved)"
ORIG_AUTH=$(echo -n "$ORIGINAL_TENANT_ID:$ORIGINAL_SECRET" | base64 | tr -d '\n')
ORIG_RESP=$(curl -sS -X POST "$AGENT_URL/api/v1/audit/tool-call" \
  -H "Content-Type: application/json" \
  -H "Authorization: Basic $ORIG_AUTH" \
  -d '{"tool_name":"w3-original-still-works","blocked":false,"redacted":false,"exfil":false}' \
  -w "\n%{http_code}")
ORIG_CODE=$(echo "$ORIG_RESP" | tail -n1)
if [ "$ORIG_CODE" != "201" ] && [ "$ORIG_CODE" != "200" ]; then
    echo "  ✗ FAIL: original tenant credentials stopped working after recovery; got $ORIG_CODE"
    exit 1
fi
echo "  ✓ PASS: original tenant credentials still work (HTTP $ORIG_CODE)"

echo ""
echo "=== W3 recovery runtime-e2e HAPPY PATH: ALL ASSERTIONS PASSED ==="
exit 0
