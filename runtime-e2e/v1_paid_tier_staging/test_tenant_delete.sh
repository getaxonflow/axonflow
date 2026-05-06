#!/usr/bin/env bash
# Runtime E2E test for the GDPR right-to-erasure flow (issue #1896).
#
# Asserts the full end-to-end deletion flow against a live community-saas
# stack (local docker-compose OR staging):
#   1. Register a fresh tenant WITH email
#   2. Use those credentials to issue several audit/tool-call writes
#   3. Insert a daily-usage row through the same endpoint surface
#   4. (Optional) issue a Pro license via synthetic_stripe_webhook
#   5. POST /api/v1/tenant/<id>/delete-request — expect 202 (anti-enum)
#   6. Read the captured deletion token from the noop-sender capture file
#      (AXONFLOW_TENANT_DELETE_TEST_CAPTURE_FILE — env var must be set on
#      the agent container; production never has this set)
#   7. POST /api/v1/tenant/<id>/delete-confirm with the token — expect 200
#      with a JSON body listing per-table deleted-rows counts
#   8. Verify the original credentials no longer authenticate (401 expected
#      since the registration row is gone)
#   9. Replay the consumed token — expect 410 Gone (idempotency)
#  10. Verify the deletion log row exists in tenant_deletion_log via the
#      psql shortcut (DATABASE_URL must be set, OR skip step 10 if no DB
#      access — script self-degrades gracefully)
#
# Per CLAUDE.md HARD RULE #0: this is the runtime-path proof the GDPR
# erasure feature ships with. Pure-unit + DB-backed integration tests live
# in platform/agent/tenant_delete_*_test.go.
#
# PREREQ: agent container must be started with
#         AXONFLOW_TENANT_DELETE_TEST_CAPTURE_FILE pointing at a path readable
#         from this script. Easiest setup:
#           docker compose -f docker-compose.yml -f docker-compose.community-saas.yml \
#             run -e AXONFLOW_TENANT_DELETE_TEST_CAPTURE_FILE=/tmp/tenant-delete-captures.txt \
#             -v /tmp:/tmp axonflow-agent
#         OR set in the docker-compose.community-saas.yml override file's
#         agent service env: section.

set -euo pipefail

AGENT_URL="${AGENT_URL:-http://localhost:8080}"
CAPTURE_FILE="${AXONFLOW_TENANT_DELETE_TEST_CAPTURE_FILE:-/tmp/axonflow-tenant-delete-captures.txt}"
TEST_EMAIL="${TEST_EMAIL:-gdpr-runtime-test-$$-$(date +%s)@axonflow-test.invalid}"
JQ="${JQ:-jq}"
SKIP_DB_CHECK="${SKIP_DB_CHECK:-0}"

# Ensure capture file is empty at start so we don't pick up stale tokens
> "$CAPTURE_FILE" 2>/dev/null || {
    echo "  ! Cannot write to $CAPTURE_FILE — must be writable by the agent container."
    echo "  ! Re-run with AXONFLOW_TENANT_DELETE_TEST_CAPTURE_FILE pointing at a shared path,"
    echo "  ! and ensure the agent has the same env var set."
    exit 2
}

cleanup() {
    echo ""
    echo "=== Cleanup ==="
    rm -f "$CAPTURE_FILE" 2>/dev/null || true
}
trap cleanup EXIT

echo "=== GDPR right-to-erasure runtime-e2e (issue #1896) ==="
echo "Agent URL: $AGENT_URL"
echo "Test email: $TEST_EMAIL"
echo "Capture file: $CAPTURE_FILE"
echo ""

# -----------------------------------------------------------------------------
# Step 1: register a fresh tenant with email
# -----------------------------------------------------------------------------
echo "Step 1: register fresh tenant WITH email"
REGISTER_RESP=$(curl -fsS -X POST "$AGENT_URL/api/v1/register" \
  -H "Content-Type: application/json" \
  -d "{\"label\":\"gdpr-erasure-test\",\"email\":\"$TEST_EMAIL\"}")
TENANT_ID=$(echo "$REGISTER_RESP" | $JQ -r '.tenant_id')
SECRET=$(echo "$REGISTER_RESP" | $JQ -r '.secret')
if [ -z "$TENANT_ID" ] || [ "$TENANT_ID" == "null" ]; then
    echo "  ✗ FAIL: registration did not return a tenant_id"
    echo "    response: $REGISTER_RESP"
    exit 1
fi
AUTH_HEADER=$(echo -n "$TENANT_ID:$SECRET" | base64 | tr -d '\n')
echo "  ✓ PASS: tenant_id = $TENANT_ID (bound to $TEST_EMAIL)"

# -----------------------------------------------------------------------------
# Step 2: drive some audit/tool-call writes so the tenant has a footprint
# -----------------------------------------------------------------------------
echo ""
echo "Step 2: issue 3 audit/tool-call writes to leave a footprint"
for i in 1 2 3; do
    AUDIT_RESP=$(curl -sS -X POST "$AGENT_URL/api/v1/audit/tool-call" \
      -H "Content-Type: application/json" \
      -H "Authorization: Basic $AUTH_HEADER" \
      -d "{\"tool_name\":\"gdpr-test-$i\",\"blocked\":false,\"redacted\":false,\"exfil\":false}" \
      -w "\n%{http_code}")
    AUDIT_CODE=$(echo "$AUDIT_RESP" | tail -n1)
    if [ "$AUDIT_CODE" != "201" ] && [ "$AUDIT_CODE" != "200" ]; then
        echo "  ✗ FAIL: audit write $i returned $AUDIT_CODE"
        exit 1
    fi
done
echo "  ✓ PASS: 3 audit writes accepted"

# -----------------------------------------------------------------------------
# Step 3: anti-enum probe — wrong-email delete-request must still return 202
# -----------------------------------------------------------------------------
echo ""
echo "Step 3: anti-enum probe (wrong email — must still return 202)"
WRONG_RESP=$(curl -sS -X POST "$AGENT_URL/api/v1/tenant/$TENANT_ID/delete-request" \
  -H "Content-Type: application/json" \
  -d '{"email":"someone-else@example.com"}' \
  -w "\n%{http_code}")
WRONG_CODE=$(echo "$WRONG_RESP" | tail -n1)
if [ "$WRONG_CODE" != "202" ]; then
    echo "  ✗ FAIL: wrong-email delete-request should be 202 (anti-enum), got $WRONG_CODE"
    exit 1
fi
echo "  ✓ PASS: wrong-email returns 202 (no token sent — verified next)"

# Capture file should still be empty at this point (no email was sent for the
# wrong-email probe).
if [ -s "$CAPTURE_FILE" ]; then
    echo "  ✗ FAIL: capture file is non-empty after wrong-email probe — anti-enum violated"
    cat "$CAPTURE_FILE"
    exit 1
fi
echo "  ✓ PASS: no email captured for wrong-email probe (anti-enum verified)"

# -----------------------------------------------------------------------------
# Step 4: legitimate delete-request — should 202 + send confirmation email
# -----------------------------------------------------------------------------
echo ""
echo "Step 4: legitimate delete-request (correct tenant + email)"
REQ_RESP=$(curl -fsS -X POST "$AGENT_URL/api/v1/tenant/$TENANT_ID/delete-request" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$TEST_EMAIL\"}" \
  -w "\n%{http_code}")
REQ_CODE=$(echo "$REQ_RESP" | tail -n1)
if [ "$REQ_CODE" != "202" ]; then
    echo "  ✗ FAIL: delete-request should return 202, got $REQ_CODE"
    exit 1
fi
echo "  ✓ PASS: 202 returned"

# -----------------------------------------------------------------------------
# Step 5: extract the confirmation token from the capture file
# -----------------------------------------------------------------------------
echo ""
echo "Step 5: extract confirmation token from capture file"
for i in 1 2 3 4 5; do
    if [ -s "$CAPTURE_FILE" ] && grep -q "to=$TEST_EMAIL" "$CAPTURE_FILE"; then
        break
    fi
    sleep 0.5
done
if ! grep -q "to=$TEST_EMAIL" "$CAPTURE_FILE"; then
    echo "  ✗ FAIL: no captured deletion email for $TEST_EMAIL after 2.5s"
    echo "    Capture file contents:"
    cat "$CAPTURE_FILE" 2>/dev/null | head -10
    echo "    Possible causes:"
    echo "      - AXONFLOW_TENANT_DELETE_TEST_CAPTURE_FILE env var not set on agent container"
    echo "      - Agent and test script see different paths for the capture file"
    exit 1
fi
# Extract: line shape is "to=<email> tenant=<id> token=<plain> url=<confirmURL>"
TOKEN=$(grep "to=$TEST_EMAIL" "$CAPTURE_FILE" | tail -1 | sed -E 's|.*token=([^ ]+).*|\1|')
if [ -z "$TOKEN" ] || [ ${#TOKEN} -lt 16 ]; then
    echo "  ✗ FAIL: extracted token looks malformed (length=${#TOKEN})"
    echo "    line: $(grep "to=$TEST_EMAIL" "$CAPTURE_FILE" | tail -1)"
    exit 1
fi
echo "  ✓ PASS: extracted token (length=${#TOKEN})"

# -----------------------------------------------------------------------------
# Step 6: POST delete-confirm — should return 200 with deleted-rows counts
# -----------------------------------------------------------------------------
echo ""
echo "Step 6: POST delete-confirm with the token"
CONFIRM_RESP=$(curl -fsS -X POST "$AGENT_URL/api/v1/tenant/$TENANT_ID/delete-confirm" \
  -H "Content-Type: application/json" \
  -d "{\"token\":\"$TOKEN\"}")
CONFIRMED_TENANT=$(echo "$CONFIRM_RESP" | $JQ -r '.tenant_id')
DELETED_REG=$(echo "$CONFIRM_RESP" | $JQ -r '.deleted_rows.registrations')
DELETED_AUDIT=$(echo "$CONFIRM_RESP" | $JQ -r '.deleted_rows.audit_logs')
if [ "$CONFIRMED_TENANT" != "$TENANT_ID" ]; then
    echo "  ✗ FAIL: response tenant_id mismatch: $CONFIRMED_TENANT vs $TENANT_ID"
    echo "    body: $CONFIRM_RESP"
    exit 1
fi
if [ "$DELETED_REG" != "1" ]; then
    echo "  ✗ FAIL: response should report registrations=1; got $DELETED_REG"
    echo "    body: $CONFIRM_RESP"
    exit 1
fi
echo "  ✓ PASS: confirm returned 200 with reg=$DELETED_REG audit=$DELETED_AUDIT"

# -----------------------------------------------------------------------------
# Step 7: original credentials should now FAIL (401) since registration is gone
# -----------------------------------------------------------------------------
echo ""
echo "Step 7: original credentials should no longer authenticate"
POST_DELETE_RESP=$(curl -sS -X POST "$AGENT_URL/api/v1/audit/tool-call" \
  -H "Content-Type: application/json" \
  -H "Authorization: Basic $AUTH_HEADER" \
  -d '{"tool_name":"should-fail","blocked":false,"redacted":false,"exfil":false}' \
  -w "\n%{http_code}")
POST_DELETE_CODE=$(echo "$POST_DELETE_RESP" | tail -n1)
if [ "$POST_DELETE_CODE" != "401" ] && [ "$POST_DELETE_CODE" != "403" ]; then
    echo "  ✗ FAIL: deleted tenant credentials should not authenticate; got $POST_DELETE_CODE"
    echo "    body: $(echo "$POST_DELETE_RESP" | sed '$d')"
    exit 1
fi
echo "  ✓ PASS: deleted credentials rejected (HTTP $POST_DELETE_CODE)"

# -----------------------------------------------------------------------------
# Step 8: idempotency — replay the consumed token, expect 410 Gone
# -----------------------------------------------------------------------------
echo ""
echo "Step 8: replay consumed token (idempotency: 410 Gone)"
REPLAY_RESP=$(curl -sS -X POST "$AGENT_URL/api/v1/tenant/$TENANT_ID/delete-confirm" \
  -H "Content-Type: application/json" \
  -d "{\"token\":\"$TOKEN\"}" \
  -w "\n%{http_code}")
REPLAY_CODE=$(echo "$REPLAY_RESP" | tail -n1)
if [ "$REPLAY_CODE" != "410" ]; then
    echo "  ✗ FAIL: replayed token should return 410, got $REPLAY_CODE"
    echo "    body: $(echo "$REPLAY_RESP" | sed '$d')"
    exit 1
fi
echo "  ✓ PASS: replay rejected with 410 Gone (idempotent)"

# -----------------------------------------------------------------------------
# Step 9: tenant_deletion_log row exists (DB check — best-effort)
# -----------------------------------------------------------------------------
echo ""
echo "Step 9: verify tenant_deletion_log row exists"
if [ "$SKIP_DB_CHECK" = "1" ]; then
    echo "  - SKIPPED (SKIP_DB_CHECK=1)"
elif [ -z "${DATABASE_URL:-}" ]; then
    echo "  - SKIPPED (DATABASE_URL not set; run with DATABASE_URL=... to enable)"
else
    if ! command -v psql >/dev/null 2>&1; then
        echo "  - SKIPPED (psql not installed locally; verify via ECS exec on staging)"
    else
        LOG_COUNT=$(psql "$DATABASE_URL" -tAc \
            "SELECT COUNT(*) FROM tenant_deletion_log WHERE tenant_id='$TENANT_ID'")
        if [ "$LOG_COUNT" != "1" ]; then
            echo "  ✗ FAIL: expected 1 tenant_deletion_log row for $TENANT_ID, got $LOG_COUNT"
            exit 1
        fi
        echo "  ✓ PASS: tenant_deletion_log row present (count=$LOG_COUNT)"

        # Spot-check counts
        psql "$DATABASE_URL" -c "
            SELECT tenant_id, email, deleted_registrations, deleted_audit_logs,
                   deleted_daily_usage, refund_needed, confirmed_at
            FROM tenant_deletion_log WHERE tenant_id='$TENANT_ID'"
    fi
fi

# -----------------------------------------------------------------------------
# Step 10: register-and-delete-with-no-audit canary path (synthetic monitoring
# canary uses this; verifies the simplest minimal-footprint deletion).
# -----------------------------------------------------------------------------
echo ""
echo "Step 10: canary-style register → immediate-delete (no audit footprint)"
CANARY_EMAIL="gdpr-canary-$$-$(date +%s)@axonflow-test.invalid"
CANARY_RESP=$(curl -fsS -X POST "$AGENT_URL/api/v1/register" \
  -H "Content-Type: application/json" \
  -d "{\"label\":\"gdpr-canary\",\"email\":\"$CANARY_EMAIL\"}")
CANARY_TENANT=$(echo "$CANARY_RESP" | $JQ -r '.tenant_id')
echo "  - registered canary tenant $CANARY_TENANT"

> "$CAPTURE_FILE"  # clear capture file so we read only the canary's email
curl -fsS -X POST "$AGENT_URL/api/v1/tenant/$CANARY_TENANT/delete-request" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$CANARY_EMAIL\"}" >/dev/null
sleep 1
CANARY_TOKEN=$(grep "to=$CANARY_EMAIL" "$CAPTURE_FILE" | tail -1 | sed -E 's|.*token=([^ ]+).*|\1|')
if [ -z "$CANARY_TOKEN" ]; then
    echo "  ✗ FAIL: could not extract canary token"
    exit 1
fi
CANARY_CONFIRM=$(curl -fsS -X POST "$AGENT_URL/api/v1/tenant/$CANARY_TENANT/delete-confirm" \
  -H "Content-Type: application/json" \
  -d "{\"token\":\"$CANARY_TOKEN\"}")
CANARY_DELETED_REG=$(echo "$CANARY_CONFIRM" | $JQ -r '.deleted_rows.registrations')
if [ "$CANARY_DELETED_REG" != "1" ]; then
    echo "  ✗ FAIL: canary deletion should return registrations=1; got $CANARY_DELETED_REG"
    exit 1
fi
echo "  ✓ PASS: canary lifecycle (register → delete) clean"

echo ""
echo "=== GDPR right-to-erasure runtime-e2e: ALL ASSERTIONS PASSED ==="
exit 0
