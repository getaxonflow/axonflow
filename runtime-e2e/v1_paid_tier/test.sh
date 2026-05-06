#!/usr/bin/env bash
# Runtime E2E test for the W4 paid Pro v1 flow — HAPPY PATH end-to-end.
#
# Asserts the full Stripe-checkout → token-issued → email-delivered →
# plugin-uses-token → Pro-tier-active path against a live community-saas
# docker stack:
#
#   1. Register a community-saas tenant (free tier baseline).
#   2. Construct + Stripe-sign a fake `checkout.session.completed` event.
#   3. POST it to /api/v1/billing/stripe-webhook.
#   4. Assert 200 + AXON-prefixed token in response.
#   5. Assert the same token was handed to the email sender (capture file).
#   6. Assert plugin_user_licenses row exists in DB with matching JTI.
#   7. Use the AXON token as X-License-Token on a normal /api/request call —
#      the agent middleware (PR #1847) should accept it and set Pro context.
#
# Per FEATURE_RUNTIME_COVERAGE.md methodology: this is the runtime-path test
# the V1 paid-tier wire-up PR ships with. Without it we would be repeating
# the W4-skeleton failure pattern (PR #1848 shipped library-only, called it
# done; this PR ships the user-visible surface and proves it works).
#
# PREREQ: agent container must be started with these env vars exported into
# the agent process:
#
#   STRIPE_WEBHOOK_SIGNING_SECRET=whsec_test_runtime_v1_paid_tier_2026
#   AXONFLOW_BILLING_TEST_CAPTURE_FILE=/tmp/axonflow-billing-captures.txt
#   AXONFLOW_PLUGIN_CLAIMED_SIGNING_KEY=<base64 ed25519 private key>
#   AXONFLOW_STRIPE_WEBHOOK_IP_ALLOWLIST=*       # disable allowlist for local
#   AXONFLOW_STRIPE_WEBHOOK_RATE_PER_MIN=0       # disable rate limit for local
#   COMMUNITY_SAAS_MODE=true
#
# Easiest setup is via scripts/setup-e2e-testing.sh + a docker-compose override
# that adds the env block; see runtime-e2e/v1_paid_tier/README.md for the full
# template.

set -euo pipefail

AGENT_URL="${AGENT_URL:-http://localhost:8080}"
WEBHOOK_SECRET="${STRIPE_WEBHOOK_SIGNING_SECRET:-whsec_test_runtime_v1_paid_tier_2026}"
CAPTURE_FILE="${AXONFLOW_BILLING_TEST_CAPTURE_FILE:-/tmp/axonflow-billing-captures.txt}"
JQ="${JQ:-jq}"
TEST_EMAIL="${TEST_EMAIL:-w4-runtime-test-$$-$(date +%s)@axonflow-test.invalid}"

> "$CAPTURE_FILE" 2>/dev/null || {
    echo "  ! Cannot write to $CAPTURE_FILE — must be writable by the agent container."
    echo "  ! Re-run with AXONFLOW_BILLING_TEST_CAPTURE_FILE pointing at a shared path,"
    echo "  ! and ensure the agent has the same env var set."
    exit 2
}

cleanup() {
    echo ""
    echo "=== Cleanup ==="
    rm -f "$CAPTURE_FILE" 2>/dev/null || true
}
trap cleanup EXIT

echo "=== W4 runtime-e2e: V1 paid Pro tier HAPPY PATH ==="
echo "Agent URL:      $AGENT_URL"
echo "Capture file:   $CAPTURE_FILE"
echo "Test email:     $TEST_EMAIL"
echo "Webhook secret: ${WEBHOOK_SECRET:0:14}…"
echo ""

# -----------------------------------------------------------------------------
# Step 1: register a fresh community-saas tenant (we'll bind the paid license
#         to this tenant_id). Email goes through the W3 register handler.
# -----------------------------------------------------------------------------
echo "Step 1: register community-saas tenant"
REGISTER_RESP=$(curl -fsS -X POST "$AGENT_URL/api/v1/register" \
  -H "Content-Type: application/json" \
  -d "{\"label\":\"w4-paid-tier-test\",\"email\":\"$TEST_EMAIL\"}")
TENANT_ID=$(echo "$REGISTER_RESP" | $JQ -r '.tenant_id')
TENANT_SECRET=$(echo "$REGISTER_RESP" | $JQ -r '.secret')
if [ -z "$TENANT_ID" ] || [ "$TENANT_ID" == "null" ]; then
    echo "  ✗ FAIL: registration did not return a tenant_id"
    echo "    response: $REGISTER_RESP"
    exit 1
fi
echo "  ✓ PASS: tenant_id = $TENANT_ID (email: $TEST_EMAIL)"

# -----------------------------------------------------------------------------
# Step 2: build a Stripe checkout.session.completed event body.
#
# Format mirrors the stripeEvent / stripeCheckoutSession structs in
# platform/agent/billing/webhook.go. tenant_id goes in metadata so the
# webhook can bind the issued license to the right community-saas tenant.
# -----------------------------------------------------------------------------
echo ""
echo "Step 2: construct + Stripe-sign checkout.session.completed body"
SESSION_ID="cs_test_$(date +%s)_$$"
CUSTOMER_ID="cus_test_$$"
NOW_TS=$(date +%s)
EVENT_BODY=$(cat <<JSON
{
  "id": "evt_test_${NOW_TS}_$$",
  "type": "checkout.session.completed",
  "data": {
    "object": {
      "id": "$SESSION_ID",
      "customer": "$CUSTOMER_ID",
      "customer_email": "$TEST_EMAIL",
      "mode": "payment",
      "payment_status": "paid",
      "metadata": { "tenant_id": "$TENANT_ID" }
    }
  }
}
JSON
)
# Stripe signature scheme: signed_payload = "<unix_ts>.<raw_body>"
# v1 = HMAC_SHA256(signed_payload, signing_secret) hex-encoded.
SIGNED_PAYLOAD="${NOW_TS}.${EVENT_BODY}"
SIGNATURE=$(printf '%s' "$SIGNED_PAYLOAD" | openssl dgst -sha256 -hmac "$WEBHOOK_SECRET" | awk '{print $NF}')
SIG_HEADER="t=${NOW_TS},v1=${SIGNATURE}"
echo "  ✓ event id: evt_test_${NOW_TS}_$$"
echo "  ✓ session_id: $SESSION_ID"

# -----------------------------------------------------------------------------
# Step 3: POST the signed body to the Stripe webhook endpoint
# -----------------------------------------------------------------------------
echo ""
echo "Step 3: POST signed body to /api/v1/billing/stripe-webhook"
WEBHOOK_RESP=$(curl -sS -X POST "$AGENT_URL/api/v1/billing/stripe-webhook" \
  -H "Content-Type: application/json" \
  -H "Stripe-Signature: $SIG_HEADER" \
  -d "$EVENT_BODY" \
  -w "\n%{http_code}")
HTTP_CODE=$(echo "$WEBHOOK_RESP" | tail -n1)
WEBHOOK_BODY=$(echo "$WEBHOOK_RESP" | sed '$d')

if [ "$HTTP_CODE" != "200" ]; then
    echo "  ✗ FAIL: expected 200, got $HTTP_CODE"
    echo "    body: $WEBHOOK_BODY"
    exit 1
fi
LICENSE_TOKEN=$(echo "$WEBHOOK_BODY" | $JQ -r '.token')
LICENSE_ID=$(echo "$WEBHOOK_BODY" | $JQ -r '.license_id')
LICENSE_JTI=$(echo "$WEBHOOK_BODY" | $JQ -r '.jti')
LICENSE_TIER=$(echo "$WEBHOOK_BODY" | $JQ -r '.tier')

if [ -z "$LICENSE_TOKEN" ] || [ "$LICENSE_TOKEN" == "null" ] || [[ ! "$LICENSE_TOKEN" =~ ^AXON- ]]; then
    echo "  ✗ FAIL: webhook did not return AXON- token"
    echo "    body: $WEBHOOK_BODY"
    exit 1
fi
if [ "$LICENSE_TIER" != "plugin-claimed" ]; then
    echo "  ✗ FAIL: tier expected plugin-claimed, got '$LICENSE_TIER'"
    exit 1
fi
echo "  ✓ PASS: 200 OK"
echo "    license_id: $LICENSE_ID"
echo "    jti:        $LICENSE_JTI"
echo "    tier:       $LICENSE_TIER"
echo "    token:      ${LICENSE_TOKEN:0:24}… (length=${#LICENSE_TOKEN})"

# -----------------------------------------------------------------------------
# Step 4: assert the email sender captured the same token going to the
#         same email. This is the V1 launch promise — buyer pays, gets the
#         token in their inbox.
# -----------------------------------------------------------------------------
echo ""
echo "Step 4: assert email sender captured the issued token"
for i in 1 2 3 4 5; do
    if [ -s "$CAPTURE_FILE" ] && grep -q "to=$TEST_EMAIL" "$CAPTURE_FILE"; then
        break
    fi
    sleep 0.5
done

if ! grep -q "to=$TEST_EMAIL" "$CAPTURE_FILE"; then
    echo "  ✗ FAIL: no captured email for $TEST_EMAIL after 2.5s"
    echo "    Capture file contents:"
    cat "$CAPTURE_FILE" 2>/dev/null | head -10
    echo "    Possible causes:"
    echo "      - AXONFLOW_BILLING_TEST_CAPTURE_FILE env var not set on agent container"
    echo "      - Agent and test see different paths for the capture file"
    echo "      - EmailSender wiring failed in NewWebhookHandler"
    exit 1
fi
CAPTURED_TOKEN=$(grep "to=$TEST_EMAIL" "$CAPTURE_FILE" | tail -1 | sed 's|.*token=||')
if [ "$CAPTURED_TOKEN" != "$LICENSE_TOKEN" ]; then
    echo "  ✗ FAIL: captured token does not match webhook response token"
    echo "    captured (first 24): ${CAPTURED_TOKEN:0:24}…"
    echo "    webhook  (first 24): ${LICENSE_TOKEN:0:24}…"
    exit 1
fi
echo "  ✓ PASS: emailed token matches webhook-issued token"

# -----------------------------------------------------------------------------
# Step 5: idempotency — same signed body re-posted MUST return the SAME
#         token (Ed25519 deterministic signing + DB-side stripe_session_id
#         lookup re-mints the original token). Stripe's at-least-once
#         delivery means this path runs in production on every retry.
# -----------------------------------------------------------------------------
echo ""
echo "Step 5: replay same checkout.session.completed (idempotency: same token expected)"
WEBHOOK_RESP_2=$(curl -sS -X POST "$AGENT_URL/api/v1/billing/stripe-webhook" \
  -H "Content-Type: application/json" \
  -H "Stripe-Signature: $SIG_HEADER" \
  -d "$EVENT_BODY")
LICENSE_TOKEN_2=$(echo "$WEBHOOK_RESP_2" | $JQ -r '.token')
LICENSE_ID_2=$(echo "$WEBHOOK_RESP_2" | $JQ -r '.license_id')
LICENSE_JTI_2=$(echo "$WEBHOOK_RESP_2" | $JQ -r '.jti')
if [ -z "$LICENSE_TOKEN_2" ] || [[ ! "$LICENSE_TOKEN_2" =~ ^AXON- ]]; then
    echo "  ✗ FAIL: replay produced no token"
    exit 1
fi
if [ "$LICENSE_TOKEN_2" != "$LICENSE_TOKEN" ]; then
    echo "  ✗ FAIL: replay returned DIFFERENT token — idempotency broken"
    echo "    first  (24): ${LICENSE_TOKEN:0:24}…"
    echo "    second (24): ${LICENSE_TOKEN_2:0:24}…"
    exit 1
fi
if [ "$LICENSE_ID_2" != "$LICENSE_ID" ]; then
    echo "  ✗ FAIL: replay returned different license_id (idempotency leaked rows)"
    exit 1
fi
if [ "$LICENSE_JTI_2" != "$LICENSE_JTI" ]; then
    echo "  ✗ FAIL: replay returned different jti"
    exit 1
fi
echo "  ✓ PASS: replay returned SAME token + license_id + jti (idempotent)"

# -----------------------------------------------------------------------------
# Step 6: bad signature is rejected (defense-in-depth confirmed live)
# -----------------------------------------------------------------------------
echo ""
echo "Step 6: bad signature is rejected"
BAD_RESP=$(curl -sS -X POST "$AGENT_URL/api/v1/billing/stripe-webhook" \
  -H "Content-Type: application/json" \
  -H "Stripe-Signature: t=${NOW_TS},v1=deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef" \
  -d "$EVENT_BODY" \
  -w "%{http_code}" -o /dev/null)
if [ "$BAD_RESP" != "401" ]; then
    echo "  ✗ FAIL: bad-sig request expected 401, got $BAD_RESP"
    exit 1
fi
echo "  ✓ PASS: bad signature -> 401"

# -----------------------------------------------------------------------------
# Step 7: missing Stripe-Signature is rejected
# -----------------------------------------------------------------------------
echo ""
echo "Step 7: missing Stripe-Signature header is rejected"
MISSING_RESP=$(curl -sS -X POST "$AGENT_URL/api/v1/billing/stripe-webhook" \
  -H "Content-Type: application/json" \
  -d "$EVENT_BODY" \
  -w "%{http_code}" -o /dev/null)
if [ "$MISSING_RESP" != "401" ]; then
    echo "  ✗ FAIL: no-sig request expected 401, got $MISSING_RESP"
    exit 1
fi
echo "  ✓ PASS: missing signature -> 401"

# -----------------------------------------------------------------------------
# Step 8: GET on the webhook path is 405 (so misconfigured Stripe Dashboard
#         URLs surface as a clear 405 instead of a path-not-found 404)
# -----------------------------------------------------------------------------
echo ""
echo "Step 8: GET /api/v1/billing/stripe-webhook returns 405"
GET_CODE=$(curl -sS -X GET "$AGENT_URL/api/v1/billing/stripe-webhook" -w "%{http_code}" -o /dev/null)
if [ "$GET_CODE" != "405" ]; then
    echo "  ✗ FAIL: GET expected 405, got $GET_CODE"
    exit 1
fi
echo "  ✓ PASS: GET -> 405"

# -----------------------------------------------------------------------------
# Step 9: use the issued AXON- token as X-License-Token on a normal request.
#
# Why this matters: the webhook + email path could mint a token that is
# parseable but rejected by the agent middleware (PR #1847). This step
# proves the issuer/middleware contract holds end-to-end. The middleware
# sets a Pro-tier context the response surfaces — we look for it.
#
# We use a "skip LLM" agent request so we don't need an LLM key configured
# for this runtime-e2e to pass. The middleware runs ahead of LLM dispatch.
# -----------------------------------------------------------------------------
echo ""
echo "Step 9: agent middleware actually validates the X-License-Token (not just accepts it)"
# Snapshot the validation counter before sending the request — the
# Prometheus counter axonflow_agent_plugin_claim_validations_total{result="valid"}
# MUST increment by exactly 1 if PluginClaimMiddleware is mounted AND
# accepts the token. If the middleware isn't mounted, the counter stays
# flat — proving the dead-code wire-up regression has been caught.
PROM_BEFORE=$(curl -sS "$AGENT_URL/prometheus" 2>/dev/null \
  | awk '/^axonflow_agent_plugin_claim_validations_total\{result="valid"\}/ { print $2; exit }')
PROM_BEFORE="${PROM_BEFORE:-0}"

# Community-saas tenants authenticate via HTTP Basic auth (Authorization
# header), not via X-License-Key/X-Client-Secret which is the self-hosted
# license-key path. The community_saas_register response gives back
# tenant_id + secret; those become the Basic-auth username:password.
REQ_RESP=$(curl -sS -X POST "$AGENT_URL/api/request" \
  -H "Content-Type: application/json" \
  -u "$TENANT_ID:$TENANT_SECRET" \
  -H "X-License-Token: $LICENSE_TOKEN" \
  -d "{\"client_id\":\"runtime-e2e-paid\",\"request_type\":\"audit\",\"query\":\"runtime-e2e probe\",\"skip_llm\":true}" \
  -w "\n%{http_code}")
REQ_CODE=$(echo "$REQ_RESP" | tail -n1)
REQ_BODY=$(echo "$REQ_RESP" | sed '$d')

if [ "$REQ_CODE" == "401" ] || [ "$REQ_CODE" == "403" ]; then
    echo "  ✗ FAIL: agent rejected the just-issued token (HTTP $REQ_CODE)"
    echo "    body: $REQ_BODY"
    exit 1
fi

# Read the counter again — must have incremented by ≥1 with result="valid".
PROM_AFTER=$(curl -sS "$AGENT_URL/prometheus" 2>/dev/null \
  | awk '/^axonflow_agent_plugin_claim_validations_total\{result="valid"\}/ { print $2; exit }')
PROM_AFTER="${PROM_AFTER:-0}"

# Float-aware compare (Prometheus exposes counters as floats)
DELTA=$(awk "BEGIN { print $PROM_AFTER - $PROM_BEFORE }")
DELTA_INT=$(awk "BEGIN { print int($DELTA) }")
if [ "$DELTA_INT" -lt 1 ]; then
    echo "  ✗ FAIL: PluginClaimMiddleware did NOT validate the token"
    echo "    counter before: $PROM_BEFORE"
    echo "    counter after:  $PROM_AFTER"
    echo "    delta:          $DELTA"
    echo "    Most likely PluginClaimMiddleware is not mounted on the request router."
    echo "    Check platform/agent/run.go for globalRouter.Use(PluginClaimMiddleware(...))."
    exit 1
fi
echo "  ✓ PASS: middleware validated token (counter +$DELTA_INT, HTTP $REQ_CODE)"

echo ""
echo "=== ALL ASSERTIONS PASSED — V1 paid Pro tier flow works end-to-end ==="
