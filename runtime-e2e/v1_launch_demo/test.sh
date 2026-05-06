#!/usr/bin/env bash
# V1 launch end-to-end demo orchestrator.
#
# Drives the full V1 paid-tier story against a live community-saas stack:
#
#   1. Stripe checkout → webhook → token issued + emailed
#   2. Each of the 4 plugins (OpenClaw, Cursor, Codex, Claude Code) sends a
#      governed agent request with X-License-Token = the issued token
#   3. PluginClaimMiddleware validation counter must increment ≥ 1 per plugin
#   4. W3 free-tier recovery flow (independent of paid Pro): register →
#      "lose" credentials → POST /recover → verify magic-link → assert new
#      credentials work
#
# This is the script to run against try.getaxonflow.com after the platform
# rolls forward and the 4 plugins are tagged. Until then it runs against a
# local docker-compose stack with the v1-paid-tier overlay.
#
# Per FEATURE_RUNTIME_COVERAGE.md: this is the V1 launch acceptance test.
# Exit 0 = V1 paid tier ships. Anything else = blocker.
#
# Sibling plugin checkouts (each at ../axonflow-<plugin>-plugin) are
# REQUIRED — overridable via env:
#   OPENCLAW_PLUGIN_DIR  (default: ../axonflow-openclaw-plugin)
#   CURSOR_PLUGIN_DIR    (default: ../axonflow-cursor-plugin)
#   CODEX_PLUGIN_DIR     (default: ../axonflow-codex-plugin)
#   CLAUDE_PLUGIN_DIR    (default: ../axonflow-claude-plugin)
# Pass SKIP_PLUGINS=cursor,codex to run only a subset.
#
# Agent stack env (must be set on the agent container as well):
#   STRIPE_WEBHOOK_SIGNING_SECRET=whsec_test_runtime_v1_paid_tier_2026
#   AXONFLOW_BILLING_TEST_CAPTURE_FILE=/tmp/axonflow-billing-captures.txt
#   AXONFLOW_RECOVERY_TEST_CAPTURE_FILE=/tmp/axonflow-recovery-captures.txt
#   AXONFLOW_PLUGIN_CLAIMED_SIGNING_KEY=<base64 ed25519 seed>
#   AXONFLOW_STRIPE_WEBHOOK_IP_ALLOWLIST=*
#   AXONFLOW_STRIPE_WEBHOOK_RATE_PER_MIN=0
#   COMMUNITY_SAAS_MODE=true

set -euo pipefail

AGENT_URL="${AGENT_URL:-http://localhost:8080}"
WEBHOOK_SECRET="${STRIPE_WEBHOOK_SIGNING_SECRET:-whsec_test_runtime_v1_paid_tier_2026}"
BILLING_CAPTURE_FILE="${AXONFLOW_BILLING_TEST_CAPTURE_FILE:-/tmp/axonflow-billing-captures.txt}"
RECOVERY_CAPTURE_FILE="${AXONFLOW_RECOVERY_TEST_CAPTURE_FILE:-/tmp/axonflow-recovery-captures.txt}"
JQ="${JQ:-jq}"

# Default sibling-checkout layout. Override per env var if your tree differs.
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
DEV_ROOT="$(dirname "$REPO_ROOT")"
OPENCLAW_PLUGIN_DIR="${OPENCLAW_PLUGIN_DIR:-$DEV_ROOT/axonflow-openclaw-plugin}"
CURSOR_PLUGIN_DIR="${CURSOR_PLUGIN_DIR:-$DEV_ROOT/axonflow-cursor-plugin}"
CODEX_PLUGIN_DIR="${CODEX_PLUGIN_DIR:-$DEV_ROOT/axonflow-codex-plugin}"
CLAUDE_PLUGIN_DIR="${CLAUDE_PLUGIN_DIR:-$DEV_ROOT/axonflow-claude-plugin}"
SKIP_PLUGINS="${SKIP_PLUGINS:-}"

TEST_EMAIL="${TEST_EMAIL:-v1-launch-demo-$$-$(date +%s)@axonflow-test.invalid}"

# Reset capture files so we don't grab stale tokens from prior runs.
> "$BILLING_CAPTURE_FILE" 2>/dev/null || {
    echo "  ! Cannot write to $BILLING_CAPTURE_FILE — must be writable by the agent container."
    exit 2
}
> "$RECOVERY_CAPTURE_FILE" 2>/dev/null || {
    echo "  ! Cannot write to $RECOVERY_CAPTURE_FILE — must be writable by the agent container."
    exit 2
}

cleanup() {
    echo ""
    echo "=== Cleanup ==="
    rm -f "$BILLING_CAPTURE_FILE" "$RECOVERY_CAPTURE_FILE" 2>/dev/null || true
}
trap cleanup EXIT

# Convenience for green/red output without depending on a terminal lib.
ok()    { echo "  ✓ $*"; }
fail()  { echo "  ✗ $*"; exit 1; }
note()  { echo "  · $*"; }
skip()  { echo "  ⊘ skipping: $*"; }

want_plugin() {
    local name="$1"
    case ",$SKIP_PLUGINS," in *",$name,"*) return 1 ;; esac
    return 0
}

echo "==========================================================================="
echo "V1 LAUNCH DEMO — Stripe checkout → token email → 4 plugins → recovery flow"
echo "==========================================================================="
echo "  Agent URL:      $AGENT_URL"
echo "  Test email:     $TEST_EMAIL"
echo "  Webhook secret: ${WEBHOOK_SECRET:0:14}…"
echo "  Plugin dirs:    OpenClaw=$OPENCLAW_PLUGIN_DIR"
echo "                  Cursor=$CURSOR_PLUGIN_DIR"
echo "                  Codex=$CODEX_PLUGIN_DIR"
echo "                  Claude=$CLAUDE_PLUGIN_DIR"
echo "  Skip plugins:   ${SKIP_PLUGINS:-(none)}"
echo ""

# ---------------------------------------------------------------------------
# Phase 1: register a community-saas tenant + simulate Stripe checkout
# ---------------------------------------------------------------------------
echo "PHASE 1 — Stripe checkout → token issued + emailed"
echo "---"

REGISTER_RESP=$(curl -fsS -X POST "$AGENT_URL/api/v1/register" \
  -H "Content-Type: application/json" \
  -d "{\"label\":\"v1-launch-demo\",\"email\":\"$TEST_EMAIL\"}")
TENANT_ID=$(echo "$REGISTER_RESP" | $JQ -r '.tenant_id')
TENANT_SECRET=$(echo "$REGISTER_RESP" | $JQ -r '.secret')
[ -n "$TENANT_ID" ] && [ "$TENANT_ID" != "null" ] || fail "registration did not return tenant_id"
ok "registered tenant $TENANT_ID for $TEST_EMAIL"

SESSION_ID="cs_v1demo_$(date +%s)_$$"
NOW_TS=$(date +%s)
EVENT_BODY=$(cat <<JSON
{
  "id": "evt_v1demo_${NOW_TS}_$$",
  "type": "checkout.session.completed",
  "data": {
    "object": {
      "id": "$SESSION_ID",
      "customer": "cus_v1demo_$$",
      "customer_email": "$TEST_EMAIL",
      "mode": "payment",
      "payment_status": "paid",
      "metadata": { "tenant_id": "$TENANT_ID" }
    }
  }
}
JSON
)
SIGNED_PAYLOAD="${NOW_TS}.${EVENT_BODY}"
SIGNATURE=$(printf '%s' "$SIGNED_PAYLOAD" | openssl dgst -sha256 -hmac "$WEBHOOK_SECRET" | awk '{print $NF}')
SIG_HEADER="t=${NOW_TS},v1=${SIGNATURE}"

WEBHOOK_RESP=$(curl -sS -X POST "$AGENT_URL/api/v1/billing/stripe-webhook" \
  -H "Content-Type: application/json" \
  -H "Stripe-Signature: $SIG_HEADER" \
  -d "$EVENT_BODY" -w "\n%{http_code}")
HTTP_CODE=$(echo "$WEBHOOK_RESP" | tail -n1)
WEBHOOK_BODY=$(echo "$WEBHOOK_RESP" | sed '$d')
[ "$HTTP_CODE" = "200" ] || fail "webhook returned $HTTP_CODE: $WEBHOOK_BODY"
LICENSE_TOKEN=$(echo "$WEBHOOK_BODY" | $JQ -r '.token')
LICENSE_JTI=$(echo "$WEBHOOK_BODY" | $JQ -r '.jti')
[[ "$LICENSE_TOKEN" =~ ^AXON- ]] || fail "webhook returned non-AXON token"
ok "webhook 200 OK, AXON token issued (jti=$LICENSE_JTI)"

# Email delivery — wait briefly for capture-file write to land
for i in 1 2 3 4 5; do
    grep -q "to=$TEST_EMAIL" "$BILLING_CAPTURE_FILE" 2>/dev/null && break
    sleep 0.5
done
grep -q "to=$TEST_EMAIL" "$BILLING_CAPTURE_FILE" || fail "no email captured for $TEST_EMAIL"
CAPTURED_TOKEN=$(grep "to=$TEST_EMAIL" "$BILLING_CAPTURE_FILE" | tail -1 | sed 's|.*token=||')
[ "$CAPTURED_TOKEN" = "$LICENSE_TOKEN" ] || fail "emailed token differs from response token"
ok "email captured with matching token"

# ---------------------------------------------------------------------------
# Phase 2: each plugin sends a governed request with X-License-Token,
# the agent's PluginClaimMiddleware validation counter must increment.
# ---------------------------------------------------------------------------
echo ""
echo "PHASE 2 — 4 plugins forward X-License-Token, middleware accepts each"
echo "---"

prom_valid_count() {
    # Returns "0" when the metric line isn't present yet (no successful
    # validation has happened, so the labelled counter hasn't registered).
    # Without the explicit fallback, `set -o pipefail` on the caller side
    # propagates grep's exit-1 (no match) and silently aborts the function.
    local out
    out=$(curl -sS "$AGENT_URL/prometheus" 2>/dev/null \
      | awk '/^axonflow_agent_plugin_claim_validations_total\{result="valid"\}/ { print $2; exit }')
    echo "${out:-0}"
}

run_plugin_request() {
    # Generic per-plugin probe: hit /api/request with the plugin's
    # tenant + secret + the new license token, assert the validation
    # counter incremented. Each plugin's pre-tool-check.sh is also
    # verified to forward X-License-Token via its own runtime test in
    # the plugin repo; this orchestrator confirms the agent side sees it.
    local plugin_name="$1"
    local before after delta_int
    before=$(prom_valid_count); before="${before:-0}"

    # Community-saas tenants authenticate via HTTP Basic auth, not via
    # X-License-Key/X-Client-Secret (that's the self-hosted license-key
    # path). The community_saas_register response gives back tenant_id +
    # secret; those become the Basic-auth username:password.
    local resp
    resp=$(curl -sS -X POST "$AGENT_URL/api/request" \
      -H "Content-Type: application/json" \
      -u "$TENANT_ID:$TENANT_SECRET" \
      -H "X-License-Token: $LICENSE_TOKEN" \
      -d "{\"client_id\":\"v1-demo-${plugin_name}\",\"request_type\":\"audit\",\"query\":\"v1 launch demo $plugin_name\",\"skip_llm\":true}" \
      -w "\n%{http_code}")
    local code; code=$(echo "$resp" | tail -n1)
    local body; body=$(echo "$resp" | sed '$d')

    if [ "$code" = "401" ] || [ "$code" = "403" ]; then
        echo "    body: $body"
        fail "$plugin_name: agent rejected the X-License-Token (HTTP $code)"
    fi

    after=$(prom_valid_count); after="${after:-0}"
    delta_int=$(awk "BEGIN { print int($after - $before) }")
    if [ "$delta_int" -lt 1 ]; then
        fail "$plugin_name: middleware did not validate token (counter $before → $after)"
    fi
    ok "$plugin_name: middleware validated token (counter +$delta_int, HTTP $code)"
}

if want_plugin openclaw; then
    if [ -d "$OPENCLAW_PLUGIN_DIR" ]; then
        run_plugin_request openclaw
    else
        skip "OpenClaw — $OPENCLAW_PLUGIN_DIR not present (set OPENCLAW_PLUGIN_DIR or use SKIP_PLUGINS=openclaw)"
    fi
fi

if want_plugin cursor; then
    if [ -d "$CURSOR_PLUGIN_DIR" ]; then
        run_plugin_request cursor
    else
        skip "Cursor — $CURSOR_PLUGIN_DIR not present"
    fi
fi

if want_plugin codex; then
    if [ -d "$CODEX_PLUGIN_DIR" ]; then
        run_plugin_request codex
    else
        skip "Codex — $CODEX_PLUGIN_DIR not present"
    fi
fi

if want_plugin claude; then
    if [ -d "$CLAUDE_PLUGIN_DIR" ]; then
        run_plugin_request claude
    else
        skip "Claude Code — $CLAUDE_PLUGIN_DIR not present"
    fi
fi

# ---------------------------------------------------------------------------
# Phase 3: replay protection — same Stripe webhook returns SAME token
# (regression guard for GAP-2 idempotency)
# ---------------------------------------------------------------------------
echo ""
echo "PHASE 3 — webhook idempotency: replay returns identical token"
echo "---"

WEBHOOK_RESP_2=$(curl -sS -X POST "$AGENT_URL/api/v1/billing/stripe-webhook" \
  -H "Content-Type: application/json" \
  -H "Stripe-Signature: $SIG_HEADER" \
  -d "$EVENT_BODY")
LICENSE_TOKEN_2=$(echo "$WEBHOOK_RESP_2" | $JQ -r '.token')
LICENSE_JTI_2=$(echo "$WEBHOOK_RESP_2" | $JQ -r '.jti')
[ "$LICENSE_TOKEN_2" = "$LICENSE_TOKEN" ] || fail "replay returned DIFFERENT token (idempotency broken)"
[ "$LICENSE_JTI_2" = "$LICENSE_JTI" ] || fail "replay returned different jti"
ok "replay returned IDENTICAL token + jti (GAP-2 idempotency intact)"

# ---------------------------------------------------------------------------
# Phase 4: W3 free-tier credential recovery (independent of paid Pro)
# ---------------------------------------------------------------------------
echo ""
echo "PHASE 4 — W3 free-tier credential recovery flow"
echo "---"

RECOVER_EMAIL="recover-$$-$(date +%s)@axonflow-test.invalid"
> "$RECOVERY_CAPTURE_FILE" 2>/dev/null || true

# Register a fresh tenant with email
REG_RESP=$(curl -fsS -X POST "$AGENT_URL/api/v1/register" \
  -H "Content-Type: application/json" \
  -d "{\"label\":\"recover-test\",\"email\":\"$RECOVER_EMAIL\"}")
ORIG_TENANT=$(echo "$REG_RESP" | $JQ -r '.tenant_id')
[ -n "$ORIG_TENANT" ] && [ "$ORIG_TENANT" != "null" ] || fail "register did not return tenant"
ok "registered original tenant $ORIG_TENANT"

# Request recovery (simulates user losing credentials)
RECOVER_CODE=$(curl -sS -X POST "$AGENT_URL/api/v1/recover" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$RECOVER_EMAIL\"}" -w "%{http_code}" -o /dev/null)
[ "$RECOVER_CODE" = "202" ] || fail "/api/v1/recover returned $RECOVER_CODE (want 202)"
ok "recovery request accepted (anti-enum 202)"

# Read magic-link token from capture file
for i in 1 2 3 4 5; do
    grep -q "to=$RECOVER_EMAIL" "$RECOVERY_CAPTURE_FILE" 2>/dev/null && break
    sleep 0.5
done
grep -q "to=$RECOVER_EMAIL" "$RECOVERY_CAPTURE_FILE" || fail "no magic link captured for $RECOVER_EMAIL"
MAGIC_TOKEN=$(grep "to=$RECOVER_EMAIL" "$RECOVERY_CAPTURE_FILE" | tail -1 | sed 's|.*token=||')
[ ${#MAGIC_TOKEN} -ge 32 ] || fail "magic-link token suspiciously short (${#MAGIC_TOKEN} chars)"
ok "magic-link token captured (${#MAGIC_TOKEN} chars)"

# Verify the magic link
VERIFY_RESP=$(curl -fsS -X POST "$AGENT_URL/api/v1/recover/verify" \
  -H "Content-Type: application/json" \
  -d "{\"token\":\"$MAGIC_TOKEN\"}")
NEW_TENANT=$(echo "$VERIFY_RESP" | $JQ -r '.tenant_id')
NEW_SECRET=$(echo "$VERIFY_RESP" | $JQ -r '.secret')
RECOVERED_EMAIL=$(echo "$VERIFY_RESP" | $JQ -r '.email')
[ -n "$NEW_TENANT" ] && [ "$NEW_TENANT" != "null" ] || fail "verify did not return tenant_id"
[ "$NEW_TENANT" != "$ORIG_TENANT" ] || fail "recovery should produce a NEW tenant_id"
[ "$RECOVERED_EMAIL" = "$RECOVER_EMAIL" ] || fail "recovered email mismatch"
ok "recovery issued new tenant $NEW_TENANT bound to $RECOVER_EMAIL"

# Replay the magic link — must be rejected
REPLAY_CODE=$(curl -sS -X POST "$AGENT_URL/api/v1/recover/verify" \
  -H "Content-Type: application/json" \
  -d "{\"token\":\"$MAGIC_TOKEN\"}" -w "%{http_code}" -o /dev/null)
[ "$REPLAY_CODE" = "401" ] || fail "magic-link replay returned $REPLAY_CODE (want 401 — single-use invariant)"
ok "magic-link replay rejected (401, single-use invariant)"

# ---------------------------------------------------------------------------
# Phase 5: bad signature / missing signature on webhook still rejected
# (regression guard — defense in depth on the now-mounted webhook)
# ---------------------------------------------------------------------------
echo ""
echo "PHASE 5 — webhook defense-in-depth (bad / missing signature)"
echo "---"

BAD_CODE=$(curl -sS -X POST "$AGENT_URL/api/v1/billing/stripe-webhook" \
  -H "Content-Type: application/json" \
  -H "Stripe-Signature: t=${NOW_TS},v1=deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef" \
  -d "$EVENT_BODY" -w "%{http_code}" -o /dev/null)
[ "$BAD_CODE" = "401" ] || fail "bad-sig webhook returned $BAD_CODE (want 401)"
ok "bad-sig webhook → 401"

MISSING_CODE=$(curl -sS -X POST "$AGENT_URL/api/v1/billing/stripe-webhook" \
  -H "Content-Type: application/json" \
  -d "$EVENT_BODY" -w "%{http_code}" -o /dev/null)
[ "$MISSING_CODE" = "401" ] || fail "missing-sig webhook returned $MISSING_CODE (want 401)"
ok "missing-sig webhook → 401"

GET_CODE=$(curl -sS -X GET "$AGENT_URL/api/v1/billing/stripe-webhook" -w "%{http_code}" -o /dev/null)
[ "$GET_CODE" = "405" ] || fail "GET webhook returned $GET_CODE (want 405)"
ok "GET webhook → 405"

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
echo ""
echo "==========================================================================="
echo "V1 LAUNCH DEMO PASSED — Stripe → token → email → 4 plugins → recovery"
echo "==========================================================================="
