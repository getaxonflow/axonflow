#!/usr/bin/env bash
# OpenClaw plugin V1 paid-tier walkthrough — runs against on-demand staging.
#
# This is the AUTOMATED walkthrough (CLI-based; OpenClaw doesn't depend on
# an IDE host). Drives the full V1 user flow against
# https://try-staging.getaxonflow.com:
#
#   1. Install the plugin from npm (or local tarball).
#   2. Auto-bootstrap a community-saas tenant on first call.
#   3. Run `axonflow-openclaw-status` — verify tenant_id surfaces.
#   4. Trigger recovery — verify magic link is sent to dev@getaxonflow.com.
#      (Manual step: operator clicks link from inbox or Resend dashboard.)
#   5. Verify recovered credentials persist.
#   6. (BUYER FLOW — manual step) Use the captured tenant_id at the
#      Stripe TEST Payment Link, pay with 4242 4242 4242 4242.
#      (Automated alternative: use `stripe trigger` if Stripe CLI is on PATH.)
#   7. Capture the AXON-… token from email/Resend.
#   8. Configure plugin with token, run a governed call, verify Pro tier.
#
# Run AS-IS: `bash openclaw_walkthrough.sh`. Override defaults via env:
#   AGENT_URL                — defaults to https://try-staging.getaxonflow.com
#   TEST_EMAIL               — defaults to dev@getaxonflow.com
#   STRIPE_TEST_PAYMENT_LINK — Stripe Payment Link URL (Test mode)
#   STRIPE_CLI_AUTO_TRIGGER  — set to 1 to use `stripe trigger` (skip Payment Link UI)

set -uo pipefail

AGENT_URL="${AGENT_URL:-https://try-staging.getaxonflow.com}"
TEST_EMAIL="${TEST_EMAIL:-dev@getaxonflow.com}"
STRIPE_TEST_PAYMENT_LINK="${STRIPE_TEST_PAYMENT_LINK:-(set this env var to your Stripe TEST Payment Link)}"
STRIPE_CLI_AUTO_TRIGGER="${STRIPE_CLI_AUTO_TRIGGER:-0}"

WORKDIR=$(mktemp -d 2>/dev/null || mktemp -d -t openclaw-staging)
export AXONFLOW_CONFIG_DIR="$WORKDIR/.config/axonflow"
mkdir -p "$AXONFLOW_CONFIG_DIR"
chmod 0700 "$AXONFLOW_CONFIG_DIR"

PASS=0
FAIL=0
SKIP=0
fail() { echo "  ❌ FAIL: $1"; FAIL=$((FAIL+1)); }
pass() { echo "  ✅ PASS: $1"; PASS=$((PASS+1)); }
skip() { echo "  ⏭️  SKIP: $1"; SKIP=$((SKIP+1)); }
note() { echo "  📝 $1"; }
sect() { echo ""; echo "===== $1 ====="; }

cleanup() {
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

echo "OpenClaw V1 paid-tier walkthrough — staging"
echo "  AGENT_URL  = $AGENT_URL"
echo "  TEST_EMAIL = $TEST_EMAIL"
echo "  WORKDIR    = $WORKDIR (cleaned on exit)"

# ---------------------------------------------------------------------------
# 0. preflight
# ---------------------------------------------------------------------------
sect "Preflight"
if ! command -v node >/dev/null 2>&1 || ! command -v npm >/dev/null 2>&1; then
  fail "node/npm not on PATH"
  exit 1
fi
pass "node + npm available"

# Verify staging is reachable before anything else.
HEALTH=$(curl -sS -o /dev/null -w "%{http_code}" --max-time 5 "$AGENT_URL/health" || echo "000")
if [ "$HEALTH" = "200" ]; then
  pass "$AGENT_URL/health responds 200"
else
  fail "staging unreachable — got HTTP $HEALTH from $AGENT_URL/health"
  echo "   Is the on-demand staging stack provisioned? Run:"
  echo "     gh workflow run deploy-platform.yml -f environment=community-saas-staging"
  exit 1
fi

# ---------------------------------------------------------------------------
# 1. install plugin
# ---------------------------------------------------------------------------
sect "Step 1 — install OpenClaw plugin"
cd "$WORKDIR"

# OPENCLAW_SOURCE controls where the plugin comes from:
#   - default (unset)            → install from local checkout at
#                                   /Users/saurabhjain/Development/axonflow-openclaw-plugin
#                                   (required while v2.2.0 with status+recover
#                                    bins is unpublished)
#   - "npm" + OPENCLAW_VERSION   → install @axonflow/openclaw@<version> from
#                                   npm registry. Use this once v2.2.0+ is live.
OPENCLAW_SOURCE="${OPENCLAW_SOURCE:-local}"
LOCAL_PLUGIN_DIR="${LOCAL_PLUGIN_DIR:-/Users/saurabhjain/Development/axonflow-openclaw-plugin}"

if [ "$OPENCLAW_SOURCE" = "npm" ]; then
  OPENCLAW_VERSION="${OPENCLAW_VERSION:-latest}"
  note "installing @axonflow/openclaw@$OPENCLAW_VERSION from npm"
  if npm install --no-save --silent "@axonflow/openclaw@$OPENCLAW_VERSION" >"$WORKDIR/npm-install.log" 2>&1; then
    pass "@axonflow/openclaw@$OPENCLAW_VERSION installed from npm"
  else
    fail "npm install failed — see $WORKDIR/npm-install.log"
    tail -20 "$WORKDIR/npm-install.log"
    exit 1
  fi
else
  if [ ! -d "$LOCAL_PLUGIN_DIR" ]; then
    fail "LOCAL_PLUGIN_DIR ($LOCAL_PLUGIN_DIR) not found — set OPENCLAW_SOURCE=npm OR override LOCAL_PLUGIN_DIR"
    exit 1
  fi
  note "installing local plugin checkout from $LOCAL_PLUGIN_DIR"
  # Ensure the local checkout has dist/ built — npm install from a local
  # path doesn't run prepare scripts on the source.
  if [ ! -d "$LOCAL_PLUGIN_DIR/dist" ]; then
    note "  building plugin first (npm run build in $LOCAL_PLUGIN_DIR)"
    (cd "$LOCAL_PLUGIN_DIR" && npm run build) >"$WORKDIR/plugin-build.log" 2>&1 \
      || { fail "plugin build failed — see $WORKDIR/plugin-build.log"; tail -10 "$WORKDIR/plugin-build.log"; exit 1; }
  fi
  if npm install --no-save --silent "$LOCAL_PLUGIN_DIR" >"$WORKDIR/npm-install.log" 2>&1; then
    pass "local plugin installed"
  else
    fail "local install failed — see $WORKDIR/npm-install.log"
    tail -20 "$WORKDIR/npm-install.log"
    exit 1
  fi
fi

# The bin scripts ship via package.json's bin field. Resolve via npm bin paths.
STATUS_BIN="$WORKDIR/node_modules/.bin/axonflow-openclaw-status"
RECOVER_BIN="$WORKDIR/node_modules/.bin/axonflow-openclaw-recover"
[ -x "$STATUS_BIN" ] && pass "axonflow-openclaw-status bin present" \
  || fail "missing $STATUS_BIN — does the plugin's package.json declare it?"
[ -x "$RECOVER_BIN" ] && pass "axonflow-openclaw-recover bin present" \
  || fail "missing $RECOVER_BIN"

# ---------------------------------------------------------------------------
# 2. status (tenant not yet bootstrapped → "not registered")
# ---------------------------------------------------------------------------
sect "Step 2 — status before any call (free tier, unregistered)"
STATUS_OUT=$(AXONFLOW_ENDPOINT="$AGENT_URL" "$STATUS_BIN" --json 2>&1) || true
echo "$STATUS_OUT" | head -10

# Tenant should be null at this point — auto-bootstrap happens on first
# governed call, not on status.
TENANT_AT_STATUS=$(echo "$STATUS_OUT" | python3 -c "import json, sys; j=json.load(sys.stdin); print(j.get('tenant_id') or '')" 2>/dev/null || echo "")
if [ -z "$TENANT_AT_STATUS" ]; then
  pass "tenant_id is null on first status (auto-bootstrap deferred to first governed call)"
else
  note "tenant_id already present ($TENANT_AT_STATUS) — registration must have run earlier"
fi

# ---------------------------------------------------------------------------
# 3. trigger auto-bootstrap by exercising a governed call shape
#    (community-saas register endpoint persists try-registration.json)
# ---------------------------------------------------------------------------
sect "Step 3 — auto-bootstrap a community-saas tenant"

# The plugin auto-registers on first AxonFlowClient call. Since the
# published @axonflow/openclaw is ESM and pre-bin-scripts, we trigger
# the same effect by directly hitting POST /api/v1/register and writing
# the response to the registration file the bins expect.
REG_FILE="$AXONFLOW_CONFIG_DIR/try-registration.json"
REG_RESP=$(curl -fsS -X POST "$AGENT_URL/api/v1/register" \
  -H "Content-Type: application/json" \
  -d "{\"label\":\"openclaw-staging-walkthrough-$$\",\"email\":\"$TEST_EMAIL\"}" 2>"$WORKDIR/register.err" || echo "")
if [ -n "$REG_RESP" ]; then
  echo "$REG_RESP" > "$REG_FILE"
  chmod 0600 "$REG_FILE"
  TENANT_FROM_REG=$(echo "$REG_RESP" | python3 -c "import json, sys; print(json.load(sys.stdin).get('tenant_id') or '')" 2>/dev/null)
  pass "register endpoint returned tenant_id = $TENANT_FROM_REG"
else
  note "register failed — see $WORKDIR/register.err"
  tail -5 "$WORKDIR/register.err"
fi

# Status now should show a tenant_id.
sleep 2
STATUS_AFTER=$(AXONFLOW_ENDPOINT="$AGENT_URL" "$STATUS_BIN" --json 2>&1)
TENANT_ID=$(echo "$STATUS_AFTER" | python3 -c "import json, sys; j=json.load(sys.stdin); print(j.get('tenant_id') or '')" 2>/dev/null || echo "")
if [ -n "$TENANT_ID" ]; then
  pass "auto-bootstrap completed — tenant_id = $TENANT_ID"
else
  fail "auto-bootstrap did not persist a tenant_id; status = $STATUS_AFTER"
fi

# ---------------------------------------------------------------------------
# 4. recovery flow
# ---------------------------------------------------------------------------
sect "Step 4 — recovery flow (delete creds, recover via magic link)"
REG_FILE="$AXONFLOW_CONFIG_DIR/try-registration.json"
[ -f "$REG_FILE" ] && pass "registration file present pre-delete" || fail "no registration file at $REG_FILE"

# Save the tenant_id so we can verify recovery returns the same one.
ORIG_TENANT="$TENANT_ID"
rm -f "$REG_FILE"
[ ! -f "$REG_FILE" ] && pass "registration file deleted (simulating lost laptop)" || fail "could not delete $REG_FILE"

# Trigger recovery — sends magic link to TEST_EMAIL via Resend. The bin
# accepts the email as the only positional arg and prompts on stdin for
# the magic-link token. We use --token-file to keep it non-interactive.
TOKEN_FILE="$WORKDIR/recovery-token.txt"
note "triggering recovery for $TEST_EMAIL — magic link will be sent to that inbox"
if [ -n "${RECOVERY_TOKEN:-}" ]; then
  echo "$RECOVERY_TOKEN" > "$TOKEN_FILE"
  if AXONFLOW_ENDPOINT="$AGENT_URL" "$RECOVER_BIN" "$TEST_EMAIL" --token-file "$TOKEN_FILE" 2>&1 | tee "$WORKDIR/recover.log" | head -20; then
    pass "recovery completed end-to-end with provided RECOVERY_TOKEN"
  else
    fail "recovery failed — see $WORKDIR/recover.log"
  fi
else
  # Without a pre-supplied token, drive only the request step. The bin
  # prompts on stdin for the magic-link token after the request succeeds;
  # we pipe EOF so the prompt step fails (exit non-zero) but the request
  # half (HTTP 202 from the agent) is what we're verifying. Inspect the
  # captured output to confirm.
  note "no RECOVERY_TOKEN env — driving the request half only (verify is manual)"
  echo "" | AXONFLOW_ENDPOINT="$AGENT_URL" timeout 30 "$RECOVER_BIN" "$TEST_EMAIL" 2>&1 | tee "$WORKDIR/recover.log" | head -20 || true
  if grep -qiE "Request accepted|HTTP 202|magic link|recovery link" "$WORKDIR/recover.log"; then
    pass "recovery request submitted — agent accepted (HTTP 202); verify is interactive"
  else
    fail "recovery request did not reach agent — see $WORKDIR/recover.log"
  fi
fi

note "Manual step: fetch magic link from $TEST_EMAIL inbox or Resend dashboard."
note "Re-run with RECOVERY_TOKEN=<token from email> to drive the verify half."

if [ -n "${RECOVERY_TOKEN:-}" ]; then
  if [ -f "$REG_FILE" ]; then
    NEW_TENANT=$(python3 -c "import json; print(json.load(open('$REG_FILE'))['tenant_id'])" 2>/dev/null || echo "")
    if [ -n "$NEW_TENANT" ]; then
      pass "recovery persisted new credentials — tenant_id = $NEW_TENANT"
      if [ "$NEW_TENANT" = "$ORIG_TENANT" ]; then
        pass "recovered tenant_id matches original (same email → same tenant)"
      else
        note "recovered tenant_id differs from original ($ORIG_TENANT → $NEW_TENANT). May be expected if recovery mints a new tenant per request."
      fi
    else
      fail "registration file written but tenant_id unparseable"
    fi
  else
    fail "verify did not persist registration file"
  fi
else
  skip "recovery verify (no RECOVERY_TOKEN env set — manual step)"
fi

# ---------------------------------------------------------------------------
# 5. buyer flow — Stripe Payment Link OR `stripe trigger`
# ---------------------------------------------------------------------------
sect "Step 5 — buyer flow (Stripe TEST mode)"
note "tenant_id to paste into the Stripe checkout custom field: $TENANT_ID"
note ""
if [ "$STRIPE_CLI_AUTO_TRIGGER" = "1" ] && command -v stripe >/dev/null 2>&1; then
  note "STRIPE_CLI_AUTO_TRIGGER=1 — using `stripe trigger` to fire a synthetic webhook"
  note "(this skips the Payment Link UI; tests only the agent-side webhook + token-mint path)"
  if stripe trigger checkout.session.completed \
       --add checkout_session:custom_fields[0][key]=tenant_id \
       --add "checkout_session:custom_fields[0][text][value]=$TENANT_ID" \
       --add "checkout_session:customer_email=$TEST_EMAIL" 2>&1 | tee "$WORKDIR/stripe-trigger.log" | head -10; then
    pass "stripe trigger dispatched — agent should receive webhook within ~10s"
    sleep 10
  else
    fail "stripe trigger failed — see $WORKDIR/stripe-trigger.log"
  fi
elif [ "$STRIPE_TEST_PAYMENT_LINK" != "(set this env var to your Stripe TEST Payment Link)" ]; then
  note "Open this URL in your browser:"
  note "  $STRIPE_TEST_PAYMENT_LINK"
  note "Paste tenant_id: $TENANT_ID"
  note "Pay with TEST card 4242 4242 4242 4242, any future expiry, any CVV."
  skip "buyer flow (manual interactive step — pause here, run again with PAID_TOKEN env after token arrives)"
else
  skip "buyer flow (set STRIPE_TEST_PAYMENT_LINK env or STRIPE_CLI_AUTO_TRIGGER=1 to drive)"
fi

# ---------------------------------------------------------------------------
# 6. paid-tier validation
# ---------------------------------------------------------------------------
sect "Step 6 — Pro-tier validation with X-License-Token"
if [ -n "${PAID_TOKEN:-}" ]; then
  note "using PAID_TOKEN from env: ${PAID_TOKEN:0:8}…${PAID_TOKEN: -4}"
  PRO_RESP=$(curl -sS -X POST "$AGENT_URL/api/request" \
    -H "Content-Type: application/json" \
    -H "X-License-Token: $PAID_TOKEN" \
    -d "{\"client_id\":\"openclaw-staging-walkthrough\",\"request_type\":\"audit\",\"query\":\"v1 staging walkthrough Pro\",\"skip_llm\":true}" \
    -w "\n%{http_code}")
  CODE=$(echo "$PRO_RESP" | tail -n 1)
  BODY=$(echo "$PRO_RESP" | head -n -1)
  if [ "$CODE" = "200" ]; then
    pass "agent accepted Pro request (HTTP 200)"
    if echo "$BODY" | grep -q '"tier"\s*:\s*"pro"'; then
      pass "response context shows tier=pro"
    else
      note "response did not surface tier=pro explicitly: $BODY"
    fi
  else
    fail "agent rejected Pro request (HTTP $CODE): $BODY"
  fi
else
  skip "Pro-tier validation (set PAID_TOKEN env after step 5 completes)"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
sect "Summary"
echo "  PASS: $PASS"
echo "  FAIL: $FAIL"
echo "  SKIP: $SKIP"
echo ""
if [ "$FAIL" -gt 0 ]; then
  echo "❌ walkthrough failed — see logs in $WORKDIR before exit cleanup"
  exit 1
fi
if [ "$SKIP" -gt 0 ]; then
  echo "⚠️  walkthrough partially complete — $SKIP step(s) need manual completion"
  exit 0
fi
echo "✅ walkthrough complete"
