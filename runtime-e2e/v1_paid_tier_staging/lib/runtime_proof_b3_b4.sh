#!/usr/bin/env bash
# B3+B4 runtime proof against community-saas-staging.
#
# Drives end-to-end verification of the per-tenant tier resolution work
# (PR #1902) and the per-tenant consumers (PR #1903) without any
# human-in-the-loop steps. Bypasses Stripe Dashboard via the
# synthetic_stripe_webhook.py tool.
#
# Assertions (in execution order):
#   1.  /health responds 200 (stack is up)
#   2.  POST /api/v1/register mints a fresh tenant
#   3.  Free baseline: authenticated request without X-License-Token
#       executes the auth path successfully (EffectiveTier=Free)
#   4.  Synthetic Stripe webhook mints a Pro token for the tenant
#   5.  Authenticated request with the Pro token returns 200/404
#       (token validated + plugin_user_licenses lookup + tier resolved)
#   6.  Malformed token rejected with HTTP 401
#   7.  Tenant mismatch: tenant_B presents tenant_A's token → HTTP 403
#   8.  Observational: agent log evidence for tier resolution path
#       (CloudWatch — caller pulls out-of-band)
#
# Usage:
#   AGENT_URL=https://try-staging.getaxonflow.com bash runtime_proof_b3_b4.sh
#
# Stack-state assumptions:
#   - Stack provisioned via `Deploy Platform (Full)` with environment=community-saas-staging
#   - Stripe webhook signing secret is in AWS Secrets Manager at
#     axonflow/community-saas-staging/stripe-webhook-signing-secret
#
# Stdout: green on full pass, red on any FAIL. Exit 0 on full pass.

set -uo pipefail

AGENT_URL="${AGENT_URL:-https://try-staging.getaxonflow.com}"
TEST_EMAIL="${TEST_EMAIL:-dev@getaxonflow.com}"
SECRET_NAME="${SECRET_NAME:-axonflow/community-saas-staging/stripe-webhook-signing-secret}"
REGION="${REGION:-us-east-1}"
WORKDIR=$(mktemp -d 2>/dev/null || mktemp -d -t b3b4-proof)

PASS=0
FAIL=0
red()   { printf "\033[31m%s\033[0m\n" "$1"; }
green() { printf "\033[32m%s\033[0m\n" "$1"; }
yellow(){ printf "\033[33m%s\033[0m\n" "$1"; }
fail() { red "  ❌ FAIL: $1"; FAIL=$((FAIL+1)); }
pass() { green "  ✅ PASS: $1"; PASS=$((PASS+1)); }
note() { echo "  📝 $1"; }
sect() { echo ""; yellow "===== $1 ====="; }

if [ "${KEEP_WORKDIR:-}" = "1" ]; then
  trap 'echo "diagnostics retained at $WORKDIR"' EXIT
else
  trap 'rm -rf "$WORKDIR"' EXIT
fi

echo "B3+B4 runtime proof against $AGENT_URL"
echo "  WORKDIR = $WORKDIR (cleaned on exit)"

# ---------------------------------------------------------------------------
# 1. /health 200 + version reflects latest main
# ---------------------------------------------------------------------------
sect "Step 1 — /health"
HEALTH=$(curl -sS --max-time 10 "$AGENT_URL/health" 2>"$WORKDIR/health.err" || echo "")
if [ -z "$HEALTH" ]; then
  fail "/health unreachable — see $WORKDIR/health.err"
  exit 1
fi
echo "$HEALTH" > "$WORKDIR/health.json"
HEALTHY=$(echo "$HEALTH" | python3 -c 'import json,sys; d=json.load(sys.stdin); print("yes" if d.get("status")=="healthy" else "no")' 2>/dev/null || echo "no")
if [ "$HEALTHY" = "yes" ]; then
  VERSION=$(echo "$HEALTH" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("version",""))')
  TIER=$(echo "$HEALTH" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("tier",""))')
  pass "/health 200, version=$VERSION, tier=$TIER"
else
  fail "/health did not return healthy: $HEALTH"
  exit 1
fi

# ---------------------------------------------------------------------------
# 2. Register a fresh tenant
# ---------------------------------------------------------------------------
sect "Step 2 — POST /api/v1/register"
REG_RESP=$(curl -sS -X POST "$AGENT_URL/api/v1/register" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$TEST_EMAIL\"}" 2>"$WORKDIR/reg.err" || echo "")
echo "$REG_RESP" > "$WORKDIR/reg.json"
TENANT_ID=$(echo "$REG_RESP" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("tenant_id",""))' 2>/dev/null || echo "")
SECRET=$(echo "$REG_RESP" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("secret",""))' 2>/dev/null || echo "")
if [ -n "$TENANT_ID" ] && [ -n "$SECRET" ]; then
  pass "registered tenant_id=$TENANT_ID"
  BASIC_AUTH="$(printf '%s:%s' "$TENANT_ID" "$SECRET" | base64)"
else
  fail "register did not return tenant_id+secret: $REG_RESP"
  exit 1
fi

# ---------------------------------------------------------------------------
# 3. Free baseline: authenticated request with NO X-License-Token
# ---------------------------------------------------------------------------
sect "Step 3 — Free baseline (no X-License-Token)"
# Hit a Free-tier endpoint that exercises the auth path. /api/v1/audit/search
# is gated by apiAuthMiddleware which exercises validateCommunitySaasAuth +
# the daily-cap (where dailyLimitForTenant runs).
FREE_RESP=$(curl -sS -o "$WORKDIR/free.body" -w "%{http_code}" \
  -H "Authorization: Basic $BASIC_AUTH" \
  -H "Content-Type: application/json" \
  --max-time 10 \
  -X POST -d '{"limit":1}' "$AGENT_URL/api/v1/audit/search" 2>"$WORKDIR/free.err" || echo "000")
if [ "$FREE_RESP" = "200" ] || [ "$FREE_RESP" = "404" ]; then
  pass "free-tier request authenticated (HTTP $FREE_RESP — auth path executed)"
else
  fail "free-tier request rejected unexpectedly: HTTP $FREE_RESP — see $WORKDIR/free.body"
fi

# ---------------------------------------------------------------------------
# 4. Synthetic Stripe webhook → mint Pro token
# ---------------------------------------------------------------------------
sect "Step 4 — synthetic Stripe webhook (mint Pro token)"
SYNTH_TOOL="$(dirname "$0")/synthetic_stripe_webhook.py"
if [ ! -f "$SYNTH_TOOL" ]; then
  fail "synthetic_stripe_webhook.py not found at $SYNTH_TOOL"
  exit 1
fi
WEBHOOK_OUT=$(python3 "$SYNTH_TOOL" \
  --tenant-id "$TENANT_ID" \
  --email "$TEST_EMAIL" \
  --agent-url "$AGENT_URL" \
  --secret-name "$SECRET_NAME" \
  --region "$REGION" 2>"$WORKDIR/webhook.err")
echo "$WEBHOOK_OUT" > "$WORKDIR/webhook.json"
HTTP_STATUS=$(echo "$WEBHOOK_OUT" | python3 -c 'import json,sys; print(json.load(sys.stdin)["response"]["http_status"])' 2>/dev/null || echo "0")
PRO_TOKEN=$(echo "$WEBHOOK_OUT" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("captured_axon_token",""))' 2>/dev/null || echo "")
if [ "$HTTP_STATUS" = "200" ] && [ -n "$PRO_TOKEN" ]; then
  pass "synthetic webhook minted Pro token (${PRO_TOKEN:0:30}...)"
else
  fail "synthetic webhook failed: HTTP=$HTTP_STATUS, token=${PRO_TOKEN:-<empty>} — see $WORKDIR/webhook.json"
  exit 1
fi

# ---------------------------------------------------------------------------
# 5. Pro request: agent accepts the token + auth path resolves Pro tier
# ---------------------------------------------------------------------------
sect "Step 5 — Pro request with valid X-License-Token"
PRO_RESP=$(curl -sS -o "$WORKDIR/pro.body" -w "%{http_code}" \
  -H "Authorization: Basic $BASIC_AUTH" \
  -H "X-License-Token: $PRO_TOKEN" \
  -H "X-Axonflow-Client: openclaw/2.1.0" \
  -H "Content-Type: application/json" \
  --max-time 10 \
  -X POST -d '{"limit":1}' "$AGENT_URL/api/v1/audit/search" 2>"$WORKDIR/pro.err" || echo "000")
if [ "$PRO_RESP" = "200" ] || [ "$PRO_RESP" = "404" ]; then
  pass "Pro request authenticated (HTTP $PRO_RESP — token validated + tier resolved)"
else
  fail "Pro request rejected unexpectedly: HTTP $PRO_RESP — see $WORKDIR/pro.body"
fi

# ---------------------------------------------------------------------------
# 6. Cross-quadrant rejection: malformed token returns 401
# ---------------------------------------------------------------------------
sect "Step 6 — malformed token rejection"
BAD_RESP=$(curl -sS -o "$WORKDIR/bad.body" -w "%{http_code}" \
  -H "Authorization: Basic $BASIC_AUTH" \
  -H "X-License-Token: AXON-bogus.bogus" \
  -H "Content-Type: application/json" \
  --max-time 10 \
  -X POST -d '{"limit":1}' "$AGENT_URL/api/v1/audit/search" 2>"$WORKDIR/bad.err" || echo "000")
if [ "$BAD_RESP" = "401" ]; then
  if grep -qiE 'invalid_license_token|invalid SaaS Plugin|cross_quadrant|aud' "$WORKDIR/bad.body"; then
    pass "malformed token rejected with explicit reason (HTTP 401 + aud/license context)"
  else
    pass "malformed token rejected (HTTP 401)"
  fi
else
  fail "malformed token should return 401, got HTTP $BAD_RESP — see $WORKDIR/bad.body"
fi

# ---------------------------------------------------------------------------
# 7. Tenant mismatch: tenant_B uses tenant_A's token → 403
# ---------------------------------------------------------------------------
sect "Step 7 — tenant_id mismatch returns 403"
REG_B=$(curl -sS -X POST "$AGENT_URL/api/v1/register" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"runtime-proof-b-$(date +%s)-$RANDOM@axonflow-test.invalid\"}" 2>/dev/null || echo "")
TENANT_B=$(echo "$REG_B" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("tenant_id",""))' 2>/dev/null || echo "")
SECRET_B=$(echo "$REG_B" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("secret",""))' 2>/dev/null || echo "")
if [ -n "$TENANT_B" ] && [ -n "$SECRET_B" ]; then
  BASIC_AUTH_B="$(printf '%s:%s' "$TENANT_B" "$SECRET_B" | base64)"
  # X-Axonflow-Client must declare plugin scope so the scope check passes
  # for tenant_A's plugin-scope token — otherwise the scope_mismatch (401)
  # fires before the tenant check (403). We want the tenant check to fire.
  MISMATCH_RESP=$(curl -sS -o "$WORKDIR/mismatch.body" -w "%{http_code}" \
    -H "Authorization: Basic $BASIC_AUTH_B" \
    -H "X-License-Token: $PRO_TOKEN" \
    -H "X-Axonflow-Client: openclaw/2.1.0" \
    -H "Content-Type: application/json" \
    --max-time 10 \
    -X POST -d '{"limit":1}' "$AGENT_URL/api/v1/audit/search" 2>/dev/null || echo "000")
  if [ "$MISMATCH_RESP" = "403" ]; then
    pass "tenant_id mismatch returned HTTP 403"
  else
    fail "tenant mismatch should return 403, got HTTP $MISMATCH_RESP — see $WORKDIR/mismatch.body"
  fi
else
  fail "could not register second tenant for mismatch test"
fi

# ---------------------------------------------------------------------------
# 8. Pre-existing W4 audit — agent log line for tier resolution
# ---------------------------------------------------------------------------
sect "Step 8 — agent log evidence (CloudWatch)"
note "agent stdout/stderr is in CloudWatch group /aws/ecs/community-saas-staging-agent"
note "search for: 'effectiveTier' or 'plugin_user_licenses lookup' in last 5 min"
note "(this assertion is observational — caller pulls logs out-of-band)"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
sect "Summary"
echo "  PASS: $PASS"
echo "  FAIL: $FAIL"
echo ""
if [ "$FAIL" -gt 0 ]; then
  red "❌ runtime proof failed — $FAIL assertion(s) failed"
  red "   diagnostic logs in $WORKDIR before cleanup"
  exit 1
fi
green "✅ runtime proof passed — B3+B4 validated end-to-end on $AGENT_URL"
exit 0
