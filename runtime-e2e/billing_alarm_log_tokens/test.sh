#!/usr/bin/env bash
# #1894 runtime proof — explicit alarm-stable log tokens
#
# Drives the synthetic Stripe webhook (no Dashboard / Live charge needed)
# against community-saas-staging, then verifies via CloudWatch Logs
# Insights that the new alarm-stable tokens land in the agent log group.
# Also checks the alarms-stack metric increments for FirstPaidLicense.
#
# This is a POSITIVE-PATH test (success → first_paid_license_issued).
# The negative path (paid_but_no_token_issued) requires forcing a DB
# failure on a paid checkout — too destructive for a shared staging
# stack. That path is covered by the unit tests in
# platform/agent/billing/webhook_test.go::TestWebhookHandler_PaidButNoTokenIssued_OnIssueFailure.
#
# Stack-state assumptions:
#   - axonflow-community-saas-staging-<TIMESTAMP> exists, post-#1894 image deployed
#   - Stripe webhook signing secret in SM at
#     axonflow/community-saas-staging/stripe-webhook-signing-secret
#   - Agent log group exported as ${STACK}-AgentLogGroupName (CFN export)
#
# Usage:
#   AGENT_URL=https://try-staging.getaxonflow.com bash test.sh
#   STACK=axonflow-community-saas-staging-20260505-104000 bash test.sh   # if auto-discover fails
#
# Stdout: PASS / FAIL summary; full evidence captured under EVIDENCE/<utc-ts>/

set -uo pipefail

# ---------------------------------------------------------------------------
# Config (env-overridable)
# ---------------------------------------------------------------------------
AGENT_URL="${AGENT_URL:-https://try-staging.getaxonflow.com}"
TEST_EMAIL="${TEST_EMAIL:-dev@getaxonflow.com}"
SECRET_NAME="${SECRET_NAME:-axonflow/community-saas-staging/stripe-webhook-signing-secret}"
REGION="${REGION:-us-east-1}"
STACK="${STACK:-}"

# Auto-discover the most-recent community-saas-staging stack name if STACK
# wasn't passed. Per feedback_workflows_anchor_stack_discovery, only
# accept the date-anchored prefix to avoid matching unrelated CloudFormation
# resources.
if [ -z "$STACK" ]; then
  # Exclude sibling sub-stacks (`-alarms`, `-synthetic-monitoring`) per #1919
  # — they share the date-anchored prefix but are not the platform stack.
  STACK=$(aws cloudformation list-stacks \
    --region "$REGION" \
    --stack-status-filter CREATE_COMPLETE UPDATE_COMPLETE UPDATE_ROLLBACK_COMPLETE \
    --query "StackSummaries[?starts_with(StackName, 'axonflow-community-saas-staging-2') && !contains(StackName, 'alarms') && !contains(StackName, 'synthetic')].StackName" \
    --output text 2>/dev/null | tr '\t' '\n' | sort -r | head -1)
fi
if [ -z "$STACK" ]; then
  echo "::error:: could not auto-discover staging stack name; pass STACK=<name>"
  exit 2
fi

# Evidence dir
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
TS=$(date -u +%Y-%m-%dT%H%M%SZ)
EVIDENCE_DIR="${SCRIPT_DIR}/EVIDENCE/${TS}"
mkdir -p "$EVIDENCE_DIR"

PASS=0; FAIL=0
red()    { printf "\033[31m%s\033[0m\n" "$1"; }
green()  { printf "\033[32m%s\033[0m\n" "$1"; }
yellow() { printf "\033[33m%s\033[0m\n" "$1"; }
fail()   { red   "  FAIL: $1"; FAIL=$((FAIL+1)); }
pass()   { green "  PASS: $1"; PASS=$((PASS+1)); }
note()   { echo  "  note: $1"; }
sect()   { echo ""; yellow "===== $1 ====="; }

echo "#1894 runtime proof — alarm-stable log tokens"
echo "  STACK         = $STACK"
echo "  AGENT_URL     = $AGENT_URL"
echo "  REGION        = $REGION"
echo "  EVIDENCE_DIR  = $EVIDENCE_DIR"

# ---------------------------------------------------------------------------
# 1. Resolve agent log group from CFN export
# ---------------------------------------------------------------------------
sect "1. Resolve agent log group"
LOG_GROUP=$(aws cloudformation list-exports \
  --region "$REGION" \
  --query "Exports[?Name=='${STACK}-AgentLogGroupName'].Value" \
  --output text 2>/dev/null)
if [ -z "$LOG_GROUP" ] || [ "$LOG_GROUP" = "None" ]; then
  fail "no CFN export ${STACK}-AgentLogGroupName found"
  echo "Cannot proceed without agent log group name. Stack rotation? Run: aws cloudformation list-exports --region $REGION | grep AgentLogGroup"
  exit 3
fi
pass "agent log group: $LOG_GROUP"
echo "$LOG_GROUP" > "$EVIDENCE_DIR/log_group.txt"

# ---------------------------------------------------------------------------
# 2. Pre-test tenant registration (the synthetic webhook needs a real tenant)
# ---------------------------------------------------------------------------
sect "2. Register tenant for the synthetic checkout"
TENANT_RAW=$(curl -fsS -X POST "${AGENT_URL}/api/v1/register" \
  -H 'Content-Type: application/json' \
  -d "{\"email\":\"${TEST_EMAIL}\"}" 2>"$EVIDENCE_DIR/register_err.txt")
if [ $? -ne 0 ]; then
  fail "register call failed; see $EVIDENCE_DIR/register_err.txt"
  exit 4
fi
TENANT_ID=$(echo "$TENANT_RAW" | python3 -c 'import sys,json;print(json.load(sys.stdin)["tenant_id"])')
echo "$TENANT_RAW" > "$EVIDENCE_DIR/register_response.json"
pass "registered tenant_id=$TENANT_ID"

# ---------------------------------------------------------------------------
# 3. Capture pre-test "now" so the CW filter only scans NEW lines
# ---------------------------------------------------------------------------
PRE_TS_MS=$(($(date -u +%s) * 1000))
echo "$PRE_TS_MS" > "$EVIDENCE_DIR/pre_test_ts_ms.txt"
note "pre-test timestamp (ms since epoch): $PRE_TS_MS"

# ---------------------------------------------------------------------------
# 4. Issue the synthetic checkout.session.completed webhook
# ---------------------------------------------------------------------------
sect "3. Synthetic Stripe webhook"
SYNTH_OUT=$(python3 \
  "${SCRIPT_DIR}/../v1_paid_tier_staging/lib/synthetic_stripe_webhook.py" \
  --tenant-id "$TENANT_ID" \
  --email "$TEST_EMAIL" \
  --agent-url "$AGENT_URL" \
  --secret-name "$SECRET_NAME" \
  --region "$REGION" 2>"$EVIDENCE_DIR/synth_err.txt") || true
echo "$SYNTH_OUT" > "$EVIDENCE_DIR/synth_response.json"
HTTP_STATUS=$(echo "$SYNTH_OUT" | python3 -c 'import sys,json;print(json.load(sys.stdin)["response"]["http_status"])')
SESSION_ID=$(echo "$SYNTH_OUT" | python3 -c 'import sys,json;print(json.load(sys.stdin)["request"]["session_id"])')
if [ "$HTTP_STATUS" != "200" ]; then
  fail "synthetic webhook returned HTTP $HTTP_STATUS (expected 200) — check $EVIDENCE_DIR/synth_response.json"
  exit 5
fi
pass "webhook accepted (HTTP 200, session=$SESSION_ID)"

# ---------------------------------------------------------------------------
# 5. Poll CW Logs Insights for the new alarm-stable token
# ---------------------------------------------------------------------------
sect "4. Assert event=first_paid_license_issued in agent logs"
DEADLINE=$(($(date -u +%s) + 90))
FOUND_LINE=""
QUERY_ID=""
while [ $(date -u +%s) -lt "$DEADLINE" ]; do
  QUERY_ID=$(aws logs start-query \
    --region "$REGION" \
    --log-group-name "$LOG_GROUP" \
    --start-time "$((PRE_TS_MS / 1000))" \
    --end-time "$(date -u +%s)" \
    --query-string "fields @timestamp, @message | filter @message like /event=first_paid_license_issued/ and @message like /tenant=${TENANT_ID}/ | sort @timestamp desc | limit 5" \
    --query queryId --output text 2>/dev/null)
  sleep 3
  RESULT=$(aws logs get-query-results --region "$REGION" --query-id "$QUERY_ID" 2>/dev/null)
  STATUS=$(echo "$RESULT" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("status",""))')
  if [ "$STATUS" = "Complete" ]; then
    HITS=$(echo "$RESULT" | python3 -c 'import sys,json;print(len(json.load(sys.stdin).get("results",[])))')
    if [ "$HITS" -gt 0 ]; then
      FOUND_LINE=$(echo "$RESULT" | python3 -c 'import sys,json
r=json.load(sys.stdin)["results"]
for row in r:
    for f in row:
        if f["field"]=="@message":
            print(f["value"]); break
    break')
      break
    fi
  fi
  echo "  ... still waiting (status=$STATUS hits=${HITS:-0})"
  sleep 4
done

echo "$FOUND_LINE" > "$EVIDENCE_DIR/found_first_paid_line.txt"
if [ -z "$FOUND_LINE" ]; then
  fail "event=first_paid_license_issued never appeared in agent logs within 90s"
  echo "  Check: agent image actually contains #1894? Run: gh pr view 1894 --json mergedAt"
else
  pass "found new alarm-stable token line"
  echo "  $FOUND_LINE"
  # Check it carries amount_cents=999 (V1 Pro = $9.99). The synthetic
  # webhook sends amount_total=999, so the agent must read + emit it.
  if echo "$FOUND_LINE" | grep -qE 'amount_cents=999\b'; then
    pass "amount_cents=999 correctly carried in the log line"
  else
    fail "amount_cents missing or wrong value in: $FOUND_LINE"
  fi
fi

# ---------------------------------------------------------------------------
# 6. Confirm the alarm metric filter actually incremented
# ---------------------------------------------------------------------------
sect "5. Assert FirstPayment alarm metric increment"
NS="AxonFlow/${STACK}/Billing"
NOW_TS=$(date -u +%s)
START_TS=$((PRE_TS_MS / 1000))
# CW metric is published with 1-min granularity; allow up to 3 min for
# delivery + aggregation lag.
SUM=$(aws cloudwatch get-metric-statistics \
  --region "$REGION" \
  --namespace "$NS" \
  --metric-name LicensesIssued \
  --statistics Sum \
  --start-time "$(date -u -r $((START_TS - 60)) +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d "@$((START_TS - 60))" +%Y-%m-%dT%H:%M:%SZ)" \
  --end-time "$(date -u -r $((NOW_TS + 180)) +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d "@$((NOW_TS + 180))" +%Y-%m-%dT%H:%M:%SZ)" \
  --period 60 \
  --query 'Datapoints[*].Sum' \
  --output text 2>"$EVIDENCE_DIR/cw_metric_err.txt")
echo "$SUM" > "$EVIDENCE_DIR/licenses_issued_metric_datapoints.txt"
TOTAL=$(echo "$SUM" | tr '\t' '\n' | awk 'BEGIN{s=0} {s+=$1} END{printf "%.0f", s}')
if [ -z "$TOTAL" ] || [ "$TOTAL" = "0" ]; then
  note "metric not yet aggregated; CW lag can be up to 5 min — re-poll once"
  sleep 60
  SUM=$(aws cloudwatch get-metric-statistics \
    --region "$REGION" \
    --namespace "$NS" \
    --metric-name LicensesIssued \
    --statistics Sum \
    --start-time "$(date -u -r $((START_TS - 60)) +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d "@$((START_TS - 60))" +%Y-%m-%dT%H:%M:%SZ)" \
    --end-time "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --period 60 --query 'Datapoints[*].Sum' --output text)
  TOTAL=$(echo "$SUM" | tr '\t' '\n' | awk 'BEGIN{s=0} {s+=$1} END{printf "%.0f", s}')
fi
if [ -n "$TOTAL" ] && [ "$TOTAL" != "0" ]; then
  pass "LicensesIssued metric increment observed: total=$TOTAL"
else
  fail "LicensesIssued metric never incremented in this window"
  echo "  Check: alarms stack deployed against the right ParentStackName? Filter pattern matches the new token?"
fi

# ---------------------------------------------------------------------------
# 7. Summary + write a markdown evidence file
# ---------------------------------------------------------------------------
sect "Summary"
TOTAL_TESTS=$((PASS + FAIL))
echo "  PASS=$PASS / $TOTAL_TESTS"
echo "  FAIL=$FAIL"

cat > "$EVIDENCE_DIR/EVIDENCE.md" <<EVIDENCE
# #1894 runtime proof evidence — ${TS}

- **Stack:** ${STACK}
- **Agent URL:** ${AGENT_URL}
- **Log group:** ${LOG_GROUP}
- **Tenant:** ${TENANT_ID}
- **Stripe session:** ${SESSION_ID}
- **Webhook HTTP status:** ${HTTP_STATUS}

## Captured log line

\`\`\`
${FOUND_LINE}
\`\`\`

## CloudWatch metric (LicensesIssued in AxonFlow/${STACK}/Billing)

\`\`\`
$(cat "$EVIDENCE_DIR/licenses_issued_metric_datapoints.txt")
\`\`\`

Total over window: ${TOTAL:-0}

## Result

- PASS: ${PASS}
- FAIL: ${FAIL}
EVIDENCE

if [ "$FAIL" -gt 0 ]; then
  red "OVERALL: FAIL"
  exit 1
fi
green "OVERALL: PASS"
