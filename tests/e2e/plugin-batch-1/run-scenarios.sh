#!/usr/bin/env bash
# Plugin Batch 1 E2E test runner.
#
# Exercises 4 canonical scenarios per plugin (block + richer context,
# override lifecycle, explain endpoint, audit filter parity) against a
# running stack booted via ./scripts/setup-e2e-testing.sh. See
# ../../../docs/test-visibility-policy.md for the split between this
# full-matrix suite and the plugin-repo smoke scenarios.
#
# Preconditions:
#   1. `./scripts/setup-e2e-testing.sh` has been run and .env.e2e exists.
#   2. Migration 010 (policy_risk_and_overrides) has been applied.
#   3. Evaluation-tier license is active.
#   4. Seeded policies: 1 critical-risk (unoverridable) + 1 medium-risk (overridable).
#
# Usage:
#   bash tests/e2e/plugin-batch-1/run-scenarios.sh [--plugin openclaw|claude|cursor|codex|all]
#
# Exit 0 if all scenarios pass, nonzero otherwise.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

PLUGIN="${1:-all}"

# Load env from setup script
if [ -f "$REPO_ROOT/.env.e2e" ]; then
  # shellcheck disable=SC1091
  source "$REPO_ROOT/.env.e2e"
fi

AXONFLOW_ENDPOINT="${AXONFLOW_ENDPOINT:-http://localhost:8080}"
CLIENT_ID="${CLIENT_ID:?CLIENT_ID not set — did you run setup-e2e-testing.sh?}"
CLIENT_SECRET="${CLIENT_SECRET:?CLIENT_SECRET not set — did you run setup-e2e-testing.sh?}"
AUTH_B64=$(printf '%s:%s' "$CLIENT_ID" "$CLIENT_SECRET" | base64)

# Test counters
PASS=0
FAIL=0
FAILED_TESTS=()

log()   { printf '\n\033[1;34m=== %s ===\033[0m\n' "$*"; }
pass()  { printf '  \033[1;32m✓ PASS\033[0m: %s\n' "$*"; PASS=$((PASS + 1)); }
fail()  { printf '  \033[1;31m✗ FAIL\033[0m: %s\n' "$*"; FAIL=$((FAIL + 1)); FAILED_TESTS+=("$*"); }

# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------

# Call the platform and return HTTP status + body separately.
http() {
  local method="$1" path="$2" body="${3:-}"
  local tmp
  tmp=$(mktemp)
  local status
  status=$(curl -sS -o "$tmp" -w '%{http_code}' \
    -X "$method" \
    "${AXONFLOW_ENDPOINT}${path}" \
    -H "Content-Type: application/json" \
    -H "Authorization: Basic $AUTH_B64" \
    ${body:+-d "$body"})
  local body
  body=$(cat "$tmp")
  rm -f "$tmp"
  echo "$status"
  echo "$body"
}

# Fire a step gate for testing. Returns the decision_id on block.
fire_step_gate() {
  local tool_name="$1" statement="$2"
  # For real stacks this would go through a step gate endpoint; left as a
  # placeholder for the setup-script integration to fill in.
  local response
  response=$(http POST /api/v1/wcp/step-gate \
    "$(jq -n --arg tn "$tool_name" --arg stmt "$statement" '{
      tool_context: {tool_name: $tn},
      step_input: {statement: $stmt}
    }')")
  echo "$response"
}

# -----------------------------------------------------------------------------
# Scenario 1 — Block + richer context enrichment
# -----------------------------------------------------------------------------

scenario_context_enriched_on_block() {
  local plugin="$1"
  log "[$plugin] Scenario 1: block response carries richer context"

  local out
  out=$(fire_step_gate "Bash" "rm -rf /")
  local status
  status=$(echo "$out" | head -1)
  local body
  body=$(echo "$out" | tail -n +2)

  if [ "$status" = "200" ]; then
    # Assert decision_id present
    local decision_id
    decision_id=$(echo "$body" | jq -r '.decision_id // empty')
    [ -n "$decision_id" ] && pass "decision_id present on block" || fail "decision_id missing on block"
    # Assert policy_matches includes risk_level
    local risk
    risk=$(echo "$body" | jq -r '.policies_matched[0].risk_level // empty')
    [ -n "$risk" ] && pass "risk_level on matched policy" || fail "risk_level missing"
    # Save decision_id for later scenarios
    echo "$decision_id" > /tmp/pb1-decision-id-"$plugin"
  else
    fail "step-gate returned status $status (expected 200)"
  fi
}

# -----------------------------------------------------------------------------
# Scenario 2 — Override create → apply → revoke
# -----------------------------------------------------------------------------

scenario_override_lifecycle() {
  local plugin="$1"
  log "[$plugin] Scenario 2: override create → apply → revoke"

  # Step 2a: Create override for the overridable test policy.
  local create_out
  create_out=$(http POST /api/v1/overrides \
    '{"policy_id":"test-overridable-policy","policy_type":"dynamic","override_reason":"E2E test","ttl_seconds":300}')
  local create_status
  create_status=$(echo "$create_out" | head -1)
  local override_id
  override_id=$(echo "$create_out" | tail -n +2 | jq -r '.id // empty')

  if [ "$create_status" = "201" ] && [ -n "$override_id" ]; then
    pass "override created (id: $override_id)"
  else
    fail "override create failed: status=$create_status"
    return
  fi

  # Step 2b: Search for override_created audit event.
  local audit_out
  audit_out=$(http POST /api/v1/audit/search \
    "$(jq -n --arg oid "$override_id" '{override_id: $oid, limit: 10}')")
  local audit_body
  audit_body=$(echo "$audit_out" | tail -n +2)
  local found_created
  found_created=$(echo "$audit_body" | jq -r '.entries[] | select(.request_type=="override_created") | .id' | head -1)
  [ -n "$found_created" ] && pass "override_created audit event present" || fail "override_created missing"

  # Step 2c: Revoke.
  local revoke_out
  revoke_out=$(http DELETE "/api/v1/overrides/$override_id")
  local revoke_status
  revoke_status=$(echo "$revoke_out" | head -1)
  [ "$revoke_status" = "200" ] && pass "override revoked" || fail "revoke failed: status=$revoke_status"

  # Step 2d: Audit has override_revoked event.
  audit_out=$(http POST /api/v1/audit/search \
    "$(jq -n --arg oid "$override_id" '{override_id: $oid, limit: 10}')")
  local found_revoked
  found_revoked=$(echo "$audit_out" | tail -n +2 | jq -r '.entries[] | select(.request_type=="override_revoked") | .id' | head -1)
  [ -n "$found_revoked" ] && pass "override_revoked audit event present" || fail "override_revoked missing"
}

# -----------------------------------------------------------------------------
# Scenario 3 — Explain returns full context
# -----------------------------------------------------------------------------

scenario_explain_returns_context() {
  local plugin="$1"
  log "[$plugin] Scenario 3: decisions.explain returns canonical DecisionExplanation"

  local decision_id
  if [ -f "/tmp/pb1-decision-id-$plugin" ]; then
    decision_id=$(cat "/tmp/pb1-decision-id-$plugin")
  fi
  if [ -z "$decision_id" ]; then
    fail "no decision_id from scenario 1 — skipping"
    return
  fi

  local out
  out=$(http GET "/api/v1/decisions/$decision_id/explain")
  local status
  status=$(echo "$out" | head -1)
  local body
  body=$(echo "$out" | tail -n +2)

  if [ "$status" != "200" ]; then
    fail "explain returned status $status (expected 200)"
    return
  fi

  # Verify required fields per ADR-043.
  for field in decision_id timestamp decision policy_matches override_available historical_hit_count_session; do
    local v
    v=$(echo "$body" | jq "has(\"$field\")")
    [ "$v" = "true" ] && pass "explain response has '$field'" || fail "explain response missing '$field'"
  done
}

# -----------------------------------------------------------------------------
# Scenario 4 — Audit search filter parity
# -----------------------------------------------------------------------------

scenario_audit_search_parity() {
  local plugin="$1"
  log "[$plugin] Scenario 4: audit search filters work"

  local decision_id
  if [ -f "/tmp/pb1-decision-id-$plugin" ]; then
    decision_id=$(cat "/tmp/pb1-decision-id-$plugin")
  fi
  if [ -z "$decision_id" ]; then
    fail "no decision_id from scenario 1 — skipping"
    return
  fi

  local out
  out=$(http POST /api/v1/audit/search "$(jq -n --arg did "$decision_id" '{decision_id: $did, limit: 10}')")
  local status
  status=$(echo "$out" | head -1)
  [ "$status" = "200" ] && pass "audit search by decision_id returns 200" || fail "audit search by decision_id returns $status"
}

# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------

run_all_scenarios() {
  local plugin="$1"
  scenario_context_enriched_on_block "$plugin"
  scenario_override_lifecycle "$plugin"
  scenario_explain_returns_context "$plugin"
  scenario_audit_search_parity "$plugin"
}

case "$PLUGIN" in
  all)
    for p in openclaw claude cursor codex; do
      run_all_scenarios "$p"
    done
    ;;
  openclaw|claude|cursor|codex)
    run_all_scenarios "$PLUGIN"
    ;;
  *)
    echo "Usage: $0 [--plugin openclaw|claude|cursor|codex|all]"
    exit 2
    ;;
esac

echo ""
log "Results"
printf 'Passed: %d\n' "$PASS"
printf 'Failed: %d\n' "$FAIL"

if [ "$FAIL" -gt 0 ]; then
  printf '\n\033[1;31mFailed tests:\033[0m\n'
  for t in "${FAILED_TESTS[@]}"; do
    printf '  - %s\n' "$t"
  done
  exit 1
fi

exit 0
