#!/usr/bin/env bash
# Regression test for the JSON-body readiness check in
# tests/tier-gate/wait_for_stack.sh.
#
# Failure mode this test pins:
#   wait_for_stack.sh used to declare the agent ready as soon as /health
#   returned HTTP 200. But platform/agent/run.go:initServerImmediately
#   registers /health BEFORE the rest of the agent's routes (so ALB/ECS
#   probes pass during slow init). The handler returns HTTP 200 with
#   `{"status":"starting"}` until the body of run.go finishes route
#   registration and sets `appReady=true`, after which it returns
#   `{"status":"healthy"}`. In enterprise mode the init takes long enough
#   that the tier-gate runner started executing while routes were still
#   registering — every late-registered agent endpoint returned 404.
#
#   The fix: wait_for_stack.sh now greps the response body for
#   `"status":"healthy"` and only declares readiness when the body matches.
#   This test pins the grep pattern against synthetic agent responses so a
#   future drift in either the agent's JSON shape or the script's pattern
#   trips this test.
#
# Run locally:
#   bash tests/tier-gate/wait_for_stack_test.sh
set -euo pipefail

# Keep this regex byte-identical to the wait_for_stack.sh grep pattern.
ready_pattern='"status"[[:space:]]*:[[:space:]]*"healthy"'

script_dir="$(cd "$(dirname "$0")" && pwd)"
script="$script_dir/wait_for_stack.sh"
if [[ ! -f "$script" ]]; then
  echo "FAIL: cannot locate $script"
  exit 1
fi

# 0. Workflow-shape assertion — the script's grep must use the exact regex
# this test pins. If either drifts, the next CI run fails this test loud.
if ! grep -qF "${ready_pattern}" "$script"; then
  echo "FAIL: wait_for_stack.sh does not contain the expected grep pattern"
  echo "      Expected: ${ready_pattern}"
  exit 1
fi
echo "PASS (script shape): wait_for_stack.sh contains the expected ready-pattern"

# Synthetic agent /health response bodies — must match what
# platform/agent/run.go:readinessAwareHealthHandler emits via Go's
# encoding/json.NewEncoder (no whitespace inserted).
declare -a should_match=(
  '{"status":"healthy","service":"axonflow-agent"}'
  '{"service":"axonflow-agent","status":"healthy"}'
  '{"status":"healthy"}'
  '{"status": "healthy", "service": "axonflow-agent"}'
)

declare -a should_not_match=(
  '{"status":"starting","service":"axonflow-agent"}'
  '{"status":"unhealthy"}'
  '{"status":"degraded"}'
  '{"service":"axonflow-agent"}'
  ''
  'plain text body'
)

failures=0

for body in "${should_match[@]}"; do
  if echo "${body}" | grep -q "${ready_pattern}"; then
    echo "PASS (match): ${body}"
  else
    echo "FAIL (expected match): ${body}"
    failures=$((failures + 1))
  fi
done

for body in "${should_not_match[@]}"; do
  if echo "${body}" | grep -q "${ready_pattern}"; then
    echo "FAIL (expected no match): ${body}"
    failures=$((failures + 1))
  else
    echo "PASS (no match): ${body:-<empty>}"
  fi
done

if (( failures > 0 )); then
  echo
  echo "${failures} case(s) failed."
  exit 1
fi

echo
echo "All ${#should_match[@]} match + ${#should_not_match[@]} no-match cases passed."
