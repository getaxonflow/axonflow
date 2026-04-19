#!/usr/bin/env bash
# Claude Code plugin scenario 1: Trigger a deny via Bash tool with SQLi
# pattern, assert the hook's deny output contains richer context.
#
# -uo pipefail (no -e) matches the other three scenario-1 scripts so the
# explicit errors=$((errors+1)) accumulator and FAIL diagnostics always
# print, even when a jq filter happens to exit non-zero mid-script.
set -uo pipefail

SCRIPT="/tmp/claude-plugin-v0.5.0-e2e/plugin/scripts/pre-tool-check.sh"
export AXONFLOW_ENDPOINT=http://localhost:8080
# AXONFLOW_AUTH is the base64 of "client:secret" — the hook prepends
# "Basic " verbatim (see pre-tool-check.sh's AUTH_HEADER construction).
export AXONFLOW_AUTH="$(echo -n 'demo-client:demo-secret' | base64)"
# The Claude Code plugin hook script doesn't currently forward per-user
# identity. We test what a user experiences on v0.5.0 with v7.1.1 server.

INPUT='{"tool_name":"Bash","tool_input":{"command":"psql -c \"SELECT * FROM users WHERE id='"'"'1'"'"' OR 1=1--\""}}'

OUTPUT=$(echo "$INPUT" | bash "$SCRIPT" 2>&1)
echo "--- hook output ---"
echo "$OUTPUT"
echo "---"

if [ -z "$OUTPUT" ]; then
  echo "FAIL: hook produced no output (expected deny)"
  exit 1
fi
# Claude Code uses permissionDecision:"deny" in hook output JSON
if ! echo "$OUTPUT" | jq -e '.hookSpecificOutput.permissionDecision == "deny"' >/dev/null 2>&1; then
  echo "FAIL: expected permissionDecision=deny"
  exit 1
fi

REASON=$(echo "$OUTPUT" | jq -r '.hookSpecificOutput.permissionDecisionReason // empty')
echo "permission decision reason: $REASON"

# Assert richer context suffix fields surfaced in the reason text.
errors=0
if ! echo "$REASON" | grep -qE "decision:"; then
  echo "FAIL: reason missing 'decision:' marker"
  errors=$((errors + 1))
fi
if ! echo "$REASON" | grep -qE "risk:"; then
  echo "FAIL: reason missing 'risk:' marker"
  errors=$((errors + 1))
fi

if [ $errors -gt 0 ]; then exit 1; fi
echo "PASS: scenario 1 — Claude Code hook surfaces decision_id + risk in deny output"
