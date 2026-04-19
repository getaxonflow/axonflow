#!/usr/bin/env bash
# Cursor plugin scenario 1: Trigger a deny via Bash tool with SQLi pattern.
# Assert exit 2 + stderr contains richer context (decision_id, risk, override).
set -uo pipefail

SCRIPT="/tmp/cursor-plugin-v0.5.1-e2e/plugin/scripts/pre-tool-check.sh"
export AXONFLOW_ENDPOINT=http://localhost:8080
# AXONFLOW_AUTH is the base64 of "client:secret" — the hook prepends
# "Basic " verbatim (see pre-tool-check.sh's AUTH_HEADER construction).
export AXONFLOW_AUTH="$(echo -n 'demo-client:demo-secret' | base64)"

INPUT='{"tool_name":"Bash","tool_input":{"command":"psql -c \"SELECT * FROM users WHERE id='"'"'1'"'"' OR 1=1--\""}}'

STDERR_OUT=$(echo "$INPUT" | bash "$SCRIPT" 2>&1 >/dev/null)
EXIT_CODE=$?
echo "--- exit code: $EXIT_CODE ---"
echo "--- stderr ---"
echo "$STDERR_OUT"
echo "---"

errors=0
if [ "$EXIT_CODE" != "2" ]; then
  echo "FAIL: expected exit 2, got $EXIT_CODE"
  errors=$((errors + 1))
fi
if ! echo "$STDERR_OUT" | grep -qE "AxonFlow policy violation"; then
  echo "FAIL: stderr missing AxonFlow policy violation prefix"
  errors=$((errors + 1))
fi
if ! echo "$STDERR_OUT" | grep -qE "decision:"; then
  echo "FAIL: stderr missing decision_id marker"
  errors=$((errors + 1))
fi
if ! echo "$STDERR_OUT" | grep -qE "risk:"; then
  echo "FAIL: stderr missing risk_level marker"
  errors=$((errors + 1))
fi

if [ $errors -gt 0 ]; then exit 1; fi
echo "PASS: scenario 1 — Cursor hook exits 2 with richer context on stderr"
