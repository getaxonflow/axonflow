#!/usr/bin/env bash
# End-to-end smoke test for the AxonFlow MCP Decision Mode example.
#
# Drives mcp_server.py over stdio (via e2e_harness.py) against a live AxonFlow
# stack and asserts five scenarios: clean allow, NIK deny, NPWP deny, context
# forwarding, and fail-closed on an unreachable PDP. Exits 0 only if all pass.
#
# Prerequisites:
#   - AxonFlow agent running on :8080 in ENTERPRISE mode with PII_ACTION=block:
#       PII_ACTION=block ./scripts/setup-e2e-testing.sh enterprise
#       source /tmp/axonflow-e2e-env.sh
#   - AXONFLOW_CLIENT_ID / AXONFLOW_CLIENT_SECRET / AXONFLOW_TENANT_ID set
#     (the setup script exports these).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

AGENT_URL="${AXONFLOW_AGENT_URL:-http://localhost:8080}"
export AXONFLOW_AGENT_URL="$AGENT_URL"
export MCP_AUDIT_LOG_PATH="${MCP_AUDIT_LOG_PATH:-$HERE/audit_log.jsonl}"

echo "=== AxonFlow MCP Decision Mode — E2E smoke test ==="
echo "Agent URL: $AGENT_URL"

# 1. AxonFlow must be reachable. Fail fast with a clear pointer otherwise.
if ! curl -sf --max-time 5 "$AGENT_URL/health" >/dev/null; then
  echo "FATAL: AxonFlow agent not reachable at $AGENT_URL/health" >&2
  echo "Start it with: PII_ACTION=block ./scripts/setup-e2e-testing.sh enterprise" >&2
  exit 1
fi

# 2. Credentials must be present (the decide call uses Basic auth).
: "${AXONFLOW_CLIENT_ID:?AXONFLOW_CLIENT_ID must be set (source /tmp/axonflow-e2e-env.sh)}"
: "${AXONFLOW_CLIENT_SECRET:?AXONFLOW_CLIENT_SECRET must be set (source /tmp/axonflow-e2e-env.sh)}"
export AXONFLOW_TENANT_ID="${AXONFLOW_TENANT_ID:-$AXONFLOW_CLIENT_ID}"

# 3. Resolve a Python interpreter + ensure deps. Reuse a local .venv if present.
if [ -d "$HERE/.venv" ]; then
  # shellcheck disable=SC1091
  source "$HERE/.venv/bin/activate"
else
  PYBIN="$(command -v python3.11 || command -v python3)"
  "$PYBIN" -m venv "$HERE/.venv"
  # shellcheck disable=SC1091
  source "$HERE/.venv/bin/activate"
  python -m pip install --quiet --upgrade pip
  pip install --quiet -r "$HERE/requirements-dev.txt"
fi

# 4. Drive the server over stdio and assert all five scenarios. Disable -e
# around the harness so a failing run STILL reaches the audit-log dump below
# (the audit log is the paste-evidence we most want to see on a failure).
echo
rc=0
set +e
python e2e_harness.py
rc=$?
set -e

# 5. Surface the audit log produced by this run as paste-evidence.
echo
echo "=== audit_log.jsonl (this run) ==="
if [ -f "$MCP_AUDIT_LOG_PATH" ]; then
  cat "$MCP_AUDIT_LOG_PATH"
fi
exit $rc
