#!/usr/bin/env bash
# Wait for the agent (8080) and orchestrator (8081) to report fully healthy.
# Exits non-zero if either fails to come up within the timeout.
#
# Used by the tier-gate workflow after `docker compose up -d`.
#
# Why we check the response body, not just HTTP 200:
#   `platform/agent/run.go:initServerImmediately` registers /health BEFORE
#   the rest of the agent's routes (so ECS/ALB health probes pass during the
#   slow init). /health returns HTTP 200 with `{"status":"starting"}` until
#   the body of `run.go` finishes and sets `appReady=true`, after which it
#   returns `{"status":"healthy"}`. A raw curl pass on HTTP 200 was racing
#   the route-registration loop in enterprise mode (slower init) and caused
#   the tier-gate runner to see 404 for not-yet-registered routes.
#   We now require the body to contain `"status":"healthy"` before
#   declaring readiness.

set -euo pipefail

AGENT_HEALTH="${AGENT_HEALTH:-http://localhost:8080/health}"
ORCH_HEALTH="${ORCH_HEALTH:-http://localhost:8081/health}"
TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-180}"
INTERVAL_SECONDS="${INTERVAL_SECONDS:-3}"

probe() {
    local url="$1" name="$2"
    local elapsed=0
    local body=""
    echo "# waiting for ${name} at ${url} (timeout=${TIMEOUT_SECONDS}s, require status=healthy)"
    while [ "${elapsed}" -lt "${TIMEOUT_SECONDS}" ]; do
        body=$(curl -fsS --max-time 5 "${url}" 2>/dev/null || true)
        if echo "${body}" | grep -q '"status"[[:space:]]*:[[:space:]]*"healthy"'; then
            echo "# ${name} ready after ${elapsed}s"
            return 0
        fi
        sleep "${INTERVAL_SECONDS}"
        elapsed=$((elapsed + INTERVAL_SECONDS))
        if [ $((elapsed % 30)) -eq 0 ]; then
            local snippet
            snippet=$(echo "${body}" | head -c 120)
            echo "# still waiting for ${name} (${elapsed}s) — last body: ${snippet:-<no response>}"
        fi
    done
    echo "ERROR: ${name} did not report status=healthy within ${TIMEOUT_SECONDS}s" >&2
    echo "ERROR: last response body: ${body:-<empty>}" >&2
    return 1
}

probe "${AGENT_HEALTH}" "agent"
probe "${ORCH_HEALTH}"  "orchestrator"
echo "# stack ready"
