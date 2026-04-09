#!/usr/bin/env bash
# AxonFlow Governance Profiles E2E Example
# Runs the same query against the agent under each of the four profiles
# and asserts the expected behavior. See README.md for details.

set -euo pipefail

AGENT_URL="${AXONFLOW_AGENT_URL:-http://localhost:8080}"
CLIENT_ID="${AXONFLOW_CLIENT_ID:-community}"
CLIENT_SECRET="${AXONFLOW_CLIENT_SECRET:-}"
AUTH_HEADER="Authorization: Basic $(printf '%s' "${CLIENT_ID}:${CLIENT_SECRET}" | base64)"

# A query containing email, phone, and a SQL fragment.
QUERY='What is the status of acme@example.com (phone +1-555-0100)? SELECT * FROM users;'

post_query() {
    curl -sS -X POST "${AGENT_URL}/api/v1/agent/process" \
        -H "Content-Type: application/json" \
        -H "${AUTH_HEADER}" \
        -d "{\"query\": $(printf '%s' "$QUERY" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))')}"
}

run_profile() {
    local profile="$1"
    local expect_blocked="$2"
    echo
    echo "=== Profile: ${profile} ==="

    if ! curl -sf "${AGENT_URL}/api/v1/health" >/dev/null 2>&1; then
        echo "ERROR: agent is not running at ${AGENT_URL}"
        echo "Run: ./scripts/setup-e2e-testing.sh community"
        return 1
    fi

    # The agent must be restarted with the desired profile env var.
    # In Docker compose: AXONFLOW_PROFILE=${profile} docker compose restart agent
    # Here we just call the agent and assume the profile is set externally.
    echo "(reading current profile from /api/v1/health)"
    profile_active=$(curl -sf "${AGENT_URL}/api/v1/health" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("active_profile","unknown"))' 2>/dev/null || echo "unknown")
    echo "  active profile: ${profile_active}"

    response=$(post_query)
    blocked=$(echo "$response" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(str(d.get("blocked", False)).lower())' 2>/dev/null || echo "error")

    if [ "$expect_blocked" = "yes" ]; then
        if [ "$blocked" = "true" ]; then
            echo "  ✓ Query blocked (expected)"
        else
            echo "  ✗ Query approved but expected block"
            echo "    response: $(echo "$response" | head -c 300)"
            return 1
        fi
    else
        if [ "$blocked" = "false" ]; then
            echo "  ✓ Query approved (expected)"
            policies=$(echo "$response" | python3 -c 'import json,sys; d=json.load(sys.stdin); pi=d.get("policy_info",{}); print(",".join(p.get("policy_id","?") for p in pi.get("policies_evaluated",[])))' 2>/dev/null || echo "")
            echo "    policies evaluated: ${policies:-(none)}"
        else
            echo "  ✗ Query blocked but expected approve"
            return 1
        fi
    fi
}

cat <<EOF
============================================================
 AxonFlow Governance Profiles E2E Example
 Agent: ${AGENT_URL}
 Query: ${QUERY}
============================================================

This script runs through the 4 profiles. Restart the agent with the
desired AXONFLOW_PROFILE between sections.

Expected results:
  dev:        approved (everything logged, nothing blocks)
  default:    approved (PII warns, query flows through)
  strict:     blocked  (PII blocks)
  compliance: blocked  (PII + compliance categories hard-block)

EOF

# When run interactively, the operator restarts the agent between each
# profile. When run from CI, this script is invoked four times with the
# correct AXONFLOW_PROFILE pre-set in the environment.

PROFILE_TO_TEST="${AXONFLOW_PROFILE:-default}"
case "$PROFILE_TO_TEST" in
    dev)        run_profile dev no ;;
    default)    run_profile default no ;;
    strict)     run_profile strict yes ;;
    compliance) run_profile compliance yes ;;
    *)
        echo "ERROR: AXONFLOW_PROFILE must be one of: dev, default, strict, compliance"
        exit 1
        ;;
esac
