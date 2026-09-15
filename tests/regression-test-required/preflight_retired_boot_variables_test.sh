#!/usr/bin/env bash
# Behavioural test for the upgrade preflight's check 25
# (scripts/deployment/v9_self_hosted_preflight.sh): a deployment whose agent or
# orchestrator still sets a variable v11.0.0 refuses at boot FAILS the
# preflight, an empty or absent one passes, and a component whose environment
# cannot be read warns rather than passing.
#
# The check's own block is extracted from the script and run against stubs of
# discover_env and the verdict functions, so this drives the code an operator
# runs, not a copy of it. The list the block carries is held equal to
# platform/shared/retiredenv by TestThePreflightNamesExactlyTheRetiredVariables.
#
# Run locally:
#   bash tests/regression-test-required/preflight_retired_boot_variables_test.sh

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PF="$ROOT/scripts/deployment/v9_self_hosted_preflight.sh"

# The block ends at the next check's header or at the section-count check,
# whichever comes first: a check appended after this one must not run here.
BLOCK="$(awk '/^# Check 25 - /{on=1; print; next} on && /^# (Check [0-9]+ - |Internal consistency: every section must have been numbered\.)/{on=0} on' "$PF")"
if ! grep -qF 'C25_RETIRED_VARS=(' <<<"$BLOCK"; then
    echo "FAIL: check 25 was not found in $PF"
    exit 1
fi

failed=0

# run_case NAME EXPECTED STUB - runs check 25 with discover_env replaced by STUB
# (a function body over $1 = component and $2 = variable) and asserts the one
# verdict line it prints starts with EXPECTED.
run_case() {
    local name="$1" expected="$2" stub="$3" out verdicts
    out="$(
        section() { :; }
        info() { :; }
        pass() { echo "PASS: $1"; }
        warn() { echo "WARN: $1"; }
        fail() { echo "FAIL: $1"; }
        eval "discover_env() { DISC_VALUE=''; DISC_SOURCE='fixture'; $stub; }"
        eval "$BLOCK"
    )"
    verdicts="$(grep -E '^(PASS|WARN|FAIL): ' <<<"$out" || true)"
    if [[ "$(grep -c . <<<"$verdicts")" -ne 1 ]]; then
        echo "not ok - $name: want exactly one verdict, got: ${verdicts:-none}"
        failed=1
    elif [[ "$verdicts" != "$expected"* ]]; then
        echo "not ok - $name: want '$expected...', got '$verdicts'"
        failed=1
    else
        echo "ok - $name"
    fi
}

run_case "nothing declared passes" \
    "PASS: None of the 19 variables v11.0.0 refuses at boot is set" \
    'DISC_STATE=absent'
run_case "an empty value boots, so it passes" \
    "PASS: None of the 19 variables" \
    'DISC_STATE=empty'
run_case "a set 'false' on the agent fails, naming the component and the variable" \
    "FAIL: A variable v11.0.0 refuses at boot is set: agent MCP_DYNAMIC_POLICIES_ENABLED" \
    'if [[ "$1" == agent && "$2" == MCP_DYNAMIC_POLICIES_ENABLED ]]; then DISC_STATE=set; DISC_VALUE=false; else DISC_STATE=absent; fi'
run_case "a retired decision-mode variable on the orchestrator fails" \
    "FAIL: A variable v11.0.0 refuses at boot is set: orchestrator AXONFLOW_DECISION_SHADOW_MODE" \
    'if [[ "$1" == orchestrator && "$2" == AXONFLOW_DECISION_SHADOW_MODE ]]; then DISC_STATE=set; DISC_VALUE=shadow; else DISC_STATE=absent; fi'
run_case "the v10 enterprise compose file's scorer timeout on the agent fails" \
    "FAIL: A variable v11.0.0 refuses at boot is set: agent AXONFLOW_FINCRIME_SCORER_TIMEOUT_MS" \
    'if [[ "$1" == agent && "$2" == AXONFLOW_FINCRIME_SCORER_TIMEOUT_MS ]]; then DISC_STATE=set; DISC_VALUE=100; else DISC_STATE=absent; fi'
run_case "a v10 CloudFormation stack's identity-compat mode on the orchestrator fails" \
    "FAIL: A variable v11.0.0 refuses at boot is set: orchestrator AXONFLOW_IDENTITY_COMPAT_MODE" \
    'if [[ "$1" == orchestrator && "$2" == AXONFLOW_IDENTITY_COMPAT_MODE ]]; then DISC_STATE=set; DISC_VALUE=off; else DISC_STATE=absent; fi'
run_case "a leftover HITL grant lifetime on the agent fails" \
    "FAIL: A variable v11.0.0 refuses at boot is set: agent AXONFLOW_HITL_GRANT_TTL_SECONDS" \
    'if [[ "$1" == agent && "$2" == AXONFLOW_HITL_GRANT_TTL_SECONDS ]]; then DISC_STATE=set; DISC_VALUE=900; else DISC_STATE=absent; fi'
run_case "an unreadable component warns instead of passing" \
    "WARN: Could not read the environment of: orchestrator" \
    'if [[ "$1" == orchestrator ]]; then DISC_STATE=unknown; else DISC_STATE=absent; fi'
run_case "a set variable fails even when another component is unreadable" \
    "FAIL: A variable v11.0.0 refuses at boot is set: agent MCP_DYNAMIC_POLICIES_GRACEFUL" \
    'if [[ "$1" == orchestrator ]]; then DISC_STATE=unknown; elif [[ "$2" == MCP_DYNAMIC_POLICIES_GRACEFUL ]]; then DISC_STATE=set; DISC_VALUE=true; else DISC_STATE=absent; fi'

if [[ "$failed" -ne 0 ]]; then
    echo "preflight_retired_boot_variables_test.sh: FAILED"
    exit 1
fi
echo "preflight_retired_boot_variables_test.sh: PASSED"
