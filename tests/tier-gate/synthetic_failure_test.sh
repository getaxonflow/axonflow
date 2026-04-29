#!/usr/bin/env bash
# Synthetic-failure test for the tier-gate contract gate.
#
# Confirms the runner is not a no-op: takes the locked manifest, mutates a
# single entry to an obviously-wrong expected status, runs the runner, and
# asserts the runner exits NON-zero.
#
# This guarantees a future PR that breaks tier behavior on a previously-
# correct endpoint will be caught by the gate.
#
# Usage:
#   AXONFLOW_TIER=community ./tests/tier-gate/synthetic_failure_test.sh
#
# Environment is the same as tests/tier-gate/run.py, plus everything needed
# to bring up the stack — i.e. this is meant to run against the same stack
# the real gate runs against.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ORIGINAL_MANIFEST="${SCRIPT_DIR}/expected.yaml"
TIER="${AXONFLOW_TIER:-community}"

if [ ! -f "${ORIGINAL_MANIFEST}" ]; then
    echo "ERROR: manifest not found at ${ORIGINAL_MANIFEST}" >&2
    exit 2
fi

# Pick a deterministic, always-200 row to corrupt: the first /health row
# matching the current tier. /health is unconditionally 200 in every tier
# so flipping it to 999 is guaranteed to fail the gate when the actual stack
# returns 200.
TMP_MANIFEST="$(mktemp -t qf16-synthetic.XXXXXX.yaml)"
trap 'rm -f "${TMP_MANIFEST}"' EXIT

python3 - "$ORIGINAL_MANIFEST" "$TMP_MANIFEST" "$TIER" <<'PY'
import sys, yaml
src, dst, tier = sys.argv[1], sys.argv[2], sys.argv[3]
with open(src) as f:
    m = yaml.safe_load(f)
mutated = False
for row in m["endpoints"]:
    if row["path"] == "/health" and row["port"] == 8080 and row["method"] == "GET":
        # Flip the expected status for this tier to a deliberately-wrong code.
        # 599 is unused — guarantees the runner sees mismatch (actual will be 200).
        row.setdefault("expected", {}).setdefault(tier, {})["status"] = 599
        row["expected"][tier]["reason"] = "SYNTHETIC FAILURE PROBE — must not match reality"
        mutated = True
        break
if not mutated:
    print("ERROR: could not find /health row to mutate", file=sys.stderr)
    sys.exit(2)
with open(dst, "w") as f:
    yaml.safe_dump(m, f, sort_keys=False)
print(f"# mutated /health status to 599 for tier={tier}")
PY

echo "# running runner against mutated manifest — expecting NON-ZERO exit"
set +e
TIER_GATE_MANIFEST="${TMP_MANIFEST}" \
    AXONFLOW_TIER="${TIER}" \
    python3 "${SCRIPT_DIR}/run.py" >"${TMP_MANIFEST}.log" 2>&1
RUNNER_EXIT=$?
set -e

echo "# runner exited ${RUNNER_EXIT}"

if [ "${RUNNER_EXIT}" -eq 0 ]; then
    echo "FAIL: runner returned 0 against deliberately-broken manifest." >&2
    echo "      The gate is a no-op — it cannot detect tier-behavior regressions." >&2
    echo "      Last 40 lines of runner output:" >&2
    tail -40 "${TMP_MANIFEST}.log" >&2 || true
    rm -f "${TMP_MANIFEST}.log"
    exit 1
fi

# Sanity: the failure must be specifically on the mutated row.
if ! grep -qE "FAIL .*health.*expected=599 actual=200" "${TMP_MANIFEST}.log"; then
    echo "FAIL: runner exited non-zero but not on the synthetic /health probe." >&2
    echo "      Possible regression — last 40 lines:" >&2
    tail -40 "${TMP_MANIFEST}.log" >&2 || true
    rm -f "${TMP_MANIFEST}.log"
    exit 1
fi

rm -f "${TMP_MANIFEST}.log"
echo "PASS: synthetic-failure probe correctly detected (mutated row → runner exit ${RUNNER_EXIT})."
