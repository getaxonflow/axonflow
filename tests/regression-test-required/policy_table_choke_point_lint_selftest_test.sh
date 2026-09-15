#!/usr/bin/env bash
# THE CHOKE-POINT LINT HAD A SELF-TEST THAT NOTHING RAN.
#
# `scripts/lint-policy-table-choke-point_test.sh` has existed for some time and
# carries, as its first row, `assert_pass "Current branch tree passes the lint"`
# against the REAL repository root. That row would have caught #3924's new
# `SELECT COUNT(*) FROM static_policies` the moment it landed on main.
#
# It never ran. `grep -rn lint-policy-table-choke-point_test .github/workflows/`
# returns NOTHING, so the lint's own coverage was a file on disk and not a gate.
# main went red instead, on every open PR, none of which touched the file - and
# it was found by a worker chasing a red that was not theirs.
#
# A test that is not wired to a trigger is not a test. This file is the wiring,
# and it lives in the required tier so it cannot quietly stop running again.
#
# It executes the self-test rather than re-implementing it: a second copy of the
# fixture set would agree with the first for exactly as long as nobody edited
# either, which is the drift this repository keeps paying for.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.." || exit 1

SELFTEST="scripts/lint-policy-table-choke-point_test.sh"
LINT="scripts/lint-policy-table-choke-point.sh"

# FAIL CLOSED on a missing subject. Neither path is stripped by the community
# sync (both are under scripts/), so this needs no mirror skip - but if either
# ever moves, this must go red rather than silently pass over nothing.
for f in "$SELFTEST" "$LINT"; do
  if [ ! -f "$f" ]; then
    echo "FAIL: $f not found - this guard cannot vacuously pass"
    exit 1
  fi
done

out="$(bash "$SELFTEST" 2>&1)"; rc=$?

# ANTI-VACUITY: a self-test that runs zero fixtures and exits 0 would otherwise
# read as a pass. Require it to report a double-digit total, which it has
# carried since it was written.
if ! grep -qE 'Results: [0-9]+/[0-9]{2,} passed' <<< "$out"; then
  echo "FAIL: the self-test did not report a double-digit fixture count; it ran almost nothing"
  echo "$out" | tail -5 | sed 's/^/      /'
  exit 1
fi

if [ "$rc" -ne 0 ]; then
  echo "FAIL: scripts/lint-policy-table-choke-point_test.sh failed (exit $rc)"
  echo "$out" | tail -20 | sed 's/^/      /'
  exit 1
fi

echo "  ok: $(grep -oE 'Results: [0-9]+/[0-9]+ passed' <<< "$out" | tail -1)"
echo "PASS: the policy-table choke-point lint's own self-test runs in the required tier"
