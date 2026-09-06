#!/usr/bin/env bash
# Regression guard: every job the sync carries to the community mirror must
# select a runner the mirror actually has.
#
# THE OUTAGE. `getaxonflow/axonflow` has ZERO registered self-hosted runners,
# and the sync copies workflow files verbatim. A job pinned
# `[self-hosted, linux, x64, axonflow]` here therefore becomes a job over there
# that does not fail - it QUEUES FOREVER. `Lint Summary` and `Test Summary` are
# required checks on the mirror, so the community release blocks on a check
# that can never report. Measured on mirror PR getaxonflow/axonflow#485: seven
# checks queued for twenty minutes, thirteen staged jobs unservable.
#
# > The failure is not red, it is ABSENT. The staged-copy assertions in
# > simulate-community-mirror.sh check WHICH FILES arrive; none of them could
# > see this, because the file arriving is exactly the problem.
#
# THE FIX AT THE RIGHT LAYER is a repository-conditional `runs-on`, which makes
# the value an expression STRING rather than a list - and that broke every
# census that asked `isinstance(runs_on, list) and 'self-hosted' in runs_on`,
# dropping twelve jobs and reporting a confident zero. Hence one shared
# resolver, tests/regression-test-required/lib/runs_on_labels.py, used by the
# fleet censuses AND by this control, so a census and its guard cannot drift.
#
# WHAT THIS TEST DRIVES. The checker over fixtures, not the real rsync: staging
# the tree takes minutes and this needs four cases, including two that must
# FAIL. The real staged copy is checked by the simulator itself, on every run
# of test.yml's mirror-simulation lane.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

CHECK=.github/scripts/check-mirror-runner-labels.py
[ -f "$CHECK" ] || { echo "FAIL: $CHECK is missing"; exit 1; }
[ -f tests/regression-test-required/lib/runs_on_labels.py ] || {
  echo "FAIL: the shared resolver is missing; the censuses and this control would diverge"; exit 1; }

tmp=$(mktemp -d) || exit 1
trap 'rm -rf "$tmp"' EXIT

stage() {  # stage <dir> <runs-on-yaml>
  mkdir -p "$1/.github/workflows"
  cat > "$1/.github/workflows/thing.yml" <<Y
on: push
jobs:
  a-job:
    runs-on: $2
    steps:
      - run: echo hi
Y
}

COND="\${{ github.repository == 'getaxonflow/axonflow-enterprise' && fromJSON('[\"self-hosted\",\"linux\",\"x64\",\"axonflow\"]') || 'ubuntu-latest' }}"

# --- 1. the repository-conditional shape must PASS -------------------------
stage "$tmp/ok" "$COND"
if python3 "$CHECK" "$tmp/ok" >/dev/null 2>&1; then
  echo "ok: a repository-conditional runs-on is schedulable on the mirror"
else
  echo "FAIL: the conditional shape was rejected - the fix itself would not pass"
  python3 "$CHECK" "$tmp/ok"; exit 1
fi

# --- 2. plain hosted must PASS --------------------------------------------
stage "$tmp/hosted" "ubuntu-latest"
python3 "$CHECK" "$tmp/hosted" >/dev/null 2>&1 \
  && echo "ok: plain ubuntu-latest is schedulable" \
  || { echo "FAIL: ubuntu-latest was rejected"; exit 1; }

# --- 3. a bare fleet pin must FAIL, and name the job ----------------------
# This is the case that caused the outage.
stage "$tmp/fleet" "[self-hosted, linux, x64, axonflow]"
out=$(python3 "$CHECK" "$tmp/fleet" 2>&1)
if [ $? -eq 0 ]; then
  echo "FAIL: a bare self-hosted pin passed - this control cannot see the outage it exists for"; exit 1
fi
case "$out" in
  *"thing.yml:a-job"*) echo "ok: a bare self-hosted pin FAILS and names the job" ;;
  *) echo "FAIL: it failed but did not name the job:"; printf '%s\n' "$out" | head -4; exit 1 ;;
esac

# --- 4. an UNPARSEABLE expression must FAIL, not pass ---------------------
# An unrecognised shape is exactly where a wrong pass reintroduces the outage,
# so fail-closed is the behaviour under test, not an implementation detail.
stage "$tmp/weird" "\${{ inputs.something_else }}"
if python3 "$CHECK" "$tmp/weird" >/dev/null 2>&1; then
  echo "FAIL: an unparseable runs-on expression PASSED - the checker fails open"; exit 1
fi
echo "ok: an unparseable runs-on expression fails closed"

# --- 5. an empty staged tree must FAIL, not pass by seeing nothing --------
mkdir -p "$tmp/empty/.github/workflows"
if python3 "$CHECK" "$tmp/empty" >/dev/null 2>&1; then
  echo "FAIL: an empty staged copy passed - the check would be vacuous when the sync chain breaks"; exit 1
fi
echo "ok: an empty staged copy fails rather than passing by examining nothing"

# --- 6. the resolver agrees with itself in both directions ----------------
python3 - <<'PY' || exit 1
import sys
sys.path.insert(0, 'tests/regression-test-required/lib')
from runs_on_labels import is_fleet, schedulable_on_mirror, conditional
c = conditional()
assert is_fleet(c) is True,                 "the conditional must be FLEET on the enterprise repo"
assert schedulable_on_mirror(c) is True,    "the conditional must be schedulable on the mirror"
assert is_fleet(['self-hosted','linux']) is True
assert schedulable_on_mirror(['self-hosted','linux']) is False
assert is_fleet('ubuntu-latest') is False
assert schedulable_on_mirror('ubuntu-latest') is True
print("ok: the shared resolver answers both questions consistently")
PY

echo "PASS: the mirror can schedule every job the sync would carry"
