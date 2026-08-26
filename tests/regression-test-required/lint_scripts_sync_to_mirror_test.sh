#!/usr/bin/env bash
# lint_scripts_sync_to_mirror_test.sh - #3334 / #3408
#
# `.github/workflows/lint.yml` SYNCS to the public community mirror: it is not
# in sync-community-repo.yml's exclusion list, and it is present today at
# getaxonflow/axonflow. `scripts/` does NOT sync - sync-community-repo.yml
# excludes it wholesale with `--exclude='/scripts/*'` and re-admits a handful of
# customer-facing scripts by explicit name above that line.
#
# So every script lint.yml executes must appear in that include list. If one
# does not, the mirrored lint.yml calls a file that is 404 on the public repo,
# the job dies, and because `Lint Summary` is the REQUIRED status check and
# holds its guard jobs to 'success' with no 'skipped' tolerance, a REQUIRED
# check on a PUBLIC repository is red for everyone, on every PR, until someone
# notices. sync-community-repo.yml:44-55 states that a guaranteed-red required
# check on a public repo is worse than no check at all, because it trains
# everyone to merge past it.
#
# This already happened once. #3512 added the `org-column-guard` job running
# scripts/lint-no-second-org-column.sh and did not add the script to the include
# list; the mirror was spared only because no sync ran between that merge and
# the fix. That is luck, not a control - hence this test.
#
# Run: bash tests/regression-test-required/lint_scripts_sync_to_mirror_test.sh

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SYNC_WORKFLOW="$REPO_ROOT/.github/workflows/sync-community-repo.yml"
LINT_WORKFLOW="$REPO_ROOT/.github/workflows/lint.yml"

PASS=0
FAIL=0
ok()  { echo "  ✅ PASS: $1"; PASS=$((PASS + 1)); }
bad() { echo "  ❌ FAIL: $1"; FAIL=$((FAIL + 1)); }

echo "=== every script lint.yml runs must be re-included in the community sync ==="

for f in "$SYNC_WORKFLOW" "$LINT_WORKFLOW"; do
  if [ ! -f "$f" ]; then
    echo "  ❌ FAIL: $f not found - this test cannot vacuously pass"
    exit 1
  fi
done

# Anti-vacuity 1: lint.yml must still be absent from the sync exclusion list.
# If someone excludes lint.yml wholesale, this test's premise is void and the
# assertions below would pass for the wrong reason.
if grep -q -- "--exclude='.github/workflows/lint.yml'" "$SYNC_WORKFLOW"; then
  echo "  ❌ FAIL: lint.yml is now EXCLUDED from the sync. This test asserts that the"
  echo "          scripts it runs are re-included, which is only meaningful while"
  echo "          lint.yml itself syncs. Delete this test or restore the sync."
  exit 1
fi
ok "lint.yml still syncs to the mirror (anti-vacuity check)"

# Anti-vacuity 2: the re-inclusion mechanism must still be spelled the way the
# grep below looks for it, and /scripts/* must still be excluded wholesale.
if ! grep -q -- "--exclude='/scripts/\*'" "$SYNC_WORKFLOW"; then
  echo "  ❌ FAIL: the sync workflow no longer carries --exclude='/scripts/*' -"
  echo "          the rsync rule format changed and this test's greps are no longer meaningful."
  exit 1
fi
ok "the sync workflow still excludes /scripts/* wholesale (anti-vacuity check)"

# The scripts lint.yml actually executes, read from the workflow rather than
# hard-coded, so adding a step that runs a new script without re-including it
# fails here.
SCRIPTS="$(grep -oE 'bash scripts/[A-Za-z0-9_./-]+\.sh' "$LINT_WORKFLOW" \
  | sed 's/^bash //' | sort -u)"

if [ -z "$SCRIPTS" ]; then
  echo "  ❌ FAIL: could not parse any 'bash scripts/*.sh' invocation out of lint.yml."
  echo "          The step format changed; this test would otherwise check nothing"
  echo "          and report success."
  exit 1
fi

COUNT="$(printf '%s\n' "$SCRIPTS" | wc -l | tr -d '[:space:]')"
if [ "$COUNT" -lt 3 ]; then
  echo "  ❌ FAIL: parsed only $COUNT script invocation(s) from lint.yml; at least 3 are"
  echo "          expected (deployment-mode, policy-table choke point, org-column guard)."
  echo "          A partial parse would let an unlisted script through."
  exit 1
fi
ok "parsed $COUNT distinct script invocations from lint.yml (anti-vacuity check)"

for s in $SCRIPTS; do
  if [ ! -f "$REPO_ROOT/$s" ]; then
    bad "lint.yml runs $s but no such file exists in this repo"
    continue
  fi
  ok "$s exists on disk (the assertion below is not decorative)"

  if grep -q -- "--include='/${s}'" "$SYNC_WORKFLOW"; then
    ok "$s is re-included in the community sync"
  else
    bad "$s is NOT re-included in the community sync - the mirrored lint.yml would 404 on it, reddening the required 'Lint Summary' check on the PUBLIC repo"
  fi
done

echo ""
echo "Results: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] || exit 1
echo "All tests passed!"
