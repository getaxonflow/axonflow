#!/usr/bin/env bash
# suite_gate_floor_is_edition_aware_test.sh
#
# THE BUG CLASS: A FLOOR CALIBRATED ON ONE TREE, SHIPPED TO TWO.
#
# .github/scripts/suite-gate.py refuses to report success unless the tree
# carries at least MIN_SUITE_RUNS stack-booting workflows declaring
# merge_group - a real anti-vacuity check, because "no failures found" over an
# empty selector reads exactly like a green build.
#
# That script and its workflow BOTH SYNC to the community mirror, and the
# mirror is not this tree: the sync strips runtime-e2e/ and every
# enterprise-only workflow, leaving 2 stack-booting merge_group workflows
# against this tree's 76. A floor of 20 can never be met there, and it was not:
# the v10.4.0 sync PR's queue build failed with
#
#   only 2 stack-booting workflows declare merge_group (sanity floor 20).
#   The selector is broken, not the day quiet.
#
# (getaxonflow/axonflow run 34066582583, job 101576291763) - a gate reporting a
# broken selector on a tree whose selector was working perfectly.
#
# THE FIX, and what this test pins: the edition is read off what the
# CHECKED-OUT TREE CONTAINS - the same marker scripts/lint-trap-handlers-exit.sh
# and scripts/lint-hitl-queue-choke-point.sh use, lint.yml present and
# sync-community-repo.yml absent - and NEVER from "the count looks small",
# which is the inference a genuinely broken selector also satisfies. The
# enterprise floor stays 20; the mirror's is derived from the mirror's own
# census.
#
# BOTH DIRECTIONS, on fixtures, because a floor that only ever passes is not a
# floor:
#   1. enterprise tree, 20 suites          -> passes, at floor 20
#   2. enterprise tree, 19 suites          -> FAILS  (the floor did not move)
#   3. enterprise tree, selector matched 0 -> FAILS  (the original purpose)
#   4. community tree, 2 of 2              -> passes (the outage, now green)
#   5. community tree, 1 of 2              -> FAILS, naming the workflow
#   6. community tree, selector matched 0  -> FAILS  (floor never below 1)
#   7. the marker itself separates the two trees, both ways
#   8. this repository's REAL tree passes its own floor - edition-aware, so
#      this file is honest on the mirror it syncs to as well.
#
# Case 4 is the delete-the-feature control: revert the fix and it goes red.
# Case 2 is the other one: loosen the enterprise floor and it goes red.
#
# Run: bash tests/regression-test-required/suite_gate_floor_is_edition_aware_test.sh

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
GATE="$REPO_ROOT/.github/scripts/suite-gate.py"

PASS=0
FAIL=0
ok()  { echo "  PASS: $1"; PASS=$((PASS + 1)); }
bad() { echo "  FAIL: $1"; FAIL=$((FAIL + 1)); }

[ -f "$GATE" ] || { echo "  FAIL: $GATE is missing; this test cannot vacuously pass"; exit 1; }
command -v python3 >/dev/null 2>&1 || {
  echo "  FAIL: python3 is unavailable; a guard that cannot run must not report success"; exit 1; }
python3 -c 'import yaml' 2>/dev/null || {
  echo "  FAIL: PyYAML is unavailable; the floor decision cannot be driven, and a guard that cannot run must not pass"; exit 1; }

tmp="$(mktemp -d)" || exit 1
trap 'rm -rf "$tmp"' EXIT

# ---------------------------------------------------------------------------
# Fixture builders. A fixture tree is a bare .github/workflows holding only
# what the decision reads, so nothing else in it can answer for the property
# under test.
#
# `edition` is set by the MARKER FILES, never by the suite count - which is the
# whole point of the change and has to be built that way here too.
# ---------------------------------------------------------------------------
mk_tree() {  # mk_tree <dir> <enterprise|community> <n_booting> <n_of_them_with_merge_group>
  local dir="$1" edition="$2" n="$3" mg="$4" i
  mkdir -p "$dir/.github/workflows"
  # lint.yml is the mirrored-lint half of the marker and is present on both.
  printf 'name: Lint\non:\n  pull_request:\njobs:\n  lint:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo lint\n' \
    > "$dir/.github/workflows/lint.yml"
  if [ "$edition" = enterprise ]; then
    # The sync excludes its own workflow, so its PRESENCE is the enterprise half.
    printf 'name: Sync Community Repo\non:\n  workflow_dispatch:\njobs:\n  sync:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo sync\n' \
      > "$dir/.github/workflows/sync-community-repo.yml"
  fi
  for ((i = 1; i <= n; i++)); do
    {
      printf 'name: Fixture Suite %02d\non:\n' "$i"
      if [ "$i" -le "$mg" ]; then printf '  merge_group:\n'; fi
      printf '  workflow_dispatch:\njobs:\n  suite:\n    runs-on: ubuntu-latest\n    steps:\n      - run: docker compose up -d\n'
    } > "$dir/.github/workflows/fixture-suite-$(printf '%02d' "$i")-e2e.yml"
  done
}

# mk_tree_no_boot: the same tree with steps that boot NOTHING - what a broken
# BOOTS selector produces, without having to mutate the script to get there.
mk_tree_no_boot() {  # mk_tree_no_boot <dir> <enterprise|community> <n>
  local dir="$1" edition="$2" n="$3" i
  mk_tree "$dir" "$edition" 0 0
  for ((i = 1; i <= n; i++)); do
    printf 'name: Fixture Suite %02d\non:\n  merge_group:\njobs:\n  suite:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo nothing boots here\n' "$i" \
      > "$dir/.github/workflows/fixture-suite-$(printf '%02d' "$i")-e2e.yml"
  done
}

# run_floor DIR -> rc, with stdout captured in $OUT
OUT=""
run_floor() {
  OUT="$(python3 "$GATE" --check-floor "$1" 2>&1)"
  return $?
}

check() {  # check <label> <expected-rc> <dir> [substring that must appear]
  local label="$1" want="$2" dir="$3" needle="${4:-}"
  run_floor "$dir"
  local rc=$?
  if [ "$rc" -ne "$want" ]; then
    bad "$label (expected rc=$want, got rc=$rc)"
    printf '%s\n' "$OUT" | sed 's/^/        /'
    return
  fi
  if [ -n "$needle" ] && ! printf '%s' "$OUT" | grep -qF -- "$needle"; then
    bad "$label (rc correct but the verdict never said: $needle)"
    printf '%s\n' "$OUT" | sed 's/^/        /'
    return
  fi
  ok "$label"
}

echo "Suite Gate sanity floor: edition-aware, both directions"

# --- 1-3. the enterprise tree: the floor of 20 is exactly where it was -------
mk_tree "$tmp/ent20" enterprise 20 20
check "enterprise tree, 20 merge_group suites: passes at floor 20" \
  0 "$tmp/ent20" "sanity floor 20 met by 20"

mk_tree "$tmp/ent19" enterprise 19 19
check "enterprise tree, 19 merge_group suites: FAILS - the floor did not move" \
  1 "$tmp/ent19" "sanity floor 20"

mk_tree_no_boot "$tmp/entzero" enterprise 30
check "enterprise tree, selector matched nothing: FAILS - the original purpose" \
  1 "$tmp/entzero" "The selector is broken, not the day quiet."

# --- 4-6. the community mirror: derived from its own census -----------------
mk_tree "$tmp/com22" community 2 2
check "community tree, 2 of 2: passes - the floor of 20 no longer reaches it" \
  0 "$tmp/com22" "sanity floor 2 met by 2"

mk_tree "$tmp/com21" community 2 1
check "community tree, a mirrored suite drops merge_group: FAILS" \
  1 "$tmp/com21" "boots a stack but declares no merge_group: Fixture Suite 02"

mk_tree_no_boot "$tmp/comzero" community 3
check "community tree, selector matched nothing: FAILS - the floor is never below 1" \
  1 "$tmp/comzero" "sanity floor 1"

# --- 7. the marker itself, both ways ---------------------------------------
# A tree carrying BOTH marker files is enterprise; the same tree without the
# sync workflow is community. Nothing but the marker changes between them, so
# a passing pair here is the marker doing the deciding.
mk_tree "$tmp/marker" enterprise 2 2
check "both marker files present -> enterprise, so 2 suites FAIL the floor of 20" \
  1 "$tmp/marker" "the enterprise calibration MIN_SUITE_RUNS=20"
rm -f "$tmp/marker/.github/workflows/sync-community-repo.yml"
check "same tree, sync workflow removed -> community, and the same 2 suites pass" \
  0 "$tmp/marker" "derived from this community tree"

# --- 8. the real tree, edition-aware -----------------------------------------
# This file syncs to the mirror, so it must be true on the mirror's own inputs.
# The assertion is the same either way - the tree passes its own floor - and
# the REASON it passes is asserted per edition, so a mirror checkout is not
# quietly accepting the enterprise wording or vice versa.
if [ -f "$REPO_ROOT/.github/workflows/lint.yml" ] && \
   [ ! -f "$REPO_ROOT/.github/workflows/sync-community-repo.yml" ]; then
  check "this COMMUNITY checkout passes its own derived floor" \
    0 "$REPO_ROOT" "derived from this community tree"
else
  check "this ENTERPRISE checkout passes its own floor of 20" \
    0 "$REPO_ROOT" "the enterprise calibration MIN_SUITE_RUNS=20"
fi

echo
echo "  $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] || exit 1
exit 0
