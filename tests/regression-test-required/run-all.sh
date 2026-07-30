#!/usr/bin/env bash
# Executes every regression test in tests/regression-test-required/.
#
# WHY THIS EXISTS (#3121)
# -----------------------
# `.github/workflows/regression-test-required.yml` is a PRESENCE gate: it
# checks that a bug-fix PR's diff contains an added-or-modified test file. It
# never runs one. Until this script was wired into CI, nothing in the repo
# executed anything under tests/regression-test-required/ — so a `fix:` PR
# could satisfy the gate with a test that had never run, that failed against
# `main` on the day it was merged, or that asserted nothing at all.
#
# Presence is not execution, and a check that cannot fail is not a check.
# That is the same conclusion reached by #2689 (a suite referenced by nothing),
# #3098 (a runner reporting PASSED while skipping entries) and #3120 (this
# gate being bypassable). This script closes the execution half.
#
# FAIL-CLOSED BY CONSTRUCTION
# ---------------------------
# The whole point of this runner is that it must be incapable of reporting
# success without having done the work. Four properties enforce that, and each
# one is pinned by a behavioural assertion in
# tests/regression-test-required/regression_suite_runner_test.sh:
#
#   1. A test that exits non-zero fails the run. Not a warning, not a skip.
#   2. A missing suite directory fails the run. "Nothing to do" is never a pass.
#   3. An empty suite directory (zero candidates) fails the run, for the same
#      reason: a runner that discovers nothing has not verified anything.
#   4. Discovered count and executed count are compared at the end. If they
#      ever diverge the run fails, even if every executed test passed. This is
#      the #3098 defect class — a dispatch loop losing entries and still
#      printing a green summary — and the guard is deliberately independent of
#      the loop that would be doing the losing.
#
# Each test is invoked with stdin redirected from /dev/null so that a test
# which reads stdin cannot consume anything the runner depends on. Dispatch
# iterates over a pre-built array rather than a stream, so stdin draining
# cannot truncate it either — belt and braces, for exactly the #3098 reason.
#
# Tests are run from the repository root. Several of them use paths relative
# to the working directory (e.g. `WORKFLOW_DIR=".github/workflows"`), so the
# cwd is part of their contract.
#
# Run locally:
#   bash tests/regression-test-required/run-all.sh
#
# Override the suite directory (used by the runner's own regression test to
# drive it over synthetic fixtures):
#   REGRESSION_SUITE_DIR=/path/to/dir bash tests/regression-test-required/run-all.sh

# NOTE: deliberately NOT `set -e`. Every test must get a chance to run so one
# failure does not hide the rest; failures are accumulated and reported at the
# end. `-u` and `pipefail` stay on.
set -uo pipefail

self_path="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
self_name="$(basename "${BASH_SOURCE[0]}")"

if [[ -n "${REGRESSION_SUITE_DIR:-}" ]]; then
    suite_dir="$REGRESSION_SUITE_DIR"
    # Fixture runs execute from the fixture's own directory; there is no
    # repository to be at the root of.
    repo_root="$suite_dir"
else
    repo_root="$(cd "$(dirname "$self_path")/../.." && pwd)"
    suite_dir="${repo_root}/tests/regression-test-required"
fi

echo "════════════════════════════════════════════════════════════════"
echo "Regression-test suite runner"
echo "  suite dir: $suite_dir"
echo "  cwd:       $repo_root"
echo "════════════════════════════════════════════════════════════════"

# Property 2 — a missing directory is a failure, never a pass.
if [[ ! -d "$suite_dir" ]]; then
    echo "::error::Regression-test suite directory not found: $suite_dir"
    echo "Refusing to report success: a runner that cannot find its tests has" >&2
    echo "verified nothing. If the directory moved, update this runner and the" >&2
    echo "job in .github/workflows/regression-test-required.yml together." >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Discovery. Everything ending in .sh except this runner itself.
#
# The glob is deliberately `*.sh` and not `*_test.sh`: a test dropped into this
# directory under any name must still run. Excluding only this file by NAME
# (not by path) means a copy of the runner under a different name would be
# executed as a test, which is the safe direction — it would run, pass or
# fail on its own merits, and never be silently ignored.
# ---------------------------------------------------------------------------
shopt -s nullglob
candidates=()
for f in "$suite_dir"/*.sh; do
    [[ "$(basename "$f")" == "$self_name" ]] && continue
    candidates+=("$f")
done
shopt -u nullglob

discovered=${#candidates[@]}

# Property 3 — zero candidates is a failure.
if (( discovered == 0 )); then
    echo "::error::No test scripts found in $suite_dir"
    echo "Refusing to report success on an empty suite. Either the directory was" >&2
    echo "emptied (which should fail loudly) or the discovery glob drifted." >&2
    exit 1
fi

# Unreadable files fail closed too — a test that cannot be read cannot be
# asserted to have passed.
unreadable=()
for f in "${candidates[@]}"; do
    [[ -r "$f" ]] || unreadable+=("$f")
done
if (( ${#unreadable[@]} > 0 )); then
    echo "::error::Test script(s) present but not readable:"
    printf '  %s\n' "${unreadable[@]}" >&2
    exit 1
fi

echo
echo "Discovered $discovered test script(s):"
for f in "${candidates[@]}"; do
    echo "  - $(basename "$f")"
done
echo

# ---------------------------------------------------------------------------
# Dispatch.
# ---------------------------------------------------------------------------
executed=0
failed_tests=()
passed_tests=()

for f in "${candidates[@]}"; do
    name="$(basename "$f")"
    echo "──────────────────────────────────────────────────────────────"
    echo "▶ $name"
    echo "──────────────────────────────────────────────────────────────"
    start=$SECONDS

    # `cd` in a subshell so a test that changes directory cannot affect the
    # next one. stdin from /dev/null: see the #3098 note in the header.
    ( cd "$repo_root" && bash "$f" ) </dev/null
    rc=$?

    executed=$(( executed + 1 ))
    elapsed=$(( SECONDS - start ))

    if (( rc == 0 )); then
        echo "✅ PASS  $name  (${elapsed}s)"
        passed_tests+=("$name")
    else
        echo "❌ FAIL  $name  (exit $rc, ${elapsed}s)"
        echo "::error file=tests/regression-test-required/${name}::Regression test ${name} failed (exit ${rc})"
        failed_tests+=("$name")
    fi
    echo
done

# ---------------------------------------------------------------------------
# Summary + Property 4 (the anti-#3098 guard).
# ---------------------------------------------------------------------------
echo "════════════════════════════════════════════════════════════════"
echo "Regression-test suite summary"
echo "  Discovered: $discovered"
echo "  Executed:   $executed"
echo "  Passed:     ${#passed_tests[@]}"
echo "  Failed:     ${#failed_tests[@]}"
echo "════════════════════════════════════════════════════════════════"

exit_code=0

if (( executed != discovered )); then
    echo "::error::Dispatch mismatch — discovered $discovered test(s) but executed $executed."
    echo "This is the #3098 failure class: a runner that loses entries mid-loop and" >&2
    echo "still reports a summary. Refusing to report success." >&2
    exit_code=1
fi

if (( ${#failed_tests[@]} > 0 )); then
    echo
    echo "Failing test(s):"
    printf '  %s\n' "${failed_tests[@]}"
    echo
    echo "Each of these is a regression test that a previous bug-fix PR committed" >&2
    echo "to. A failure here means either the fix regressed or the test drifted —" >&2
    echo "both need a human, neither may be skipped." >&2
    exit_code=1
fi

if (( exit_code == 0 )); then
    echo
    echo "All $executed regression test(s) passed."
fi

exit "$exit_code"
