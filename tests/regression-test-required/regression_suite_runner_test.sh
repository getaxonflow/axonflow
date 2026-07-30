#!/usr/bin/env bash
# Regression test for the regression-test suite runner (issue #3121).
#
# THE BUG
# -------
# Nothing in the repository executed anything under
# tests/regression-test-required/. The CI gate
# (.github/workflows/regression-test-required.yml) is a PRESENCE check: it
# verifies a test file appears in the bug-fix PR's diff and never runs it. So a
# `fix:` PR satisfied the gate with a test that had never executed, could have
# been failing against `main` on the day it merged, or asserted nothing at all.
#
# tests/regression-test-required/run-all.sh + the `run-regression-suite` job
# close that. This file is the test OF that runner.
#
# WHY THIS TEST IS SHAPED THIS WAY
# --------------------------------
# The runner's whole value is that it cannot report success without having done
# the work — so verifying it by reading it would be exactly the mistake #3121
# is about. Every property below is proved by EXECUTING the runner over a
# synthetic suite directory and checking its exit code:
#
#   * a failing test FAILS the run (not a warning, not a skip);
#   * an empty suite directory FAILS (nothing discovered is never a pass);
#   * a missing suite directory FAILS;
#   * an unreadable test FAILS;
#   * the runner does not execute itself;
#   * discovered and executed counts are reported and agree.
#
# Exit codes are taken from a direct invocation, never from a `$(...)` capture:
# command substitution runs in a subshell and would discard the status, making
# every exit-code assertion here pass unconditionally.
#
# Fixture directories are created fresh per scenario and never reused or
# removed — a stale fixture is a false result in both directions, and the work
# dir is printed so a failure can be inspected after the fact.
#
# Run locally:
#   bash tests/regression-test-required/regression_suite_runner_test.sh

set -uo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
RUNNER="${RUNNER_UNDER_TEST:-${REPO_ROOT}/tests/regression-test-required/run-all.sh}"
WORKFLOW="${WORKFLOW_UNDER_TEST:-${REPO_ROOT}/.github/workflows/regression-test-required.yml}"

WORK_ROOT="${TEST_WORK_DIR:-$(mktemp -d)}"
mkdir -p "$WORK_ROOT"

echo "runner under test: $RUNNER"
echo "work dir:          $WORK_ROOT"
echo

ASSERTIONS_RUN=0
FAILURES=0
EXPECTED_ASSERTIONS_MIN=20

fail() {
    echo "  FAIL: $*"
    FAILURES=$((FAILURES + 1))
}

assert_true() {
    ASSERTIONS_RUN=$((ASSERTIONS_RUN + 1))
    if [ "$1" -eq 0 ]; then
        echo "  ok: $2"
    else
        fail "$2"
    fi
}

assert_exit_code() {
    ASSERTIONS_RUN=$((ASSERTIONS_RUN + 1))
    if [ "$1" = "$2" ]; then
        echo "  ok: $3 (exit $2)"
    else
        fail "$3 — expected exit $2, got $1"
    fi
}

assert_nonzero_exit() {
    ASSERTIONS_RUN=$((ASSERTIONS_RUN + 1))
    if [ "$1" -ne 0 ]; then
        echo "  ok: $2 (exit $1)"
    else
        fail "$2 — runner exited 0; it reported success without doing the work"
    fi
}

assert_grep() {
    # $1 pattern  $2 file  $3 message
    ASSERTIONS_RUN=$((ASSERTIONS_RUN + 1))
    if grep -qE "$1" "$2"; then
        echo "  ok: $3"
    else
        fail "$3 — pattern '$1' not found in $2"
    fi
}

if [ ! -f "$RUNNER" ]; then
    echo "FAIL: runner not found at $RUNNER"
    echo "      This is the #3121 defect itself: without it, nothing executes"
    echo "      tests/regression-test-required/."
    exit 1
fi

new_fixture() {
    local d
    d="$(mktemp -d "${WORK_ROOT}/${1}-XXXXXX")"
    echo "$d"
}

# Runs the runner over <suite_dir>, capturing combined output into <outfile>,
# and RETURNS the runner's exit code.
run_runner() {
    local suite_dir="$1" outfile="$2"
    REGRESSION_SUITE_DIR="$suite_dir" bash "$RUNNER" >"$outfile" 2>&1
    return $?
}

passing_test() {
    cat >"$1" <<'EOF'
#!/usr/bin/env bash
echo "this test passes"
exit 0
EOF
    chmod +x "$1"
}

failing_test() {
    cat >"$1" <<'EOF'
#!/usr/bin/env bash
echo "this test is deliberately broken"
exit 1
EOF
    chmod +x "$1"
}

# ---------------------------------------------------------------------------
# Scenario 1 — the baseline: every test passes.
# On its own this proves nothing (a runner that always exits 0 passes it too);
# it exists so Scenario 2's failure can be attributed to the failing test
# rather than to the runner being broken outright.
# ---------------------------------------------------------------------------
echo "── Scenario 1: all tests pass ──"
S1="$(new_fixture s1)"
passing_test "${S1}/alpha_test.sh"
passing_test "${S1}/beta_test.sh"
run_runner "$S1" "${S1}/out.log"; S1_RC=$?
assert_exit_code "$S1_RC" 0 "runner exits 0 when every test passes"
assert_grep '^  Discovered: 2$' "${S1}/out.log" "runner reports 2 discovered"
assert_grep '^  Executed:   2$' "${S1}/out.log" "runner reports 2 executed"
assert_grep '^  Failed:     0$' "${S1}/out.log" "runner reports 0 failed"

# ---------------------------------------------------------------------------
# Scenario 2 — THE load-bearing one. A deliberately broken test must fail the
# run. This is the mutation: it is the only scenario that can tell a real
# runner apart from one that reports success unconditionally.
# ---------------------------------------------------------------------------
echo
echo "── Scenario 2: one deliberately broken test ──"
S2="$(new_fixture s2)"
passing_test "${S2}/alpha_test.sh"
failing_test "${S2}/broken_test.sh"
passing_test "${S2}/gamma_test.sh"
run_runner "$S2" "${S2}/out.log"; S2_RC=$?
assert_nonzero_exit "$S2_RC" "a failing test FAILS the run"
assert_grep 'FAIL  broken_test\.sh' "${S2}/out.log" "the failing test is named in the output"
assert_grep '^  Failed:     1$' "${S2}/out.log" "runner reports exactly 1 failure"
# The other two must still have run — one failure may not abort the suite, or a
# single early failure would mask every test after it.
assert_grep '^  Executed:   3$' "${S2}/out.log" "the other tests still ran after the failure"
assert_grep '^::error file=tests/regression-test-required/broken_test\.sh::' "${S2}/out.log" \
    "the failure is annotated for the CI run summary"

# ---------------------------------------------------------------------------
# Scenario 3 — an empty suite directory must FAIL.
# "Nothing to do" reported as success is precisely how #3098 stayed invisible.
# ---------------------------------------------------------------------------
echo
echo "── Scenario 3: empty suite directory ──"
S3="$(new_fixture s3)"
run_runner "$S3" "${S3}/out.log"; S3_RC=$?
assert_nonzero_exit "$S3_RC" "an empty suite directory FAILS (discovering nothing is not a pass)"
assert_grep '::error::No test scripts found' "${S3}/out.log" "the empty-suite failure says why"

# ---------------------------------------------------------------------------
# Scenario 4 — a missing suite directory must FAIL.
# ---------------------------------------------------------------------------
echo
echo "── Scenario 4: missing suite directory ──"
S4_PARENT="$(new_fixture s4)"
S4="${S4_PARENT}/never-created"
run_runner "$S4" "${S4_PARENT}/out.log"; S4_RC=$?
assert_nonzero_exit "$S4_RC" "a missing suite directory FAILS"
assert_grep '::error::Regression-test suite directory not found' "${S4_PARENT}/out.log" \
    "the missing-directory failure says why"

# ---------------------------------------------------------------------------
# Scenario 5 — an unreadable test must FAIL closed.
#
# A dangling symlink is used rather than `chmod 000`: chmod is a no-op for
# root, and CI containers routinely run as root, so a chmod-based fixture
# would quietly stop testing anything on exactly the runner that matters.
# `[[ -r ]]` is false on a dangling symlink for every user including root.
# ---------------------------------------------------------------------------
echo
echo "── Scenario 5: an unreadable test script ──"
S5="$(new_fixture s5)"
passing_test "${S5}/alpha_test.sh"
ln -s "${S5}/definitely-not-here" "${S5}/dangling_test.sh"
run_runner "$S5" "${S5}/out.log"; S5_RC=$?
assert_nonzero_exit "$S5_RC" "an unreadable test script FAILS the run"
assert_grep 'not readable' "${S5}/out.log" "the unreadable-script failure says why"

# ---------------------------------------------------------------------------
# Scenario 6 — the runner does not execute itself.
# A file in the suite dir sharing the runner's own basename must be skipped;
# everything else must run.
#
# The decoy is named after $RUNNER's basename rather than the literal
# "run-all.sh" so that this scenario keeps testing self-exclusion, and only
# self-exclusion, when the test is pointed at a renamed runner via
# RUNNER_UNDER_TEST — otherwise every mutant would trip this scenario for a
# reason that has nothing to do with the mutation.
# ---------------------------------------------------------------------------
echo
echo "── Scenario 6: self-exclusion ──"
S6="$(new_fixture s6)"
passing_test "${S6}/alpha_test.sh"
failing_test "${S6}/$(basename "$RUNNER")"   # would fail the run if it were executed
run_runner "$S6" "${S6}/out.log"; S6_RC=$?
assert_exit_code "$S6_RC" 0 "the runner skips a suite-dir file sharing its own name ($(basename "$RUNNER"))"
assert_grep '^  Discovered: 1$' "${S6}/out.log" "only the real test is discovered"

# ---------------------------------------------------------------------------
# Scenario 7 — tests that read stdin cannot truncate dispatch.
# This is the #3098 shape: a dispatch loop reading its work list on its own
# stdin loses every remaining entry to the first test that drains it.
# ---------------------------------------------------------------------------
echo
echo "── Scenario 7: a test that drains stdin ──"
S7="$(new_fixture s7)"
passing_test "${S7}/a_test.sh"
cat >"${S7}/b_drains_stdin_test.sh" <<'EOF'
#!/usr/bin/env bash
cat >/dev/null
echo "drained stdin"
exit 0
EOF
chmod +x "${S7}/b_drains_stdin_test.sh"
passing_test "${S7}/c_test.sh"
run_runner "$S7" "${S7}/out.log"; S7_RC=$?
assert_exit_code "$S7_RC" 0 "suite exits 0 when every entry passes"
assert_grep '^  Discovered: 3$' "${S7}/out.log" "3 discovered"
assert_grep '^  Executed:   3$' "${S7}/out.log" "3 executed — a stdin-draining test truncates nothing"

# ---------------------------------------------------------------------------
# Scenario 8 — the CI wiring. A runner nothing calls is #3121 all over again.
# ---------------------------------------------------------------------------
echo
echo "── Scenario 8: the runner is actually wired into CI ──"

WIRING="$(python3 - "$WORKFLOW" <<'PY'
import sys, yaml
d = yaml.safe_load(open(sys.argv[1]))
on = d.get(True, d.get("on", {}))
invokes = False
for job in d.get("jobs", {}).values():
    for step in job.get("steps", []) or []:
        if "run-all.sh" in (step.get("run") or ""):
            invokes = True
print("invokes=%s" % ("yes" if invokes else "no"))
# A paths filter that forgets tests/regression-test-required/** or the
# workflow itself is the #3089 failure mode. No filter at all is the
# strongest form and what we assert.
pr = on.get("pull_request", {}) or {}
print("paths=%s" % ("none" if not (pr.get("paths") or pr.get("paths-ignore")) else "filtered"))
PY
)"
echo "$WIRING" | sed 's/^/  /'

case "$WIRING" in
    *"invokes=yes"*) assert_true 0 "a workflow job invokes tests/regression-test-required/run-all.sh";;
    *)               assert_true 1 "a workflow job invokes tests/regression-test-required/run-all.sh";;
esac
case "$WIRING" in
    *"paths=none"*) assert_true 0 "the workflow has no paths filter, so it runs on PRs that change the tests or the workflow";;
    *)              assert_true 1 "the workflow has no paths filter, so it runs on PRs that change the tests or the workflow";;
esac

# ---------------------------------------------------------------------------
echo
echo "── Summary ──"
echo "  assertions run: $ASSERTIONS_RUN (floor $EXPECTED_ASSERTIONS_MIN)"
echo "  failures:       $FAILURES"

if [ "$ASSERTIONS_RUN" -lt "$EXPECTED_ASSERTIONS_MIN" ]; then
    echo "FAIL: only $ASSERTIONS_RUN assertions ran, expected at least $EXPECTED_ASSERTIONS_MIN."
    echo "      The test bailed early; a green run that asserted nothing is not a pass."
    exit 1
fi

if [ "$FAILURES" -gt 0 ]; then
    echo "FAIL: $FAILURES assertion(s) failed. Work dir kept at $WORK_ROOT"
    exit 1
fi

echo "Assertions run: $ASSERTIONS_RUN"
echo "✅ the regression-test suite runner fails on a failing test, on an empty or missing suite, and is wired into CI."
