#!/usr/bin/env bash
# Regression test for the production-posture runner's dispatch truncation
# (scripts/e2e/run-production-posture-suite.sh, issue #3071).
#
# THE BUG
# -------
# The dispatch loop read the registry on its OWN stdin (`done <"$REGISTRY"`)
# and invoked each entry with `bash -c "$invocation" 2>&1`, which inherits
# that stdin. Any entry that reads stdin — `docker compose exec -T ... psql`,
# `docker run -i ...`, buildkit — therefore consumed the REMAINING REGISTRY
# LINES. The loop hit EOF and stopped dispatching, silently, still exiting 0.
# The job printed "✅ Suite PASSED" while never running the tail of the
# registry. A registered-but-never-dispatched suite is exactly as dead as an
# unregistered one, and the symptom is a GREEN job — which is why this went
# unnoticed and why it needs a test rather than an exemption.
#
# WHY THIS TEST EXISTS IN THIS SHAPE
# ----------------------------------
# * Marker FILES, never `echo` sentinels. `some-command >/dev/null 2>&1` is a
#   legal registry invocation, so a stdout sentinel reports "never ran" for an
#   entry that ran perfectly. A marker file cannot be redirected away.
# * A FRESH directory per scenario. A marker left over from an earlier run is
#   a false positive for "the entry ran", which inverts what the test proves.
#   Nothing is ever reused, and nothing is deleted — the work dir is printed
#   so a failure can be inspected after the fact.
# * Scenario 3 (an entry that drains fd 3 directly) is the load-bearing one.
#   Scenarios 1 and 2 pass with EITHER half of the fix, so on their own they
#   cannot tell whether the count guard does independent work. Scenario 3
#   defeats `</dev/null` deliberately and can only be caught by a count taken
#   from a SEPARATE pre-scan. If someone "simplifies" the two reads back into
#   one, this scenario is what fails.
#
# Run locally:
#   bash tests/regression-test-required/posture_runner_dispatch_truncation_test.sh
#
# Prove it actually discriminates (must FAIL against the pre-fix runner):
#   git show <pre-fix-sha>:scripts/e2e/run-production-posture-suite.sh >/tmp/pre.sh
#   RUNNER_UNDER_TEST=/tmp/pre.sh bash tests/regression-test-required/posture_runner_dispatch_truncation_test.sh

set -uo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
RUNNER="${RUNNER_UNDER_TEST:-${REPO_ROOT}/scripts/e2e/run-production-posture-suite.sh}"

WORK_ROOT="${TEST_WORK_DIR:-$(mktemp -d)}"
mkdir -p "$WORK_ROOT"
echo "work dir: $WORK_ROOT"
echo "runner under test: $RUNNER"

ASSERTIONS_RUN=0
FAILURES=0
# Every scenario below contributes at least one assertion. If the count comes
# out under this floor the test bailed early somewhere and is not entitled to
# report success — a green run that asserted nothing is the very defect this
# file exists to prevent.
EXPECTED_ASSERTIONS_MIN=12

fail() {
    echo "  FAIL: $*"
    FAILURES=$((FAILURES + 1))
}

assert_true() { # <condition-result:0/1> <description>
    ASSERTIONS_RUN=$((ASSERTIONS_RUN + 1))
    if [[ "$1" -ne 0 ]]; then
        fail "$2"
    else
        echo "  ok: $2"
    fi
}

assert_marker_present() { # <path> <description>
    ASSERTIONS_RUN=$((ASSERTIONS_RUN + 1))
    if [[ -e "$1" ]]; then
        echo "  ok: $2"
    else
        fail "$2 (marker file missing: $1)"
    fi
}

assert_marker_absent() { # <path> <description>
    ASSERTIONS_RUN=$((ASSERTIONS_RUN + 1))
    if [[ -e "$1" ]]; then
        fail "$2 (marker file unexpectedly present: $1)"
    else
        echo "  ok: $2"
    fi
}

assert_exit_code() { # <actual> <expected> <description>
    ASSERTIONS_RUN=$((ASSERTIONS_RUN + 1))
    if [[ "$1" == "$2" ]]; then
        echo "  ok: $3"
    else
        fail "$3 (expected exit $2, got $1)"
    fi
}

# Build an isolated scenario directory. Never reused, never cleaned.
new_scenario_dir() { # <name>
    local d
    d="$(mktemp -d "${WORK_ROOT}/${1}-XXXXXX")"
    printf '%s' "$d"
}

# The runner refuses to start without `docker` on PATH, and scans container
# logs for boot-time RLS violations. Scenarios that do not need a real
# container get a stub so they are hermetic and deterministic: a developer
# with a live (or broken) axonflow stack on the machine must not change this
# test's verdict.
STUB_BIN="${WORK_ROOT}/stub-bin"
mkdir -p "$STUB_BIN"
cat >"${STUB_BIN}/docker" <<'STUB'
#!/usr/bin/env bash
# Minimal stand-in: `logs` yields nothing (⇒ clean-boot assertion passes),
# anything else is a no-op success. Never contacts a real daemon.
exit 0
STUB
chmod +x "${STUB_BIN}/docker"

# Run the runner over a registry, capturing stdout+stderr into <outfile> and
# RETURNING the runner's exit code.
#
# The output deliberately goes to a file rather than to stdout: a `$(...)`
# wrapper would run this in a subshell, and an exit code stashed in a global
# there never reaches the caller — every exit-code assertion would then read a
# stale 0 and pass unconditionally. That is the same "check that reports
# success without checking" failure this file exists to prevent, so it is not
# a shape worth having anywhere in here.
#
# The runner is given `</dev/null` as ITS stdin, and a wall-clock timeout
# where one is available. Both are anti-hang measures, learned the hard way:
# a runner that keeps the registry on fd 3 but loses the per-invocation
# `</dev/null` leaves `cat` inheriting whatever stdin the test itself was
# started with. Under a CI runner that is often a pipe nobody ever closes, so
# the entry blocks forever and the job dies on the workflow timeout with no
# usable output. A test for a silent-truncation bug must not itself fail
# silently by hanging — it has to return a verdict.
TIMEOUT_BIN=""
for _t in timeout gtimeout; do
    command -v "$_t" >/dev/null 2>&1 && { TIMEOUT_BIN="$_t"; break; }
done
SUITE_TIMEOUT_SECS="${SUITE_TIMEOUT_SECS:-120}"

run_suite() { # <registry> <use-real-docker:0/1> <outfile> [extra-env...]
    local registry="$1" real_docker="$2" outfile="$3" path
    shift 3
    path="$PATH"
    [[ "$real_docker" == "0" ]] && path="${STUB_BIN}:${PATH}"
    if [[ -n "$TIMEOUT_BIN" ]]; then
        env "PATH=$path" \
            SUITE_SKIP_BOOT_PROBE=1 \
            "SUITE_REGISTRY=$registry" \
            AGENT_CONTAINER=axonflow-dispatch-test-absent-agent \
            ORCH_CONTAINER=axonflow-dispatch-test-absent-orch \
            PORTAL_CONTAINER=axonflow-dispatch-test-absent-portal \
            "$@" \
            "$TIMEOUT_BIN" "$SUITE_TIMEOUT_SECS" \
            bash "$RUNNER" >"$outfile" 2>&1 </dev/null
    else
        env "PATH=$path" \
            SUITE_SKIP_BOOT_PROBE=1 \
            "SUITE_REGISTRY=$registry" \
            AGENT_CONTAINER=axonflow-dispatch-test-absent-agent \
            ORCH_CONTAINER=axonflow-dispatch-test-absent-orch \
            PORTAL_CONTAINER=axonflow-dispatch-test-absent-portal \
            "$@" \
            bash "$RUNNER" >"$outfile" 2>&1 </dev/null
    fi
}

# ---------------------------------------------------------------------------
# Scenario 0 — `</dev/null` is present on the invocation (structural).
#
# This one cannot be proven behaviourally: with the registry on fd 3, the
# stdin fix and the fd fix each independently rescue scenarios 1 and 2, so a
# runner missing `</dev/null` still passes them. It is kept because the
# redirect is the defence that survives a refactor back to `done <"$REGISTRY"`.
# ---------------------------------------------------------------------------
echo
echo "── Scenario 0: invocation is insulated from the loop's stdin ──"
# shellcheck disable=SC2016  # $invocation is literal source text being matched, not a variable to expand.
grep -qE 'bash -c "\$invocation" *</dev/null' "$RUNNER"
assert_true $? "entries are invoked with </dev/null so a stdin-reading suite gets EOF"

# ---------------------------------------------------------------------------
# Scenario 1 — an entry that reads stdin must not eat the rest of the registry.
# Pre-fix: 2 of 4 entries processed, 1 of 3 markers, exit 0, "Suite PASSED".
# ---------------------------------------------------------------------------
echo
echo "── Scenario 1: entry #2 reads stdin (cat >/dev/null) ──"
S1="$(new_scenario_dir s1)"
cat >"${S1}/registry.txt" <<EOF
touch ${S1}/marker-1|pass|-|marker for entry 1
cat >/dev/null|pass|-|entry that reads stdin
touch ${S1}/marker-3|pass|-|marker for entry 3
touch ${S1}/marker-4|pass|-|marker for entry 4
EOF
run_suite "${S1}/registry.txt" 0 "${S1}/output.log"
S1_RC=$?
S1_OUT="$(cat "${S1}/output.log")"

assert_marker_present "${S1}/marker-1" "entry #1 ran"
assert_marker_present "${S1}/marker-3" "entry #3 ran (pre-fix: eaten by entry #2's stdin read)"
assert_marker_present "${S1}/marker-4" "entry #4 ran (pre-fix: eaten by entry #2's stdin read)"
grep -qE '^  Entries dispatched: +4$' <<<"$S1_OUT"
assert_true $? "runner reports 4 of 4 entries dispatched"
assert_exit_code "$S1_RC" 0 "suite exits 0 when every entry passes"

# ---------------------------------------------------------------------------
# Scenario 2 — the real-world class: a container that drains stdin.
# `docker run -i ... cat` is the shape that actually bit CI (compose exec -T
# forwards stdin into the container). Needs a real daemon; skipped without
# one, and the skip is loud so it can never be mistaken for a pass.
# ---------------------------------------------------------------------------
echo
echo "── Scenario 2: entry #2 is a stdin-draining container ──"
DOCKER_IMAGE="${DISPATCH_TEST_IMAGE:-alpine}"
if command -v docker >/dev/null 2>&1 && docker image inspect "$DOCKER_IMAGE" >/dev/null 2>&1; then
    S2="$(new_scenario_dir s2)"
    S2_NAME="axonflow-dispatch-test-$$-$RANDOM"
    cat >"${S2}/registry.txt" <<EOF
touch ${S2}/marker-1|pass|-|marker for entry 1
docker run --rm -i --name ${S2_NAME} ${DOCKER_IMAGE} cat|pass|-|container that drains stdin
touch ${S2}/marker-3|pass|-|marker for entry 3
EOF
    run_suite "${S2}/registry.txt" 1 "${S2}/output.log"
    S2_RC=$?
    S2_OUT="$(cat "${S2}/output.log")"

    assert_marker_present "${S2}/marker-1" "entry #1 ran"
    assert_marker_present "${S2}/marker-3" "entry #3 ran after a real container drained stdin"
    grep -qE '^  Entries dispatched: +3$' <<<"$S2_OUT"
    assert_true $? "runner reports 3 of 3 entries dispatched"
    assert_exit_code "$S2_RC" 0 "suite exits 0 when every entry passes"
else
    echo "  SKIPPED: docker daemon or image '${DOCKER_IMAGE}' unavailable."
    echo "           Scenario 1 covers the same defect with a hermetic stdin reader;"
    echo "           this scenario adds the real-container shape only."
fi

# ---------------------------------------------------------------------------
# Scenario 3 — an entry that drains fd 3 DIRECTLY, defeating `</dev/null`.
#
# The count guard must catch it. This is what proves the guard does
# independent work: ENTRIES_DECLARED comes from a separate pre-scan whose
# loop body spawns no subprocess and so cannot itself be drained. Collapse
# the two reads into one and this scenario stops failing — silently.
# ---------------------------------------------------------------------------
echo
echo "── Scenario 3: entry #2 drains fd 3 directly ──"
S3="$(new_scenario_dir s3)"
cat >"${S3}/registry.txt" <<EOF
touch ${S3}/marker-1|pass|-|marker for entry 1
cat <&3 >/dev/null|pass|-|entry that drains the dispatch fd
touch ${S3}/marker-3|pass|-|marker for entry 3
touch ${S3}/marker-4|pass|-|marker for entry 4
EOF
run_suite "${S3}/registry.txt" 0 "${S3}/output.log"
S3_RC=$?
S3_OUT="$(cat "${S3}/output.log")"

assert_marker_present "${S3}/marker-1" "entry #1 ran before the truncation"
assert_marker_absent  "${S3}/marker-3" "entry #3 genuinely never ran (the truncation is real)"
grep -q 'DISPATCH TRUNCATED' <<<"$S3_OUT"
assert_true $? "runner reports DISPATCH TRUNCATED"
assert_exit_code "$S3_RC" 1 "truncation FAILS the job, rather than merely printing a warning"
if grep -q 'Suite PASSED' <<<"$S3_OUT"; then S3_CLAIMED_PASS=1; else S3_CLAIMED_PASS=0; fi
assert_true "$S3_CLAIMED_PASS" "runner does not claim 'Suite PASSED' after truncating"

# ---------------------------------------------------------------------------
# Scenario 4 — the comparison is `-ne`, not `-lt`.
# An entry that APPENDS to the registry mid-run makes the loop reach MORE
# entries than were declared. That is equally a broken run and must fail too.
# ---------------------------------------------------------------------------
echo
echo "── Scenario 4: entry appends to the registry mid-run ──"
S4="$(new_scenario_dir s4)"
cat >"${S4}/append.sh" <<EOF
#!/usr/bin/env bash
printf 'touch %s/marker-appended\x7cpass\x7c-\x7cappended mid-run\n' "${S4}" >>"${S4}/registry.txt"
EOF
chmod +x "${S4}/append.sh"
cat >"${S4}/registry.txt" <<EOF
touch ${S4}/marker-1|pass|-|marker for entry 1
bash ${S4}/append.sh|pass|-|appends a registry line while the loop is reading
EOF
run_suite "${S4}/registry.txt" 0 "${S4}/output.log"
S4_RC=$?
S4_OUT="$(cat "${S4}/output.log")"

grep -q 'DISPATCH TRUNCATED' <<<"$S4_OUT"
assert_true $? "a registry that grows mid-run is caught (comparison is -ne, not -lt)"
assert_exit_code "$S4_RC" 1 "mid-run growth FAILS the job"

# ---------------------------------------------------------------------------
# Scenario 5 — the real registry still parses under the fixed loop.
# ---------------------------------------------------------------------------
echo
echo "── Scenario 5: the committed registry parses and dispatches completely ──"
REAL_REGISTRY="${REPO_ROOT}/scripts/e2e/production_posture_registry.txt"
DECLARED="$(grep -cvE '^[[:space:]]*(#|$)' "$REAL_REGISTRY")"
S5="$(new_scenario_dir s5)"
# SUITE_REGISTRY is passed explicitly rather than relying on the runner's
# default: the runner resolves the default relative to its OWN directory, so a
# copy under test elsewhere on disk would fail here for a reason that has
# nothing to do with the registry. This scenario is about the registry.
run_suite "$REAL_REGISTRY" 0 "${S5}/output.log" SUITE_DRY_RUN=1
S5_RC=$?
S5_OUT="$(cat "${S5}/output.log")"

grep -qE "^  Entries processed: +${DECLARED}\$" <<<"$S5_OUT"
assert_true $? "all ${DECLARED} committed registry entries are reached"
grep -qE '^  Parse errors: +0$' <<<"$S5_OUT"
assert_true $? "committed registry parses with zero errors"
assert_exit_code "$S5_RC" 0 "dry-run over the committed registry exits 0"

# ---------------------------------------------------------------------------
echo
echo "Assertions run: ${ASSERTIONS_RUN}"
if [[ "$ASSERTIONS_RUN" -lt "$EXPECTED_ASSERTIONS_MIN" ]]; then
    echo "FAIL: only ${ASSERTIONS_RUN} assertions ran, expected at least ${EXPECTED_ASSERTIONS_MIN}."
    echo "      A run that asserts nothing must not report success — that is the"
    echo "      exact defect class this file guards (#3071)."
    exit 1
fi
if [[ "$FAILURES" -gt 0 ]]; then
    echo "FAIL: ${FAILURES} assertion(s) failed. Captured runner output is under ${WORK_ROOT}."
    exit 1
fi
echo "PASS: the posture runner dispatches every declared registry entry and fails loudly when it cannot."
