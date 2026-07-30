#!/usr/bin/env bash
# Regression test for the two defects in
# .github/workflows/definition-of-done.yml (issue #3144).
#
# THE BUGS
# --------
# The `Runtime E2E required for user-facing changes` job is in the
# `Main Branch Protection` ruleset's required-status-checks list, and it
# carried both of the defects #3138 had just fixed in the sibling gate
# .github/workflows/regression-test-required.yml — so the weaker of the two
# was the one that could actually let a merge past.
#
#   1. `PR_TITLE` / `PR_BODY` came from `github.event.pull_request.*`, i.e.
#      state-at-trigger. Mitigated only incidentally, because `edited`
#      happens to be in the trigger list.
#
#   2. The justification check was a bare
#      `grep -q '## Skip-runtime-e2e justification'`. **A HEADING ALONE
#      WAIVED THE GATE.** An author could put `[skip-runtime-e2e]` in the
#      title, paste the heading into the body, type nothing under it, and the
#      runtime-e2e requirement was satisfied. CLAUDE.md HARD RULE #9 requires
#      explicit operator approval for that escape hatch; a gate a blank
#      heading can waive cannot enforce it.
#
# WHY THIS TEST IS SHAPED THIS WAY
# --------------------------------
# The load-bearing assertions EXECUTE the workflow's real steps, extracted
# verbatim out of the YAML, against synthetic PR state and a stubbed `gh`.
# Asserting on the YAML text alone would test the renderer, not the path: a
# grep for "gh api" passes whether or not the read actually fails closed. So
# the text assertions here cover only what genuinely IS a property of the file
# (trigger list, paths filter, permissions, absence of the payload read), and
# every behavioural claim is proved by running the step.
#
# Run locally:
#   bash tests/regression-test-required/dod_gate_state_test.sh
#
# Prove it discriminates (must FAIL against the pre-fix workflow):
#   git show <pre-fix-sha>:.github/workflows/definition-of-done.yml > /tmp/pre.yml
#   WORKFLOW_UNDER_TEST=/tmp/pre.yml \
#     bash tests/regression-test-required/dod_gate_state_test.sh
#
# Prove the awk behaves identically under mawk (the Ubuntu runner's awk):
#   docker run -i -v "$PWD:/w" -w /w ubuntu:24.04 \
#     bash -c 'apt-get update -qq && apt-get install -y -qq jq git >/dev/null &&
#              git config --global --add safe.directory /w &&
#              bash tests/regression-test-required/dod_gate_state_test.sh'

set -uo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
WORKFLOW="${WORKFLOW_UNDER_TEST:-${REPO_ROOT}/.github/workflows/definition-of-done.yml}"
TEMPLATE="${PR_TEMPLATE_UNDER_TEST:-${REPO_ROOT}/.github/pull_request_template.md}"

# Nothing here is ever deleted: the work dir is printed so a failure can be
# inspected after the fact.
WORK_ROOT="${TEST_WORK_DIR:-$(mktemp -d)}"
mkdir -p "$WORK_ROOT"

echo "workflow under test: $WORKFLOW"
echo "template under test: $TEMPLATE"
echo "awk implementation:  $(awk --version 2>&1 | head -n1 || true)"
echo "work dir:            $WORK_ROOT"
echo

ASSERTIONS_RUN=0
FAILURES=0
# Every section below contributes assertions. A run that comes out under this
# floor bailed early and is not entitled to report success — a green run that
# asserted nothing is the same defect class this file exists to prevent.
EXPECTED_ASSERTIONS_MIN=54

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

assert_eq() {
    ASSERTIONS_RUN=$((ASSERTIONS_RUN + 1))
    if [ "$1" = "$2" ]; then
        echo "  ok: $3 (= $2)"
    else
        fail "$3 — expected '$2', got '$1'"
    fi
}

if [ ! -f "$WORKFLOW" ]; then
    echo "FAIL: workflow not found at $WORKFLOW"
    exit 1
fi
if [ ! -f "$TEMPLATE" ]; then
    echo "FAIL: PR template not found at $TEMPLATE"
    exit 1
fi

for tool in python3 jq awk sed; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        # Deliberately a hard failure, not a skip. A dependency this test needs
        # in order to assert anything must never turn into a silent pass.
        echo "FAIL: '$tool' is required by this test and is not on PATH."
        exit 1
    fi
done
if ! python3 -c 'import yaml' >/dev/null 2>&1; then
    echo "FAIL: python3 PyYAML is required by this test (pip install pyyaml)."
    exit 1
fi

# ---------------------------------------------------------------------------
# Step extraction. Everything downstream runs the workflow's REAL shell.
# ---------------------------------------------------------------------------
extract_step() {
    # $1 = job id, $2 = step id (or __name__:<name prefix>), $3 = outfile
    python3 - "$WORKFLOW" "$1" "$2" "$3" <<'PY'
import sys, yaml
wf, job, sid, out = sys.argv[1:5]
d = yaml.safe_load(open(wf))
steps = d["jobs"][job]["steps"]
if sid.startswith("__name__:"):
    want = sid.split(":", 1)[1]
    match = [s for s in steps if (s.get("name") or "").startswith(want)]
else:
    match = [s for s in steps if s.get("id") == sid]
if len(match) != 1:
    sys.stderr.write("expected exactly one step %r, found %d\n" % (sid, len(match)))
    sys.exit(1)
open(out, "w").write("#!/usr/bin/env bash\n" + match[0]["run"])
PY
}

# ---------------------------------------------------------------------------
# Part 1 — file-level properties. These ARE properties of the file.
# ---------------------------------------------------------------------------
echo "── Part 1: triggers, paths filter, payload independence ──"

TRIGGER_TYPES="$(python3 - "$WORKFLOW" <<'PY'
import sys, yaml
d = yaml.safe_load(open(sys.argv[1]))
on = d.get(True, d.get("on", {}))
print(" ".join((on.get("pull_request") or {}).get("types", [])))
PY
)"
echo "  pull_request types: ${TRIGGER_TYPES:-(none)}"

for t in opened reopened synchronize edited; do
    case " $TRIGGER_TYPES " in
        *" $t "*) assert_true 0 "'$t' is a pull_request trigger";;
        *)        assert_true 1 "'$t' is a pull_request trigger";;
    esac
done

# "The job must run on the PR that changes it." A `paths:` filter here would
# let a change to the gate itself dodge the gate — the #3089 failure mode.
HAS_PATHS="$(python3 - "$WORKFLOW" <<'PY'
import sys, yaml
d = yaml.safe_load(open(sys.argv[1]))
on = d.get(True, d.get("on", {}))
pr = on.get("pull_request") or {}
print("yes" if ("paths" in pr or "paths-ignore" in pr) else "no")
PY
)"
assert_eq "$HAS_PATHS" "no" "no paths/paths-ignore filter — the gate runs on the PR that edits the gate"

HAS_MERGE_GROUP="$(python3 - "$WORKFLOW" <<'PY'
import sys, yaml
d = yaml.safe_load(open(sys.argv[1]))
on = d.get(True, d.get("on", {}))
print("yes" if "merge_group" in on else "no")
PY
)"
# This job IS required, so without a merge_group check-run every queue entry
# sits in AWAITING_CHECKS until the ruleset's 60-minute timeout ejects it.
assert_eq "$HAS_MERGE_GROUP" "yes" "workflow emits a check-run on merge_group (it is a required check)"

PERMS="$(python3 - "$WORKFLOW" <<'PY'
import sys, yaml
d = yaml.safe_load(open(sys.argv[1]))
p = d.get("permissions") or {}
print(p.get("pull-requests", "MISSING"))
PY
)"
assert_eq "$PERMS" "read" "workflow grants pull-requests: read (required for the live API read)"

# Comment lines are stripped first: the workflow documents the bypass it
# closed, and that prose necessarily NAMES the expressions it no longer uses —
# an assertion that could not tell the two apart would force the fix to ship
# undocumented.
#
# WHOLE-LINE comments only. A trailing `s/#.*$//` looks equivalent and is not:
# it also eats the `'## Skip-runtime-e2e justification'` out of the pre-fix
# `grep -q` line, so the assertion that the bare grep is gone would pass
# against the very workflow that still has it. Found by running this test
# against the pre-fix file.
NONCOMMENT="${WORK_ROOT}/workflow.noncomment"
sed -e 's/^[[:space:]]*#.*$//' "$WORKFLOW" > "$NONCOMMENT"

grep -qE 'github\.event\.pull_request\.title' "$NONCOMMENT"
assert_true $(( $? == 0 ? 1 : 0 )) "workflow never reads the title from the event payload (state-at-trigger)"

grep -qE 'github\.event\.pull_request\.body' "$NONCOMMENT"
assert_true $(( $? == 0 ? 1 : 0 )) "workflow never reads the body from the event payload (state-at-trigger)"

grep -qE 'gh api "repos/\$\{REPO\}/pulls/\$\{PR_NUMBER\}"' "$WORKFLOW"
assert_true $? "workflow reads current PR state from the REST API at evaluation time"

grep -qE 'if ! gh api .*; then' "$WORKFLOW"
assert_true $? "the API read is guarded and fails the job when it cannot complete"

# The bare presence grep is defect #2 itself; it must be gone from the shell.
grep -qE "grep -q '## Skip-runtime-e2e justification'" "$NONCOMMENT"
assert_true $(( $? == 0 ? 1 : 0 )) "the bare presence-only grep for the justification heading is gone"

# The gate reads no labels, which is why `labeled`/`unlabeled` are absent from
# `types`. If that ever stops being true the trigger list has to grow with it.
grep -qE 'github\.event\.pull_request\.labels' "$NONCOMMENT"
assert_true $(( $? == 0 ? 1 : 0 )) "gate reads no labels, so the absent labeled/unlabeled triggers are justified"

# ---------------------------------------------------------------------------
# Part 2 — the live-state step, executed against a stubbed `gh`.
#
# Eight failure modes, every one of them fail-closed. This is the half that
# makes a missed trigger event harmless: even a stale run re-reads the PR.
# ---------------------------------------------------------------------------
echo
echo "── Part 2: the extracted 'state' step, eight API failure modes ──"

STATE_SH="${WORK_ROOT}/state.sh"
extract_step runtime-e2e-required state "$STATE_SH"
STATE_OK=$?
assert_true $STATE_OK "the live-state step (id: state) can be extracted from the workflow"
# NOTE: a missing step is recorded as a failure and the run CONTINUES. Bailing
# here would mean that against a workflow with no live read — i.e. the pre-fix
# file — this test reported only "cannot extract" and never showed the
# empty-heading waiver still working. The discrimination evidence is the point.

# A stub `gh` whose behaviour is driven by $GH_STUB_MODE.
STUB_BIN="${WORK_ROOT}/stubbin"
mkdir -p "$STUB_BIN"
cat > "${STUB_BIN}/gh" <<'STUB'
#!/usr/bin/env bash
case "${GH_STUB_MODE:-ok}" in
  ok)          # An empty PR number means the caller asked for `.../pulls/`, which
               # is the LIST endpoint — the real API answers that with an array,
               # not a 404. Modelling it faithfully keeps the empty-PR-number
               # scenario honest instead of stub-flattered.
               if [[ "${1:-}" == */pulls/ ]]; then
                 echo '[{"number": 7}, {"number": 8}]'
               else
                 printf '{"number": %s, "title": "%s", "body": %s, "labels": []}\n' \
                   "${GH_STUB_NUMBER:-7}" "${GH_STUB_TITLE:-t}" "${GH_STUB_BODY_JSON:-\"\"}"
               fi ;;
  nonzero)     echo "gh: HTTP 502" >&2; exit 1 ;;
  empty)       : ;;
  emptyobject) echo '{}' ;;
  notfound)    echo '{"message": "Not Found", "documentation_url": "https://docs.github.com"}' ;;
  array)       echo '[{"number": 7}]' ;;
  notjson)     echo '<html><body>502 Bad Gateway</body></html>' ;;
  otherpr)     echo '{"number": 999, "title": "someone elses PR", "body": ""}' ;;
  *)           echo "unknown stub mode ${GH_STUB_MODE}" >&2; exit 3 ;;
esac
STUB
chmod +x "${STUB_BIN}/gh"

# $1 scenario name; env GH_STUB_MODE / PR_NUMBER / PATH_MODE control the case.
run_state() {
    local name="$1"; shift
    local dir="${WORK_ROOT}/state_${name}"
    mkdir -p "${dir}/runner_temp"
    : > "${dir}/github_output"
    local path="$STUB_BIN:$PATH"
    if [ "${PATH_MODE:-stub}" = "nogh" ]; then
        # The verified sandbox: every tool the step needs, and no `gh`.
        path="$NOGH_BIN"
    fi
    (
        cd "$REPO_ROOT" || exit 99
        PATH="$path" \
        RUNNER_TEMP="${dir}/runner_temp" \
        GITHUB_OUTPUT="${dir}/github_output" \
        REPO="getaxonflow/axonflow-enterprise" \
        bash "$STATE_SH"
    ) >"${dir}/stdout.log" 2>&1
    # NOTE: the exit code is taken from the direct invocation, never from a
    # `$(...)` capture — command substitution runs in a subshell and would
    # discard it, making every exit-code assertion pass unconditionally.
    return $?
}

state_output() {
    grep -E "^$2=" "${WORK_ROOT}/state_$1/github_output" | tail -n1 | cut -d= -f2-
}

# $1 exit code, $2 scenario, $3 label, $4 substring the diagnostic must contain.
#
# The exit-code half alone is not discriminating: these guards are layered, and
# removing any single one leaves the step failing anyway via the next one down
# (or via `set -e`). Asserting that the diagnostic NAMES the cause the guard
# observed is what makes each guard individually load-bearing — and it is the
# same rule the rest of this repo applies to error messages: a diagnostic must
# name only causes it can actually observe.
assert_fails_with() {
    local rc="$1" scenario="$2" label="$3" needle="$4"
    assert_true $(( rc != 0 ? 0 : 1 )) "$label"
    grep -qF "$needle" "${WORK_ROOT}/state_${scenario}/stdout.log"
    assert_true $? "…and says why: \"${needle}\""
}

# A sandbox PATH that has everything the step needs and genuinely no `gh`, so
# mode 1 is a real "binary absent" rather than a stub pretending.
#
# The obvious construction — drop every PATH entry that contains a `gh` — is
# WRONG, and CI proved it. On a GitHub runner `gh` lives in /usr/bin, so
# dropping that directory also drops `bash` and `jq`: the step then died with
# "bash: command not found" and the exit-code assertion passed while the
# diagnostic assertion (correctly) did not. A negative-capability test has to
# remove exactly the one capability it names.
#
# So: a directory of symlinks to the real tools, with `gh` simply not among
# them, and PATH set to that directory alone.
NOGH_BIN="${WORK_ROOT}/nogh"
mkdir -p "$NOGH_BIN"
for t in bash sh jq env cat echo printf mktemp dirname basename sed awk grep \
         head tail cut tr sort uniq wc rm mkdir touch chmod ln date; do
    src="$(command -v "$t" 2>/dev/null || true)"
    if [ -n "$src" ] && [ ! -e "${NOGH_BIN}/${t}" ]; then
        ln -s "$src" "${NOGH_BIN}/${t}"
    fi
done

# The sandbox has to be verified, not assumed — the whole point of this block
# is that an unverified PATH is what made the assertion pass for the wrong
# reason in the first place.
if PATH="$NOGH_BIN" command -v gh >/dev/null 2>&1; then
    echo "FAIL: the no-gh sandbox still resolves 'gh'; mode 1 would be vacuous."
    exit 1
fi
for t in bash jq; do
    if ! PATH="$NOGH_BIN" command -v "$t" >/dev/null 2>&1; then
        echo "FAIL: the no-gh sandbox is missing '$t'; mode 1 would fail for the wrong reason."
        exit 1
    fi
done

if [ $STATE_OK -eq 0 ]; then
    # --- mode 1: `gh` binary absent
    PATH_MODE=nogh PR_NUMBER=7 run_state nogh
    rc=$?
    assert_fails_with $rc nogh "FAIL-CLOSED 1/8: gh binary absent → job fails" "The GitHub CLI (gh) is not available"

    # --- mode 2: empty PR number
    GH_STUB_MODE=ok PR_NUMBER="" run_state noprnum
    rc=$?
    assert_fails_with $rc noprnum "FAIL-CLOSED 2/8: empty PR number → job fails" "No PR number available"

    # --- mode 3: gh api exits non-zero
    GH_STUB_MODE=nonzero PR_NUMBER=7 run_state nonzero
    rc=$?
    assert_fails_with $rc nonzero "FAIL-CLOSED 3/8: gh api non-zero exit → job fails" "Could not read the current state"

    # --- mode 4: empty body, exit 0
    GH_STUB_MODE=empty PR_NUMBER=7 run_state empty
    rc=$?
    assert_fails_with $rc empty "FAIL-CLOSED 4/8: empty response with exit 0 → job fails" "returned an empty response"

    # --- mode 5: not valid JSON at all (HTML error page / truncated read)
    GH_STUB_MODE=notjson PR_NUMBER=7 run_state notjson
    rc=$?
    assert_fails_with $rc notjson "FAIL-CLOSED 5/8: non-JSON response → job fails" "is not a JSON object"

    # --- mode 6: a JSON array
    GH_STUB_MODE=array PR_NUMBER=7 run_state array
    rc=$?
    assert_fails_with $rc array "FAIL-CLOSED 6/8: JSON array response → job fails" "is not a JSON object"

    # --- mode 7a: {}
    GH_STUB_MODE=emptyobject PR_NUMBER=7 run_state emptyobject
    rc=$?
    assert_fails_with $rc emptyobject "FAIL-CLOSED 7/8a: '{}' response → job fails" "is not a pull request object"

    # --- mode 7b: {"message": "Not Found"}
    GH_STUB_MODE=notfound PR_NUMBER=7 run_state notfound
    rc=$?
    assert_fails_with $rc notfound "FAIL-CLOSED 7/8b: 'Not Found' response → job fails" "is not a pull request object"

    # --- mode 8: a well-formed PR object, but for a DIFFERENT PR
    GH_STUB_MODE=otherpr PR_NUMBER=7 run_state otherpr
    rc=$?
    assert_fails_with $rc otherpr "FAIL-CLOSED 8/8: object for another PR number → job fails" "Refusing to gate on another PR"

    # --- and the happy path still works, or every assertion above is vacuous.
    GH_STUB_MODE=ok PR_NUMBER=7 GH_STUB_TITLE="fix: something" run_state ok
    assert_true $? "happy path: a real PR object is read and the step succeeds"
    OK_JSON="$(state_output ok pr_json)"
    if [ -n "$OK_JSON" ] && [ -s "$OK_JSON" ]; then ok_rc=0; else ok_rc=1; fi
    assert_true "$ok_rc" \
        "happy path writes a non-empty pr_json output the next step can consume"
else
    echo "  (state step absent — its eight fail-closed scenarios cannot run)"
fi

# ---------------------------------------------------------------------------
# Part 3 — the extracted escape-hatch classifier.
#
# THE HEADLINE: an empty heading no longer waives a required check.
# ---------------------------------------------------------------------------
echo
echo "── Part 3: the extracted 'hatch' step, run against synthetic PR state ──"

HATCH_SH="${WORK_ROOT}/hatch.sh"
extract_step runtime-e2e-required hatch "$HATCH_SH"
HATCH_OK=$?
assert_true $HATCH_OK "the escape-hatch step (id: hatch) can be extracted from the workflow"
if [ $HATCH_OK -ne 0 ]; then
    echo "FAIL: cannot extract the hatch step; the behavioural assertions below cannot run."
    echo "Work dir kept at $WORK_ROOT"
    exit 1
fi

make_pr_json() {
    # $1 outfile  $2 title  $3 body
    jq -n --arg t "$2" --arg b "$3" '{number: 7, title: $t, body: $b}' > "$1"
}

run_hatch() {
    # $1 pr.json path (may be empty/nonexistent on purpose)  $2 scenario name
    local pr_json="$1" name="$2"
    local dir="${WORK_ROOT}/hatch_${name}"
    mkdir -p "${dir}/runner_temp"
    : > "${dir}/github_output"

    # The harness supplies BOTH input shapes for the same scenario: the
    # post-fix step's PR_JSON, and the pre-fix step's PR_TITLE / PR_BODY,
    # derived from that same JSON so they describe an identical PR.
    #
    # This is load-bearing, not belt-and-braces. Feeding only PR_JSON means
    # the pre-fix step hits `$PR_TITLE` under `set -u`, dies with "unbound
    # variable", and EVERY "step FAILS" assertion below passes against the
    # workflow that still has the bug — for the wrong reason. The
    # empty-heading before/after is the headline of #3144; it has to
    # discriminate on behaviour, not on an unset variable.
    local t="" b=""
    if [ -s "$pr_json" ]; then
        t="$(jq -r '.title // ""' "$pr_json" 2>/dev/null || echo "")"
        b="$(jq -r '.body // ""' "$pr_json" 2>/dev/null || echo "")"
    fi

    (
        cd "$REPO_ROOT" || exit 99
        PR_JSON="$pr_json" \
        PR_TITLE="$t" \
        PR_BODY="$b" \
        RUNNER_TEMP="${dir}/runner_temp" \
        GITHUB_OUTPUT="${dir}/github_output" \
        bash "$HATCH_SH"
    ) >"${dir}/stdout.log" 2>&1
    return $?
}

hatch_output() {
    grep -E "^$2=" "${WORK_ROOT}/hatch_$1/github_output" | tail -n1 | cut -d= -f2-
}

MARKER='fix(ci): tidy [skip-runtime-e2e]'

# --- no marker in the title: the hatch simply does not engage.
make_pr_json "${WORK_ROOT}/h_nomarker.json" "fix(ci): tidy" "no justification anywhere"
run_hatch "${WORK_ROOT}/h_nomarker.json" nomarker
assert_true $? "no [skip-runtime-e2e] marker → step succeeds"
assert_eq "$(hatch_output nomarker skip)" "false" "no marker → skip=false (gate still applies)"

# --- THE DEFECT: marker + heading with nothing under it.
make_pr_json "${WORK_ROOT}/h_empty.json" "$MARKER" \
$'Intro.\n\n## Skip-runtime-e2e justification\n'
run_hatch "${WORK_ROOT}/h_empty.json" empty
assert_true $(( $? != 0 ? 0 : 1 )) "EMPTY HEADING alone no longer waives the gate — step FAILS (#3144)"
assert_eq "$(hatch_output empty skip)" "" "…and emits no skip=true output"

# --- heading followed only by the template's placeholder comment.
make_pr_json "${WORK_ROOT}/h_comment.json" "$MARKER" \
$'## Skip-runtime-e2e justification\n\n<!-- replace this with the reason -->\n\n## Next\n'
run_hatch "${WORK_ROOT}/h_comment.json" comment
assert_true $(( $? != 0 ? 0 : 1 )) "heading + HTML comment only → step FAILS"

# --- heading followed only by a MULTI-LINE HTML comment. Different awk path
#     from the single-line case, and the shape the real template ships.
make_pr_json "${WORK_ROOT}/h_mlcomment.json" "$MARKER" \
$'## Skip-runtime-e2e justification\n\n<!-- line one\n     line two\n     line three -->\n\n## Next\n'
run_hatch "${WORK_ROOT}/h_mlcomment.json" mlcomment
assert_true $(( $? != 0 ? 0 : 1 )) "heading + MULTI-LINE HTML comment only → step FAILS (mawk path)"

# --- heading followed only by a horizontal rule.
make_pr_json "${WORK_ROOT}/h_rule.json" "$MARKER" \
$'## Skip-runtime-e2e justification\n\n---\n\nprose that belongs to the next block\n'
run_hatch "${WORK_ROOT}/h_rule.json" rule
assert_true $(( $? != 0 ? 0 : 1 )) "heading + horizontal rule only → step FAILS (rule does not borrow the next block)"

# --- heading immediately followed by the next heading.
make_pr_json "${WORK_ROOT}/h_nextheading.json" "$MARKER" \
$'## Skip-runtime-e2e justification\n\n## Something else\n\ntext under the wrong heading\n'
run_hatch "${WORK_ROOT}/h_nextheading.json" nextheading
assert_true $(( $? != 0 ? 0 : 1 )) "empty heading does NOT borrow content from the next section"

# --- a null body (the API returns JSON null, not "").
jq -n --arg t "$MARKER" '{number: 7, title: $t, body: null}' > "${WORK_ROOT}/h_null.json"
run_hatch "${WORK_ROOT}/h_null.json" null
assert_true $(( $? != 0 ? 0 : 1 )) "null PR body with the marker → step FAILS (never a silent pass)"

# --- fail closed on an absent / empty state file.
run_hatch "${WORK_ROOT}/does-not-exist.json" missingstate
assert_true $(( $? != 0 ? 0 : 1 )) "absent PR-state file → step FAILS closed"
: > "${WORK_ROOT}/h_emptyfile.json"
run_hatch "${WORK_ROOT}/h_emptyfile.json" emptystate
assert_true $(( $? != 0 ? 0 : 1 )) "empty PR-state file → step FAILS closed"

# --- a legitimately justified skip STILL PASSES. Without this every
#     assertion above could be satisfied by a gate that fails unconditionally.
make_pr_json "${WORK_ROOT}/h_good.json" "$MARKER" \
$'Intro paragraph.\n\n## Skip-runtime-e2e justification\n\nBuild-only change to the Dockerfile base image; no shipped runtime surface.\nExemption approved by the operator.\n\n## Next section\n'
run_hatch "${WORK_ROOT}/h_good.json" good
assert_true $? "a real justification still succeeds (the fix is not over-tightened)"
assert_eq "$(hatch_output good skip)" "true" "…and sets skip=true so the gate is waived"
grep -q 'Build-only change' "${WORK_ROOT}/hatch_good/runner_temp/dod-justification.txt"
assert_true $? "…and the stated rationale is echoed into the run log for reviewers"

# --- prose plus a placeholder comment still counts (comment stripped, prose kept).
make_pr_json "${WORK_ROOT}/h_mixed.json" "$MARKER" \
$'## Skip-runtime-e2e justification\n\n<!-- template hint -->\nLint-baseline bump only. Approved by the operator.\n\n## Next\n'
run_hatch "${WORK_ROOT}/h_mixed.json" mixed
assert_eq "$(hatch_output mixed skip)" "true" "prose alongside a placeholder comment still counts"

# --- CRLF bodies (GitHub serves them for web-edited descriptions).
make_pr_json "${WORK_ROOT}/h_crlf.json" "$MARKER" \
$'## Skip-runtime-e2e justification\r\n\r\nGenerated artifact regen only; approved by the operator.\r\n'
run_hatch "${WORK_ROOT}/h_crlf.json" crlf
assert_eq "$(hatch_output crlf skip)" "true" "CRLF line endings in the PR body are handled"

# --- a deeper heading level is accepted (the template uses '##', a checklist
#     section might reasonably use '###').
make_pr_json "${WORK_ROOT}/h_h3.json" "$MARKER" \
$'### Skip-runtime-e2e justification\n\nCI plumbing only; approved by the operator.\n'
run_hatch "${WORK_ROOT}/h_h3.json" h3
assert_eq "$(hatch_output h3 skip)" "true" "a '###' heading is accepted"

# --- THE ^#+ vs ^##+ DIVERGENCE, pinned explicitly.
#     A grep of `^#+` over the template would accept a heading demoted to a
#     single '#'; the classifier's awk is `^##+` and rejects it. The two are
#     independent transcriptions of one rule and they genuinely diverge, which
#     is why Part 4 below feeds the REAL template through the REAL classifier
#     instead of grepping it.
make_pr_json "${WORK_ROOT}/h_h1.json" "$MARKER" \
$'# Skip-runtime-e2e justification\n\nCI plumbing only; approved by the operator.\n'
run_hatch "${WORK_ROOT}/h_h1.json" h1
assert_true $(( $? != 0 ? 0 : 1 )) "a single-'#' heading is NOT accepted by the classifier (the ^#+ vs ^##+ divergence)"
printf '# Skip-runtime-e2e justification\n' > "${WORK_ROOT}/h1_probe.md"
grep -qE '^#+[[:space:]]*Skip-runtime-e2e justification[[:space:]]*$' "${WORK_ROOT}/h1_probe.md"
assert_true $? "…while a '^#+' grep DOES accept it — the divergence is real, not hypothetical"

# ---------------------------------------------------------------------------
# Part 4 — the real PR template, through the real classifier, both directions.
#
# A template that tells authors to write one thing while the parser looks for
# another is the same defect one layer out: the documented path becomes the
# broken path. So the REAL template is fed through the REAL classifier rather
# than compared by eye — which is also the only thing that closes the
# `^#+` / `^##+` gap pinned just above.
#
# Two directions, and both matter:
#
#   (i)  as shipped — heading present, only the placeholder comment (and the
#        horizontal rule) under it — must NOT count. An unfilled template is
#        not a rationale, and a parser lenient enough to accept it would let
#        the title marker waive a REQUIRED check with nobody having typed a
#        word. That is the failure #3144 is about, so this direction is
#        asserted deliberately rather than treated as an inconvenience.
#
#   (ii) with the placeholder replaced by real text — must count. This is what
#        proves the heading STRING and LEVEL in the template are ones the
#        parser accepts; (i) alone would also pass if the heading were
#        misspelled or demoted to '#'.
# ---------------------------------------------------------------------------
echo
echo "── Part 4: the PR template's own text, through the real classifier ──"

grep -qE '^#+[[:space:]]*Skip-runtime-e2e justification[[:space:]]*$' "$TEMPLATE"
assert_true $? "PR template carries a 'Skip-runtime-e2e justification' heading"

# (i) as shipped
python3 - "$TEMPLATE" "${WORK_ROOT}/tmpl_asis.json" "$MARKER" <<'PY'
import sys, json
body = open(sys.argv[1]).read()
json.dump({"number": 7, "title": sys.argv[3], "body": body}, open(sys.argv[2], "w"))
PY
run_hatch "${WORK_ROOT}/tmpl_asis.json" tmpl_asis
assert_true $(( $? != 0 ? 0 : 1 )) \
    "template AS SHIPPED (placeholder comment only) does NOT satisfy the escape hatch"
assert_eq "$(hatch_output tmpl_asis skip)" "" "…and emits no skip=true output"

# (ii) as an author would submit it — placeholder replaced with a real reason.
python3 - "$TEMPLATE" "${WORK_ROOT}/tmpl_filled.json" "$MARKER" <<'PY'
import sys, json, re
body = open(sys.argv[1]).read()
# Replace everything between the heading and the end of its section with
# prose, exactly as an author filling the template in would. The section ends
# at the next heading OR at a horizontal rule, matching the classifier.
pat = re.compile(
    r"(^#+[ \t]*Skip-runtime-e2e justification[ \t]*\n)"
    r"(.*?)"
    r"(?=^#+[ \t]|^[ \t]*(?:-{3,}|\*{3,}|_{3,})[ \t]*$|\Z)",
    re.MULTILINE | re.DOTALL)
new, n = pat.subn(
    r"\1\nBuild-only change to the Dockerfile base image; no shipped runtime\n"
    r"surface. Exemption approved by the operator.\n\n", body)
if n != 1:
    sys.stderr.write("expected exactly one escape-hatch section, found %d\n" % n)
    sys.exit(1)
if "<!--" in pat.search(new).group(2):
    sys.stderr.write("placeholder comment survived the substitution\n")
    sys.exit(1)
json.dump({"number": 7, "title": sys.argv[3], "body": new}, open(sys.argv[2], "w"))
PY
assert_true $? "the template's escape-hatch section can be located and filled in programmatically"
run_hatch "${WORK_ROOT}/tmpl_filled.json" tmpl_filled
assert_true $? "template FILLED IN as an author would submit it is parsed without error"
assert_eq "$(hatch_output tmpl_filled skip)" "true" \
    "template FILLED IN DOES satisfy the escape hatch (heading string AND level are ones the parser accepts)"

# ---------------------------------------------------------------------------
# Part 5 — the enforcement step actually fails the job.
#
# "A failing check must fail the job, not warn or skip." Proved by executing
# the step, not by reading it.
# ---------------------------------------------------------------------------
echo
echo "── Part 5: the enforcement step exits non-zero ──"

ENFORCE_SH="${WORK_ROOT}/enforce.sh"
extract_step runtime-e2e-required "__name__:Enforce runtime-e2e/ presence" "$ENFORCE_SH"
extract_rc=$?
assert_true $extract_rc "the enforcement step can be extracted from the workflow"
if [ $extract_rc -eq 0 ]; then
    ( cd "$REPO_ROOT" && bash "$ENFORCE_SH" ) >"${WORK_ROOT}/enforce.log" 2>&1
    enforce_rc=$?
    assert_true $(( enforce_rc != 0 ? 0 : 1 )) "the enforcement step FAILS the job (exit $enforce_rc), it does not warn"
    grep -q '::error::' "${WORK_ROOT}/enforce.log"
    assert_true $? "…and emits a ::error:: annotation"
fi

# The enforce step must still be reachable: its `if` may not be short-circuited
# by anything other than the three documented outs.
ENFORCE_IF="$(python3 - "$WORKFLOW" <<'PY'
import sys, yaml
d = yaml.safe_load(open(sys.argv[1]))
steps = d["jobs"]["runtime-e2e-required"]["steps"]
s = [x for x in steps if (x.get("name") or "").startswith("Enforce runtime-e2e/ presence")][0]
print(s.get("if", ""))
PY
)"
case "$ENFORCE_IF" in
    *"steps.hatch.outputs.skip != 'true'"*)
        assert_true 0 "enforcement is skipped only when the hatch explicitly set skip=true";;
    *)  assert_true 1 "enforcement is skipped only when the hatch explicitly set skip=true";;
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
echo "✅ definition-of-done gate reads CURRENT PR state and an empty heading cannot waive it."
