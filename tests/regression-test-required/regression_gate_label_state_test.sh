#!/usr/bin/env bash
# Regression test for the label-state bypass in
# .github/workflows/regression-test-required.yml (issue #3120).
#
# THE BUG
# -------
# The gate classified from `github.event.pull_request.labels.*.name` — the
# labels as captured WHEN THE TRIGGERING EVENT FIRED — and listed only
# [opened, synchronize, labeled] in `types`. Observed on PR #3119:
#
#     06:57:06Z  labeled    regression-test-exempt
#     06:57:16Z  unlabeled  regression-test-exempt
#     06:57:28Z  the run reported "Skip — exempt label applied" → green
#
# The head SHA never changed and `unlabeled` was not a trigger, so nothing
# re-evaluated. A required check read green with no exemption label, no
# regression test, and no trace of either in the PR's current state.
#
# WHY THIS TEST IS SHAPED THIS WAY
# --------------------------------
# The load-bearing assertions EXECUTE the workflow's real classifier step —
# extracted verbatim out of the YAML — against synthetic PR JSON. Asserting on
# the YAML text alone would test the renderer, not the path: a grep for
# "unlabeled" passes whether or not the classifier actually derives its answer
# from current state. So the text assertions here cover only what genuinely is
# a property of the file (trigger list, permissions, absence of the payload
# read), and every behavioural claim is proved by running the step.
#
# The extracted step is driven with a stubbed $RUNNER_TEMP and $GITHUB_OUTPUT
# so it behaves exactly as it does on a runner, including the awk that mines
# the exemption justification out of the PR body.
#
# Run locally:
#   bash tests/regression-test-required/regression_gate_label_state_test.sh
#
# Prove it discriminates (must FAIL against the pre-fix workflow):
#   git show <pre-fix-sha>:.github/workflows/regression-test-required.yml \
#     > /tmp/pre.yml
#   WORKFLOW_UNDER_TEST=/tmp/pre.yml \
#     bash tests/regression-test-required/regression_gate_label_state_test.sh

set -uo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
WORKFLOW="${WORKFLOW_UNDER_TEST:-${REPO_ROOT}/.github/workflows/regression-test-required.yml}"

# Nothing here is ever deleted: the work dir is printed so a failure can be
# inspected after the fact.
WORK_ROOT="${TEST_WORK_DIR:-$(mktemp -d)}"
mkdir -p "$WORK_ROOT"

echo "workflow under test: $WORKFLOW"
echo "work dir:           $WORK_ROOT"
echo

ASSERTIONS_RUN=0
FAILURES=0
# Every section below contributes assertions. A run that comes out under this
# floor bailed early and is not entitled to report success — a green run that
# asserted nothing is the same defect class this file exists to prevent.
EXPECTED_ASSERTIONS_MIN=32

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

for tool in python3 jq awk; do
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
# Part 1 — file-level properties. These ARE properties of the file, so text
# assertions are the right tool for them.
# ---------------------------------------------------------------------------
echo "── Part 1: trigger set and payload independence ──"

TRIGGER_TYPES="$(python3 - "$WORKFLOW" <<'PY'
import sys, yaml
d = yaml.safe_load(open(sys.argv[1]))
on = d.get(True, d.get("on", {}))
print(" ".join(on.get("pull_request", {}).get("types", [])))
PY
)"
echo "  pull_request types: ${TRIGGER_TYPES:-(none)}"

case " $TRIGGER_TYPES " in
    *" unlabeled "*) assert_true 0 "'unlabeled' is a trigger (the #3120 half that was missing)";;
    *)               assert_true 1 "'unlabeled' is a trigger (the #3120 half that was missing)";;
esac
case " $TRIGGER_TYPES " in
    *" labeled "*) assert_true 0 "'labeled' is still a trigger";;
    *)             assert_true 1 "'labeled' is still a trigger";;
esac
case " $TRIGGER_TYPES " in
    *" edited "*) assert_true 0 "'edited' is a trigger (title reclassifies, body carries the exemption rationale)";;
    *)            assert_true 1 "'edited' is a trigger (title reclassifies, body carries the exemption rationale)";;
esac
case " $TRIGGER_TYPES " in
    *" synchronize "*) assert_true 0 "'synchronize' is still a trigger";;
    *)                 assert_true 1 "'synchronize' is still a trigger";;
esac

HAS_MERGE_GROUP="$(python3 - "$WORKFLOW" <<'PY'
import sys, yaml
d = yaml.safe_load(open(sys.argv[1]))
on = d.get(True, d.get("on", {}))
print("yes" if "merge_group" in on else "no")
PY
)"
# Without this, making the check required (#3124) parks every merge-queue entry
# in AWAITING_CHECKS until the ruleset's 60-minute timeout ejects it.
assert_eq "$HAS_MERGE_GROUP" "yes" "workflow emits a check-run on merge_group so it CAN be made required"

# The durable half of the #3120 fix: classification must not be derived from
# the event payload's snapshot at all.
#
# Comment lines are stripped first. The workflow documents the bypass it
# closed, and that prose necessarily NAMES the expression it no longer uses —
# an assertion that could not tell the two apart would force the fix to be
# shipped undocumented.
NONCOMMENT="${WORK_ROOT}/workflow.noncomment"
sed -e 's/[[:space:]]*#.*$//' "$WORKFLOW" > "$NONCOMMENT"

grep -qF 'github.event.pull_request.labels' "$NONCOMMENT"
assert_true $(( $? == 0 ? 1 : 0 )) "workflow never reads github.event.pull_request.labels (state-at-trigger)"

grep -qE 'github\.event\.pull_request\.title' "$NONCOMMENT"
assert_true $(( $? == 0 ? 1 : 0 )) "workflow never takes the title from the event payload either"

grep -qE 'github\.event\.pull_request\.body' "$NONCOMMENT"
assert_true $(( $? == 0 ? 1 : 0 )) "workflow never takes the body from the event payload either"

grep -qE 'gh api "repos/\$\{REPO\}/pulls/\$\{PR_NUMBER\}"' "$WORKFLOW"
assert_true $? "workflow reads current PR state from the REST API at evaluation time"

PERMS="$(python3 - "$WORKFLOW" <<'PY'
import sys, yaml
d = yaml.safe_load(open(sys.argv[1]))
p = d.get("permissions") or {}
print(p.get("pull-requests", "MISSING"))
PY
)"
assert_eq "$PERMS" "read" "workflow grants pull-requests: read (required for the live API read)"

# Fail-closed on an API read that cannot complete.
grep -qE 'if ! gh api .*; then' "$WORKFLOW"
assert_true $? "the API read is guarded and fails the job when it cannot complete"

# ---------------------------------------------------------------------------
# Part 2 — execute the real classifier step.
# ---------------------------------------------------------------------------
echo
echo "── Part 2: the extracted classifier, run against synthetic PR state ──"

CLASSIFY_SH="${WORK_ROOT}/classify.sh"
python3 - "$WORKFLOW" "$CLASSIFY_SH" <<'PY'
import sys, yaml
wf, out = sys.argv[1], sys.argv[2]
d = yaml.safe_load(open(wf))
steps = d["jobs"]["check-regression-test"]["steps"]
match = [s for s in steps if s.get("id") == "classify"]
if len(match) != 1:
    sys.stderr.write("expected exactly one step with id 'classify', found %d\n" % len(match))
    sys.exit(1)
open(out, "w").write("#!/usr/bin/env bash\n" + match[0]["run"])
PY
extract_rc=$?
assert_true $extract_rc "the classifier step (id: classify) can be extracted from the workflow"
if [ $extract_rc -ne 0 ]; then
    echo "cannot continue without the classifier step"
    exit 1
fi

# Drive the extracted step exactly as a runner does.
#   $1 pr.json   $2 scenario name
# Writes outputs to <scenario>/github_output; returns the step's exit code.
run_classify() {
    local pr_json="$1" name="$2"
    local dir="${WORK_ROOT}/${name}"
    mkdir -p "${dir}/runner_temp"
    : > "${dir}/github_output"
    (
        cd "$REPO_ROOT" || exit 99
        PR_JSON="$pr_json" \
        RUNNER_TEMP="${dir}/runner_temp" \
        GITHUB_OUTPUT="${dir}/github_output" \
        bash "$CLASSIFY_SH"
    ) >"${dir}/stdout.log" 2>&1
    # NOTE: the exit code is taken from the direct invocation, never from a
    # `$(...)` capture — command substitution runs in a subshell and would
    # discard it, making every exit-code assertion pass unconditionally.
    return $?
}

output_value() {
    # last-wins, matching GITHUB_OUTPUT semantics
    grep -E "^$2=" "${WORK_ROOT}/$1/github_output" | tail -n1 | cut -d= -f2-
}

make_pr_json() {
    # $1 outfile  $2 title  $3 body  $4.. labels
    local out="$1" title="$2" body="$3"
    shift 3
    local labels="[]"
    if [ "$#" -gt 0 ]; then
        labels="$(printf '%s\n' "$@" | jq -R . | jq -s 'map({name: .})')"
    fi
    jq -n --arg t "$title" --arg b "$body" --argjson l "$labels" \
        '{number: 1, title: $t, body: $b, labels: $l}' > "$out"
}

# --- Scenario A: the #3119 sequence. Exempt label REMOVED.
# The whole bypass was that this state still evaluated as "exempt". Reading
# current labels means an absent label is simply absent, whatever fired.
make_pr_json "${WORK_ROOT}/a.json" "fix(gate): something" "Body with no justification"
run_classify "${WORK_ROOT}/a.json" "a"
assert_true $? "classifier exits 0 for a fix: PR with no labels"
assert_eq "$(output_value a is_bug_fix)" "true"   "fix: title classifies as a bug fix"
assert_eq "$(output_value a has_exempt)" "false"  "label absent from CURRENT state ⇒ not exempt (this is #3120)"

# --- Scenario B: exempt label present, no justification section.
make_pr_json "${WORK_ROOT}/b.json" "fix: something" "No justification here." "regression-test-exempt"
run_classify "${WORK_ROOT}/b.json" "b"
assert_eq "$(output_value b has_exempt)" "true"        "exempt label present in current state is honoured"
assert_eq "$(output_value b has_justification)" "false" "no justification section ⇒ has_justification=false"

# --- Scenario C: exempt label plus a real justification.
make_pr_json "${WORK_ROOT}/c.json" "fix: something" \
$'Intro paragraph.\n\n## Regression-test-exempt justification\n\nCloudFormation-only change; no executable surface.\n\n## Next section\n' \
    "regression-test-exempt"
run_classify "${WORK_ROOT}/c.json" "c"
assert_eq "$(output_value c has_exempt)" "true"        "exempt label honoured"
assert_eq "$(output_value c has_justification)" "true" "justification section with content is recognised"

# --- Scenario D: heading present but the only content is an HTML comment.
# The PR template ships exactly this shape, so an empty heading must not count.
make_pr_json "${WORK_ROOT}/d.json" "fix: something" \
$'## Regression-test-exempt justification\n\n<!-- e.g. "infra-only change to CFN template" -->\n' \
    "regression-test-exempt"
run_classify "${WORK_ROOT}/d.json" "d"
assert_eq "$(output_value d has_justification)" "false" "heading followed only by an HTML comment does NOT count as a rationale"

# --- Scenario E: heading with nothing under it at all.
make_pr_json "${WORK_ROOT}/e.json" "fix: something" \
$'## Regression-test-exempt justification\n\n## Something else\n\ntext under the wrong heading\n' \
    "regression-test-exempt"
run_classify "${WORK_ROOT}/e.json" "e"
assert_eq "$(output_value e has_justification)" "false" "empty heading does NOT borrow content from the next section"

# --- Scenario F: `bug` label classifies, and exact matching (not substring).
make_pr_json "${WORK_ROOT}/f.json" "chore: tidy" "" "bug"
run_classify "${WORK_ROOT}/f.json" "f"
assert_eq "$(output_value f is_bug_fix)" "true" "'bug' label classifies a non-fix: title as a bug fix"

make_pr_json "${WORK_ROOT}/g.json" "chore: tidy" "" "not-a-bug" "debug"
run_classify "${WORK_ROOT}/g.json" "g"
assert_eq "$(output_value g is_bug_fix)" "false" "labels are matched exactly — 'not-a-bug'/'debug' do not classify"

# --- Scenario H: CRLF bodies (GitHub serves them for web-edited descriptions).
make_pr_json "${WORK_ROOT}/h.json" "fix: something" \
$'## Regression-test-exempt justification\r\n\r\nGenerated artifact regen only.\r\n' \
    "regression-test-exempt"
run_classify "${WORK_ROOT}/h.json" "h"
assert_eq "$(output_value h has_justification)" "true" "CRLF line endings in the PR body are handled"

# --- Scenario I: a null body (the API returns JSON null, not "").
jq -n '{number: 1, title: "fix: something", body: null, labels: [{name: "regression-test-exempt"}]}' \
    > "${WORK_ROOT}/i.json"
run_classify "${WORK_ROOT}/i.json" "i"
assert_true $? "classifier survives a null PR body"
assert_eq "$(output_value i has_justification)" "false" "null body ⇒ no justification"

# ---------------------------------------------------------------------------
# Part 3 — the PR template must document the heading the classifier accepts.
#
# A template that tells authors to write one thing while the parser looks for
# another is the same defect one layer out: the documented path becomes the
# broken path. So the REAL template is fed through the REAL classifier rather
# than compared by eye.
#
# Two directions, and both matter:
#
#   (i)  as shipped — heading present, only the placeholder comment under it —
#        must NOT count as a justification. An unfilled template is not a
#        rationale, and a parser lenient enough to accept it would let the
#        exempt label waive the gate with nobody having typed a word. That is
#        the failure this whole PR is about, so this direction is asserted
#        deliberately rather than treated as an inconvenience.
#
#   (ii) with the placeholder replaced by real text — must count. This is what
#        proves the heading STRING in the template is one the parser accepts;
#        (i) alone would also pass if the heading were misspelled.
# ---------------------------------------------------------------------------
echo
echo "── Part 3: the PR template's own text, through the real classifier ──"

TEMPLATE="${PR_TEMPLATE_UNDER_TEST:-${REPO_ROOT}/.github/pull_request_template.md}"
if [ ! -f "$TEMPLATE" ]; then
    echo "FAIL: PR template not found at $TEMPLATE"
    exit 1
fi

# The template's exemption heading, at whatever level it uses.
grep -qE '^#+[[:space:]]*Regression-test-exempt justification[[:space:]]*$' "$TEMPLATE"
assert_true $? "PR template carries a 'Regression-test-exempt justification' heading"

# (i) as shipped
python3 - "$TEMPLATE" "${WORK_ROOT}/tmpl_asis.json" <<'PY'
import sys, json
body = open(sys.argv[1]).read()
json.dump({"number": 1, "title": "fix: something", "body": body,
           "labels": [{"name": "regression-test-exempt"}]}, open(sys.argv[2], "w"))
PY
run_classify "${WORK_ROOT}/tmpl_asis.json" "tmpl_asis"
assert_true $? "classifier parses the real PR template without error"
assert_eq "$(output_value tmpl_asis has_justification)" "false" \
    "template AS SHIPPED (placeholder comment only) does NOT satisfy the exemption"

# (ii) as an author would submit it — placeholder replaced with a real reason.
python3 - "$TEMPLATE" "${WORK_ROOT}/tmpl_filled.json" <<'PY'
import sys, json, re
body = open(sys.argv[1]).read()
# Replace the comment block that follows the exemption heading with prose,
# exactly as an author filling the template in would.
pat = re.compile(
    r"(^#+[ \t]*Regression-test-exempt justification[ \t]*\n)(.*?)(?=^#+[ \t]|\Z)",
    re.MULTILINE | re.DOTALL)
new, n = pat.subn(r"\1\nInfra-only change to the CFN template; no executable surface.\n\n", body)
if n != 1:
    sys.stderr.write("expected exactly one exemption section, found %d\n" % n)
    sys.exit(1)
if "<!--" in pat.search(new).group(2):
    sys.stderr.write("placeholder comment survived the substitution\n")
    sys.exit(1)
json.dump({"number": 1, "title": "fix: something", "body": new,
           "labels": [{"name": "regression-test-exempt"}]}, open(sys.argv[2], "w"))
PY
assert_true $? "the template's exemption section can be located and filled in programmatically"
run_classify "${WORK_ROOT}/tmpl_filled.json" "tmpl_filled"
assert_eq "$(output_value tmpl_filled has_justification)" "true" \
    "template FILLED IN as an author would submit it DOES satisfy the exemption"
assert_eq "$(output_value tmpl_filled has_exempt)" "true" \
    "…and the exempt label is still honoured on that body"

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
echo "✅ regression-test gate reads CURRENT PR state and cannot be bypassed by add-then-remove of the exempt label."
