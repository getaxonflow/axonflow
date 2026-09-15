#!/usr/bin/env bash
# Regression guard: a runtime-e2e suite with a FIXED compose project name must
# clear its own stack BEFORE it boots one.
#
# THE BUG CLASS (#3784), diagnosed on drain 11 of #3741. On a persistent host a
# suite whose compose project name is fixed, and whose postgres uses the root
# compose's NAMED volume `postgres-data`, inherits the DATABASE of its own
# previous run whenever that run was cancelled:
#
#   1. the project name is fixed, so every run reuses `<project>_postgres-data`;
#   2. a NAMED volume survives `docker rm`, and `docker rm -v` removes only
#      ANONYMOUS ones, so the runner's leaked-container reaper cannot reclaim
#      it - and its 2h age bound would not reach a recent leftover anyway;
#   3. the only cleanup is the script's `trap cleanup EXIT`;
#   4. A CANCELLED JOB NEVER RUNS THE TRAP. Measured on run 33991169158:
#      step 7 cancelled, step 8 skipped, steps 9+ never evaluated.
#
# It produced two reds that looked like product failures: a mode-off arm
# behaving as enforce, because it inherited a per-organization row written by
# the previous run's enforce phase, and counters it never wrote. Both suites
# were green on `ubuntu-latest` in the same minutes - a hosted runner is a
# fresh VM per job, so no volume can outlive a run.
#
# WHY THE FIX IS A PRE-FLIGHT AND `if: always()` IS NOT A SUBSTITUTE. On
# cancellation the runner stops evaluating steps, so NO post-step runs - not
# even one marked `always()`. The only cleanup that survives a kill is one that
# runs at the START of the next job.
#
# ORDER IS THE INVARIANT, NOT PRESENCE, which is why `AFTER` is a distinct
# state. A teardown placed after the suite is the cleanup the suite already
# does for itself on a clean exit; it does nothing about the PREVIOUS run
# having been killed, and a guard that accepted it would pass a tree with the
# bug fully intact. 32 of these suites DO have such a post-run step, so this is
# the common shape rather than a hypothetical one.
#
# SCOPE. Suites whose project name is unique per run ($$, $RANDOM, a run id)
# cannot inherit - they leak a volume instead, which is a disk problem and not
# this one. Suites the registry marks `unwired` have no executor workflow, so
# they never run in CI and cannot eject a drain; they are counted on line 1
# rather than silently dropped.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

CENSUS=tests/regression-test-required/lib/preflight_teardown_census.py
[ -f "$CENSUS" ] || { echo "FAIL: census helper missing: $CENSUS"; exit 1; }

run_census() { python3 "$CENSUS" "$1"; }

out=$(run_census .) || { echo "FAIL: census did not run"; exit 1; }
header=$(printf '%s\n' "$out" | head -1)
censused=$(printf '%s\n' "$header" | cut -d' ' -f1)
unwired=$(printf '%s\n' "$header" | cut -d' ' -f2)
problems=$(printf '%s\n' "$out" | tail -n +2 | sed '/^$/d')

# Anti-vacuity on the EXAMINED population. A registry parse change once made
# every lookup miss and the census reported "not invoked" for all 40 suites;
# without a floor that reads as a clean tree.
if [ "${censused:-0}" -lt 30 ]; then
  echo "FAIL: only ${censused:-0} fixed-project suites with an executor censused (floor 30)"
  echo "      the registry or the suite glob is not being read"
  exit 1
fi
echo "ok: censused ${censused} fixed-project suites with an executor workflow (${unwired} unwired, out of scope)"

if [ -n "$problems" ]; then
  echo "FAIL: these suites can inherit a cancelled run's database:"
  printf '%s\n' "$problems" | sed 's/^/  /'
  echo ""
  echo "  MISSING  = no pre-flight teardown at all"
  echo "  AFTER    = a teardown exists but runs AFTER the suite, which is the"
  echo "             cleanup the suite already does for itself; it does nothing"
  echo "             about the previous run having been killed"
  echo "  NOTFOUND = the mapped workflow does not invoke this suite"
  echo ""
  echo "Add, BEFORE the step that runs the suite:"
  echo ""
  echo "    - name: Clear any stack a killed run of this suite left behind"
  echo "      shell: bash"
  echo "      run: ./runtime-e2e/<suite>/test.sh teardown || true"
  echo ""
  echo "An always() post-step does NOT work: a cancelled job stops evaluating"
  echo "steps, so no post-step of any kind runs."
  exit 1
fi
echo "ok: every fixed-project suite clears its own stack before booting one"

# ---------------------------------------------------------------------------
# Controls. Three states, each built from a REAL workflow, because a census
# that only ever returns clean is indistinguishable from one that reads
# nothing.
#
# The two victims come from what the tree actually contains, which the census
# itself revealed: 32 of these suites ALREADY carry a post-run "Tear down
# stack" step and 4 carry only the pre-flight. So deleting the pre-flight
# yields a different state depending on the victim, and both are worth pinning.
# An earlier draft used one victim for both and asserted MISSING against a
# workflow that has a post-run step; it got AFTER, which was the census being
# right and the control being wrong.
# ---------------------------------------------------------------------------
tmp=$(mktemp -d) || exit 1
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/.github" "$tmp/scripts/e2e"
cp -R runtime-e2e "$tmp/runtime-e2e"
cp scripts/e2e/runtime_e2e_suites.tsv "$tmp/scripts/e2e/"

STRIPPER="$tmp/strip_preflight.py"
cat > "$STRIPPER" <<'STRIPPY'
import io, re, sys
root, suite, wf = sys.argv[1], sys.argv[2], sys.argv[3]
p = root + '/.github/workflows/' + wf
s = io.open(p, encoding='utf-8').read()
# Cut exactly the block: its `- name:` line through its own `run:` line, plus
# one following blank line. An earlier version keyed on "up to the next blank
# line" and ate the step AFTER it - a fixture that mutates more than it names
# proves nothing about the rule it claims to test.
new = re.sub(r'^[ \t]*- name: Clear any stack a killed run of this suite left behind\n'
             r'(?:[ \t]+(?!- ).*\n)*?'
             r'[ \t]+run: \./runtime-e2e/[^\n]*test\.sh teardown \|\| true\n'
             r'[ \t]*\n?',
             '', s, count=1, flags=re.M)
assert new != s, 'fixture removed nothing for ' + suite
io.open(p, 'w', encoding='utf-8').write(new)
STRIPPY

fresh_workflows() { rm -rf "$tmp/.github/workflows"; cp -R .github/workflows "$tmp/.github/workflows"; }

# CONTROL 1 - MISSING: a suite whose ONLY teardown is the pre-flight.
fresh_workflows
python3 "$STRIPPER" "$tmp" 3605_decision_proof_key_custody decision-proof-key-custody-e2e.yml
c1=$(run_census "$tmp" | tail -n +2 | grep -c "^MISSING	3605_decision_proof_key_custody	")
[ "$c1" -ge 1 ] && echo "ok: removing the only teardown IS caught (MISSING)" || {
  echo "FAIL: removing the pre-flight went unnoticed"
  run_census "$tmp" | tail -n +2 | head -3; exit 1; }

# CONTROL 2 - AFTER, and this is the one that matters: the suite keeps its
# post-run "Tear down stack" step, so a guard keyed on PRESENCE passes it while
# the bug is fully intact.
fresh_workflows
python3 "$STRIPPER" "$tmp" 3363_audit_date_range audit-date-range-e2e.yml
c2=$(run_census "$tmp" | tail -n +2 | grep -c "^AFTER	3363_audit_date_range	")
[ "$c2" -ge 1 ] && echo "ok: a teardown that runs only AFTER the suite IS caught (order, not presence)" || {
  echo "FAIL: a post-suite-only teardown passed - the guard checks presence, not order"
  run_census "$tmp" | tail -n +2 | head -3; exit 1; }

# CONTROL 3 - a RUN-UNIQUE project with no pre-flight must NOT be flagged: it
# leaks a volume rather than inheriting one, which is a different problem.
fresh_workflows
python3 "$STRIPPER" "$tmp" 3605_decision_proof_key_custody decision-proof-key-custody-e2e.yml
python3 - "$tmp" <<'UNIQ'
import io, re, sys
t = sys.argv[1] + '/runtime-e2e/3605_decision_proof_key_custody/test.sh'
u = io.open(t, encoding='utf-8').read()
u2 = re.sub(r'^(\s*PROJECT=)(.*)$', r'\1"wt-$$"', u, count=1, flags=re.M)
assert u2 != u, 'fixture: PROJECT= line not found'
io.open(t, 'w', encoding='utf-8').write(u2)
UNIQ
c3=$(run_census "$tmp" | tail -n +2 | grep -c "	3605_decision_proof_key_custody	")
[ "$c3" = "0" ] && echo "ok: a run-unique project name is correctly out of scope" || {
  echo "FAIL: fired on a suite that cannot inherit (unique project per run)"; exit 1; }

echo "PASS: no fixed-project suite can inherit a cancelled run's database"
