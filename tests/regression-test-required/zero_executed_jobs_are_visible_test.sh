#!/usr/bin/env bash
# zero_executed_jobs_are_visible_test.sh - #3649
#
# A PATH-FILTERED WORKFLOW CAN REPORT SUCCESS HAVING EXECUTED NOTHING. A rollup
# job that accepts `skipped` from its needs (it must - a required summary has
# to stay satisfiable on a docs-only change) reports `success` when the change
# detector matched no path and every sibling skipped. On the checks list that
# is the same green as a run of the suite. At the v10.3.0 release head the
# community twin did exactly this, and the #3555 gate rerun discarded it as
# evidence only because a reviewer noticed.
#
# THE RULE: every workflow that carries a skip-accepting rollup - a job with
# `if: always()` and a step whose `if` compares a `needs.*.result` against
# 'skipped' - must also carry a `tests-executed-census` job that
#   1. `needs` at least every job the rollup needs (it counts the same set),
#   2. runs `if: always()` (a census that skips counts nothing),
#   3. reads `${{ toJSON(needs) }}` into NEEDS_JSON (the count is derived from
#      the context, never typed),
#   4. exits non-zero when zero substantive jobs executed (the `sys.exit(1)`
#      after the "nothing failed and nothing was tested" line).
# The census is deliberately NOT a required context: it is the first-class
# "this run proved nothing" outcome, visible on the checks list, that a
# required summary cannot be.
#
# Both halves are read from the workflows with a YAML parser; a missing parser
# FAILS. Self-tests run first against fixtures in both directions, so a guard
# that stopped seeing rollups cannot pass as "nothing to check".
#
# Run: bash tests/regression-test-required/zero_executed_jobs_are_visible_test.sh
set -uo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORKFLOWS="$REPO_ROOT/.github/workflows"

check_tree() {
  # $1: directory of workflow files. Prints findings; exit 0 clean, 1 findings,
  # 2 could not run.
  python3 - "$1" <<'PY'
import glob, os, re, sys
try:
    import yaml
except ImportError:
    print("FAIL: PyYAML is unavailable; the assertions cannot run, and a guard that cannot run must not pass")
    sys.exit(2)

d = sys.argv[1]
files = sorted(glob.glob(os.path.join(d, "*.yml")))
if not files:
    print(f"FAIL: no workflow files under {d}; a census over nothing is not a census")
    sys.exit(2)

SKIP_RE = re.compile(r"needs\.[\w-]+\.result\s*!=\s*'skipped'")
findings = []
rollups_seen = 0

def as_list(v):
    if v is None:
        return []
    return v if isinstance(v, list) else [v]

for path in files:
    with open(path, encoding="utf-8") as fh:
        try:
            doc = yaml.safe_load(fh)
        except yaml.YAMLError as e:
            findings.append(f"{os.path.basename(path)}: not parseable YAML: {e}")
            continue
    jobs = (doc or {}).get("jobs") or {}
    rollups = []
    for jid, job in jobs.items():
        if not isinstance(job, dict):
            continue
        cond = str(job.get("if") or "")
        if "always()" not in cond:
            continue
        for step in job.get("steps") or []:
            if isinstance(step, dict) and SKIP_RE.search(str(step.get("if") or "")):
                rollups.append(jid)
                break
    if not rollups:
        continue
    rollups_seen += len(rollups)
    name = os.path.basename(path)
    census = jobs.get("tests-executed-census")
    if not isinstance(census, dict):
        findings.append(f"{name}: rollup job(s) {rollups} accept skipped needs but the workflow has no `tests-executed-census` job; a run in which every job skipped reports success with nothing to say so")
        continue
    if "always()" not in str(census.get("if") or ""):
        findings.append(f"{name}: tests-executed-census does not run `if: always()`; a census that skips with its siblings counts nothing")
    census_needs = set(as_list(census.get("needs")))
    for rid in rollups:
        missing = set(as_list(jobs[rid].get("needs"))) - census_needs
        if missing:
            findings.append(f"{name}: tests-executed-census does not need {sorted(missing)}, which rollup `{rid}` needs; the census must count the set the summary reports on")
    steps = census.get("steps") or []
    env_ok = any(isinstance(s, dict) and str((s.get("env") or {}).get("NEEDS_JSON", "")).replace(" ", "") == "${{toJSON(needs)}}" for s in steps)
    if not env_ok:
        findings.append(f"{name}: tests-executed-census has no step with env NEEDS_JSON: ${{{{ toJSON(needs) }}}}; the count must be derived from the needs context, not typed")
    body = "\n".join(str(s.get("run") or "") for s in steps if isinstance(s, dict))
    if "nothing failed and nothing was tested" not in body or "sys.exit(1)" not in body:
        findings.append(f"{name}: tests-executed-census does not fail on zero executed jobs (missing the 'nothing failed and nothing was tested' refusal); a census that cannot go red is decoration")

if rollups_seen == 0:
    print(f"FAIL: no skip-accepting rollup found under {d}; the selector stopped seeing the tree (or the fixture is wrong)")
    sys.exit(2)
for f in findings:
    print("FAIL: " + f)
if findings:
    sys.exit(1)
print(f"ok: {rollups_seen} skip-accepting rollup(s) across {len(files)} workflow(s), each beside a tests-executed-census that can go red")
PY
}

# ---------------------------------------------------------------------------
# Self-tests: the guard must go RED on the defect and GREEN on the cure.
# ---------------------------------------------------------------------------
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

good_census() {
  cat <<'EOF'
  tests-executed-census:
    needs: [detect-changes, unit]
    if: always()
    steps:
      - name: Count
        env:
          NEEDS_JSON: ${{ toJSON(needs) }}
        run: |
          echo "nothing failed and nothing was tested"
          python3 -c 'import sys; sys.exit(1)'
EOF
}
rollup() {
  cat <<'EOF'
on: pull_request
jobs:
  detect-changes:
    runs-on: ubuntu-latest
    steps: [{run: echo}]
  unit:
    needs: [detect-changes]
    runs-on: ubuntu-latest
    steps: [{run: echo}]
  summary:
    needs: [detect-changes, unit]
    if: always()
    steps:
      - name: fail if
        if: needs.unit.result != 'success' && needs.unit.result != 'skipped'
        run: exit 1
EOF
}

mkdir -p "$TMP/none" "$TMP/narrow" "$TMP/noexit" "$TMP/good"
rollup > "$TMP/none/w.yml"
{ rollup; good_census | sed 's/needs: \[detect-changes, unit\]/needs: [detect-changes]/'; } > "$TMP/narrow/w.yml"
{ rollup; good_census | grep -v 'sys.exit(1)'; } > "$TMP/noexit/w.yml"
{ rollup; good_census; } > "$TMP/good/w.yml"

fail=0
expect() { # $1 label, $2 dir, $3 expected exit
  local out rc
  out=$(check_tree "$2" 2>&1); rc=$?
  if [ "$rc" -ne "$3" ]; then echo "SELF-TEST FAIL ($1): exit $rc, want $3"; echo "$out"; fail=1; else echo "self-test ok: $1"; fi
}
expect "RED on a rollup with no census" "$TMP/none" 1
expect "RED on a census narrower than the rollup" "$TMP/narrow" 1
expect "RED on a census that cannot exit non-zero" "$TMP/noexit" 1
expect "GREEN on rollup + complete census" "$TMP/good" 0
[ "$fail" -eq 0 ] || { echo "FAIL: the guard's self-tests failed; its verdict on the real tree cannot be trusted"; exit 1; }

# ---------------------------------------------------------------------------
# The real tree.
# ---------------------------------------------------------------------------
out=$(check_tree "$WORKFLOWS" 2>&1); rc=$?
echo "$out"
if [ "$rc" -ne 0 ]; then
  echo "FAIL: zero-executed-jobs visibility (#3649)"
  exit 1
fi
echo "PASS: every skip-accepting rollup has a census beside it that goes red when nothing executed"
