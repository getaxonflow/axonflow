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

# --- 7. reading the runner INVENTORY must FAIL, even on a hosted runner ----
#
# The second way to depend on a fleet the mirror has not got, and the one
# rule 1 says yes to: runner-fleet-health.yml runs on ubuntu-latest - it has
# to, so it can still report when the fleet is down - and asks
# `/repos/{repo}/actions/runners`. On the mirror that is
# `gh: Resource not accessible by integration (HTTP 403)`, every 30 minutes,
# on a PUBLIC repository, blocking nothing. 47 of 47 runs of it on the mirror
# in the 24 hours to 2026-09-08T09:03Z failed - every one (run 34203530117).
stage_run() {  # stage_run <dir> <step-name> <run-body>
  mkdir -p "$1/.github/workflows"
  cat > "$1/.github/workflows/thing.yml" <<Y
on: push
jobs:
  fleet:
    runs-on: ubuntu-latest
    steps:
      - name: $2
        run: |
          $3
Y
}

stage_run "$tmp/inv" "Count online runners" 'gh api "/repos/${GITHUB_REPOSITORY}/actions/runners?per_page=100"'
out=$(python3 "$CHECK" "$tmp/inv" 2>&1)
if [ $? -eq 0 ]; then
  echo "FAIL: a step calling the runner-inventory API PASSED on a hosted runner - rule 1 cannot see this and nothing else would"; exit 1
fi
case "$out" in
  *"thing.yml:fleet / Count online runners"*"actions/runners"*)
    echo "ok: reading the runner inventory FAILS and names the file, job, step and endpoint" ;;
  *) echo "FAIL: it failed but did not name where:"; printf '%s\n' "$out" | head -6; exit 1 ;;
esac

# --- 8. the same endpoint via actions/github-script -----------------------
mkdir -p "$tmp/octo/.github/workflows"
cat > "$tmp/octo/.github/workflows/thing.yml" <<'Y'
on: push
jobs:
  fleet:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/github-script@v7
        with:
          script: |
            const r = await github.rest.actions.listSelfHostedRunnersForRepo({owner: 'x', repo: 'y'})
Y
out=$(python3 "$CHECK" "$tmp/octo" 2>&1)
if [ $? -eq 0 ]; then
  echo "FAIL: the Octokit spelling of the same call passed"; exit 1
fi
# THE REASON, not just the exit code. A row that asserts only "it failed" is
# satisfied by a failure for any other cause - a parse error, a missing file -
# and would go on passing after the rule it exists for was removed.
case "$out" in
  *"listSelfHostedRunners"*) echo "ok: the Octokit spelling fails, and the message names the call" ;;
  *) echo "FAIL: it failed, but not for the Octokit call:"; printf '%s\n' "$out" | head -4; exit 1 ;;
esac

# --- 9. a COMMENT about the endpoint must PASS ----------------------------
#
# The rule reads the parsed document, not the file text. A text rule is
# satisfied by your own comment - and, in this direction, TRIPPED by it, which
# would red a workflow that calls nothing. Both halves are wrong; this is the
# half a text implementation gets wrong first.
mkdir -p "$tmp/comment/.github/workflows"
cat > "$tmp/comment/.github/workflows/thing.yml" <<'Y'
# This workflow deliberately does NOT call /repos/{repo}/actions/runners,
# because listSelfHostedRunnersForRepo is unavailable on the mirror.
on: push
jobs:
  a-job:
    runs-on: ubuntu-latest
    steps:
      - name: something about actions/runners in a step name only
        run: echo hi
Y
python3 "$CHECK" "$tmp/comment" >/dev/null 2>&1 \
  && echo "ok: a comment - and a step NAME - about the endpoint does not red a workflow that calls nothing" \
  || { echo "FAIL: a comment mentioning the endpoint reddened a workflow that never calls it"; python3 "$CHECK" "$tmp/comment"; exit 1; }

# --- 9b. a reusable-workflow CALLER job has no steps ----------------------
#
# `jobs.<id>.uses` with `jobs.<id>.with` is a whole job expressed at job level.
# A scan that walked only `steps` skipped it, and this fixture smuggled the
# endpoint past the checker through a caller job's `with:`. Unlike the three
# indirections the rule's comment names, this one needs no call graph to see -
# the value is right there in the document.
mkdir -p "$tmp/reusable/.github/workflows"
cat > "$tmp/reusable/.github/workflows/thing.yml" <<'Y'
on: push
jobs:
  call:
    uses: ./.github/workflows/reusable.yml
    with:
      endpoint: /repos/x/actions/runners
Y
out=$(python3 "$CHECK" "$tmp/reusable" 2>&1)
if [ $? -eq 0 ]; then
  echo "FAIL: a reusable-workflow caller job passed the endpoint through job-level with: and was not seen"; exit 1
fi
case "$out" in
  *"actions/runners"*) echo "ok: a caller job's job-level uses/with is scanned, not only steps" ;;
  *) echo "FAIL: it failed but not for the endpoint:"; printf '%s\n' "$out" | head -4; exit 1 ;;
esac

# --- 9c. an unclassifiable runs-on must NOT be diagnosed as a fleet job ----
#
# THE FAILURE MODE THIS ROW EXISTS FOR IS A GUARD THAT IS RIGHT TO FAIL AND
# WRONG ABOUT WHY. build.yml's `${{ matrix.arch == 'arm64' && 'ubuntu-24.04-arm'
# || 'ubuntu-latest' }}` selects two GitHub-HOSTED runners and neither is
# self-hosted, but the shared resolver cannot parse it and fails closed - which
# is correct. What is not correct is telling that author to exclude their
# workflow from the mirror. A guard that fails is a guard; a guard that
# confidently prescribes the wrong fix gets obeyed.
stage "$tmp/opaque" "\${{ matrix.arch == 'arm64' && 'ubuntu-24.04-arm' || 'ubuntu-latest' }}"
out=$(python3 "$CHECK" "$tmp/opaque" 2>&1)
if [ $? -eq 0 ]; then
  echo "FAIL: an unclassifiable runs-on passed; the checker fails open"; exit 1
fi
case "$out" in
  *"cannot classify"*"remedy is NOT to exclude"*)
    echo "ok: an unclassifiable runs-on fails closed AND is diagnosed as unclassifiable, not as a fleet pin" ;;
  *) echo "FAIL: it failed, but the message prescribes the fleet remedy for a job that asks for no fleet:"
     printf '%s\n' "$out" | head -8; exit 1 ;;
esac
case "$out" in
  *"ask for a runner the mirror has not got"*)
    echo "FAIL: the fleet section fired for a job whose labels contain no self-hosted"; exit 1 ;;
  *) echo "ok: and the fleet section did not fire for it" ;;
esac

# --- 10. every fleet-dependent workflow in THIS tree is excluded from the sync
#
# Rows 1-9 prove the RULE over fixtures. This one applies it to the real tree:
# any workflow that runs on the fleet, or reads its inventory, must be absent
# from the mirror. Resolved against the sync's own exclusion list, never a
# re-typed copy of it, and stated as a rule over a census rather than as a
# third named entry - the list has now been reasoned about three times.
#
# ENTERPRISE TREE ONLY, keyed on the POSITIVE `ee/` marker the shared resolver
# already uses. On the mirror sync-community-repo.yml does not exist and this
# repository's other ~140 workflows do not either, so the census would read a
# small number and the row would answer a question nobody asked. Rows 1-9 are
# fixture-driven and do run there, which is the point of skipping this one
# rather than excluding the whole file.
#
# TWO QUESTIONS, NOT ONE, AND THE SKIP ANSWERS ONLY THE FIRST. "Is this the
# enterprise tree" and "are this row's inputs present" are different questions,
# and a branch that serves both turns a rename into a silent retirement: the
# census would stop running and every board would stay green. So the tree is
# classified by TWO markers that must agree - `ee/` (stripped by the sync) and
# `sync-community-repo.yml` (excluded by the sync). Both present is the
# enterprise tree and the row RUNS, failing on any missing input. Both absent
# is the mirror and the row skips, loudly, naming why. One of each is a tree
# neither branch was written for, and that FAILS rather than picking a branch.
tree=$(python3 - <<'PY'
import os, sys
sys.path.insert(0, 'tests/regression-test-required/lib')
from runs_on_labels import is_enterprise_tree
ee = is_enterprise_tree('.')
sync = os.path.isfile('.github/workflows/sync-community-repo.yml')
print("enterprise" if (ee and sync) else "mirror" if not (ee or sync)
      else "unrecognised ee=%s sync=%s" % (ee, sync))
PY
)
case "$tree" in
  enterprise)
    python3 - <<'PY' || exit 1
import fnmatch, glob, io, os, re, sys
sys.path.insert(0, 'tests/regression-test-required/lib')
import yaml
from runs_on_labels import labels_for, schedulable_on_mirror, MIRROR, UNPARSEABLE
import importlib.util
spec = importlib.util.spec_from_file_location(
    "mirror_check", ".github/scripts/check-mirror-runner-labels.py")
mirror_check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mirror_check)

sync = ".github/workflows/sync-community-repo.yml"
if not os.path.isfile(sync):
    print("FAIL: %s is missing in the enterprise tree; this row cannot check "
          "what it cannot read" % sync)
    sys.exit(1)
rules = re.findall(r"--exclude='([^']*)'", io.open(sync, encoding="utf-8").read())
if len(rules) < 50:
    print("FAIL: parsed only %d exclude rules from the sync; the extraction is "
          "broken, not the list" % len(rules))
    sys.exit(1)


def excluded(name):
    """Is `.github/workflows/<name>` kept off the mirror by the sync's own list?

    Only the two shapes the list uses for workflow files: the exact path, and a
    `.github/workflows/<glob>.yml` pattern. Anything else is NOT treated as an
    exclusion, so an unfamiliar rule reads as "still synced" and this row goes
    red rather than quiet.
    """
    path = ".github/workflows/" + name
    for rule in rules:
        if rule == path:
            return True
        if rule.startswith(".github/workflows/") and fnmatch.fnmatch(path, rule):
            return True
    return False


# BOTH EXTENSIONS: GitHub honours `.yaml`, and a `.yml`-only glob would miss
# such a workflow SILENTLY - a smaller count, every assertion still passing.
workflows = sorted(glob.glob(".github/workflows/*.yml")
                   + glob.glob(".github/workflows/*.yaml"))
if len(workflows) < 100:
    print("FAIL: censused only %d workflow(s); this tree should carry ~140 and the "
          "row would pass by seeing almost nothing" % len(workflows))
    sys.exit(1)

leaked, unclassifiable, fleet_aware = [], [], 0
for f in workflows:
    try:
        d = yaml.safe_load(io.open(f, encoding="utf-8"))
    except Exception as exc:
        print("FAIL: %s does not parse (%s)" % (f, str(exc)[:80]))
        sys.exit(1)
    if not isinstance(d, dict):
        continue
    name = os.path.basename(f)
    # TWO CAUSES OF "unservable", AND THEY GET DIFFERENT REMEDIES. A job either
    # ASKS for the fleet, or carries a `runs-on` the shared resolver cannot
    # classify - which fails closed, correctly, but is often a perfectly hosted
    # job. build.yml's matrix fan-out over `arch` selects two GitHub-hosted
    # runners and neither is self-hosted; a message telling its author to
    # exclude the workflow from the mirror would be a guard confidently
    # prescribing the wrong fix.
    fleet_why, opaque_why = [], []
    for jn, j in (d.get("jobs") or {}).items():
        if not isinstance(j, dict):
            continue
        ro = j.get("runs-on")
        if schedulable_on_mirror(ro):
            continue
        labels = labels_for(ro, MIRROR)
        if "self-hosted" in labels:
            fleet_why.append("job %s runs on the fleet" % jn)
        elif UNPARSEABLE in labels:
            opaque_why.append("job %s has a runs-on this checker cannot classify (%r)" % (jn, ro))
    for jn, label, token in mirror_check.fleet_inventory_calls(d):
        fleet_why.append("%s/%s calls %s" % (jn, label, token))
    if fleet_why:
        fleet_aware += 1
        if not excluded(name):
            leaked.append((name, fleet_why))
    elif opaque_why and not excluded(name):
        unclassifiable.append((name, opaque_why))

if fleet_aware == 0:
    print("FAIL: the census found ZERO fleet-dependent workflows in a tree that has "
          "several; the classifier is broken and this row would pass vacuously")
    sys.exit(1)

if unclassifiable:
    for name, why in unclassifiable:
        print("FAIL: .github/workflows/%s reaches the mirror with a `runs-on` the shared "
              "resolver cannot classify (%s). This is NOT a finding that the workflow "
              "depends on the fleet, and the remedy is NOT to exclude it: an "
              "unrecognised expression fails closed because that is where a wrong pass "
              "reintroduces the queue-forever outage. Teach the shape to "
              "tests/regression-test-required/lib/runs_on_labels.py (_COND), or rewrite "
              "it into the repository-conditional form." % (name, "; ".join(why)))
if leaked:
    for name, why in leaked:
        print("FAIL: .github/workflows/%s reaches the mirror and depends on the "
              "self-hosted fleet (%s). The mirror has no fleet and its GITHUB_TOKEN "
              "cannot read the runner list, so there it can only be red - on a "
              "schedule, on a public repository, blocking nothing. Exclude it in "
              "sync-community-repo.yml with its reason." % (name, "; ".join(why)))
if leaked or unclassifiable:
    sys.exit(1)
print("ok: all %d fleet-dependent workflow(s) of %d are excluded from the sync"
      % (fleet_aware, len(workflows)))
PY
    ;;
  mirror)
    echo "ok: row 10 SKIPPED - both enterprise markers are absent (no ee/, no"
    echo "    sync-community-repo.yml), so this is the mirror's copy of this file"
    echo "    and the real-tree census has no tree to census. Rows 1-9 ran."
    ;;
  *)
    echo "FAIL: row 10 cannot classify this tree ($tree). Exactly one of the two"
    echo "      enterprise markers is present, which is neither the enterprise"
    echo "      checkout nor the staged mirror. Skipping here would retire the"
    echo "      eight-workflow census silently - the failure mode this branch"
    echo "      exists to refuse - so it fails instead. If sync-community-repo.yml"
    echo "      was renamed, update this row; if ee/ moved, update runs_on_labels."
    exit 1
    ;;
esac

echo "PASS: the mirror can schedule every job the sync would carry, and no staged workflow reads the fleet it has not got"
