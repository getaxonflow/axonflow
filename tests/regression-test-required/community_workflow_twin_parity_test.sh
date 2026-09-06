#!/usr/bin/env bash
# community_workflow_twin_parity_test.sh - #3574
#
# TWO LANES THAT TEST ONE MODULE DIFFERENTLY WILL DISAGREE, AND THE MIRROR IS
# THE LANE NOBODY WATCHES. test-community.yml SYNCS to the public mirror and
# test.yml does not, so any job that exists in both is two copies of one
# intent. The decision job was copied to test-community.yml in #3578 as a
# deliberate byte-exact twin of test.yml's; within a day #3577 and #3581 added
# the shadow gate, the legacy-compiler gate and the registry gates to test.yml
# only. Nothing was red. The public lane simply ran fewer gates than the
# private one, on the module whose gates exist to catch fail-open.
#
# THE RULES:
#
#   1. Every job id declared in BOTH workflows with at least one `run:` step
#      must carry the SAME sequence of steps - for a run step its name, env,
#      working-directory, shell and script; for a uses step its action and
#      `with:` - plus the same job-level env, byte for byte, unless it is
#      exempted below with a reason. Script-only parity was found wanting on
#      review: an `env: DATABASE_URL=...` added to one twin's step un-skips a
#      class of tests on one side only and is invisible to a body comparison. An exemption must be load-bearing: the
#      pair it names must actually differ, or the entry is dead weight hiding
#      the day the pair starts to differ for real.
#
#   2. test.yml's community-mirror-simulation job replays community jobs on a
#      staged copy of the mirror. The set it replays must EQUAL the set of
#      community jobs that can be replayed - every job with no `services:`,
#      at least one `run:` step, and no step carrying an `if:` - minus the
#      exemptions below, each with a reason and each load-bearing (the job it
#      names must exist and be replayable, or the entry is dead). A community
#      job added without a replay is then a red regression suite here, not a
#      suite that lands on the public repository having never executed.
#
# Both rules are read from the workflows with a YAML parser. A missing parser
# FAILS; a guard that cannot run must not report success.
#
# Run: bash tests/regression-test-required/community_workflow_twin_parity_test.sh
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ENTERPRISE_WORKFLOW="$REPO_ROOT/.github/workflows/test.yml"
COMMUNITY_WORKFLOW="$REPO_ROOT/.github/workflows/test-community.yml"

# The mirror strips test.yml, so on a mirror checkout this test has no
# enterprise twin to compare against. The suite that runs this directory is
# enterprise-only (regression-test-required.yml gates on github.repository);
# the file is left in place on the mirror rather than excluded so the sync's
# exclusion list does not grow a line per guard.
if [ ! -f "$ENTERPRISE_WORKFLOW" ]; then
  if [ -d "$REPO_ROOT/ee" ]; then
    echo "FAIL: $ENTERPRISE_WORKFLOW not found in an enterprise tree - this test cannot vacuously pass"
    exit 1
  fi
  echo "SKIP: community checkout (no test.yml to compare against); this guard runs in the enterprise repository"
  exit 0
fi
[ -f "$COMMUNITY_WORKFLOW" ] || { echo "FAIL: $COMMUNITY_WORKFLOW not found - this test cannot vacuously pass"; exit 1; }

# ---------------------------------------------------------------------------
# Exemptions. `job :: reason`. Reviewed, not assumed; each is checked to be
# load-bearing below.
# ---------------------------------------------------------------------------
PARITY_EXEMPT=$'integration-tests :: the database set-up step differs by design - the enterprise lane applies migrations/core, migrations/enterprise and migrations/industry/travel, the community lane applies migrations/core only, because the sync excludes migrations/enterprise/ and migrations/industry/ from the mirror
test-summary :: the two summaries aggregate different job sets (test.yml has the enterprise, real-PG, audit and simulation jobs) and resolve different required-context names'

# Replay exemptions: community jobs that COULD be replayed on the staged copy
# and deliberately are not.
REPLAY_EXEMPT=$'race-detector :: runs `go test -race` over platform/orchestrator and the two decision-shadow packages - all three have untagged builds that test.yml\'s unit-test jobs execute on every pull request and whose community-build compile the simulation vets; replaying a multi-minute race run over already-proven packages is cost without evidence
tests-executed-census :: reads the `needs` context of the run it is in (#3649); a replay has no needs context to count, and the job is byte-identical to test.yml\'s census, which executes on every enterprise pull request - the twin parity rule above is what proves the mirror copy is the executed one'

python3 - "$ENTERPRISE_WORKFLOW" "$COMMUNITY_WORKFLOW" "$PARITY_EXEMPT" "$REPLAY_EXEMPT" <<'PY'
import re, sys

try:
    import yaml
except ImportError:
    print("FAIL: PyYAML is unavailable; the parity assertions cannot run, and a guard that cannot run must not pass")
    sys.exit(1)

ent_path, com_path, parity_exempt_raw, replay_exempt_raw = sys.argv[1:5]

def load(path):
    with open(path) as fh:
        doc = yaml.safe_load(fh)
    return (doc or {}).get("jobs") or {}

def parse_exempt(raw):
    out = {}
    for line in raw.split("\n"):
        line = line.strip()
        if not line:
            continue
        if " :: " not in line:
            print("FAIL: exemption entry %r has no ' :: reason'" % line)
            sys.exit(1)
        job, reason = line.split(" :: ", 1)
        if not reason.strip():
            print("FAIL: exemption for %r carries no reason" % job)
            sys.exit(1)
        out[job.strip()] = reason.strip()
    return out

ent = load(ent_path)
com = load(com_path)
parity_exempt = parse_exempt(parity_exempt_raw)
replay_exempt = parse_exempt(replay_exempt_raw)

failures = 0
def ok(msg):
    print("  PASS: " + msg)
def bad(msg):
    global failures
    failures += 1
    print("  FAIL: " + msg)

def run_scripts(job):
    return [str(s["run"]) for s in (job.get("steps") or []) if isinstance(s, dict) and "run" in s]

def step_shape(job):
    """Everything about a job that decides what its steps DO, as a comparable
    list. Display names are included: a renamed gate is a gate whose log line
    changed, which is what a reader of the mirror's log greps for."""
    shape = [("job-env", job.get("env") or {})]
    for s in job.get("steps") or []:
        if not isinstance(s, dict):
            shape.append(("malformed", s))
            continue
        if "run" in s:
            shape.append(("run", s.get("name"), s.get("env") or {}, s.get("working-directory"), s.get("shell"), str(s["run"])))
        else:
            shape.append(("uses", s.get("name"), s.get("uses"), s.get("with") or {}))
    return shape

def first_divergence(a, b):
    for i, (x, y) in enumerate(zip(a, b)):
        if x != y:
            return i, x, y
    return min(len(a), len(b)), None, None

# ---------------------------------------------------------------------------
# Rule 1: twin parity.
# ---------------------------------------------------------------------------
print("=== rule 1: every job declared in both workflows runs the same steps ===")
shared = sorted(set(ent) & set(com))
if not shared:
    print("  FAIL: no job id is declared in both workflows; the parity set is empty and this rule is checking nothing")
    sys.exit(1)

compared = 0
for job_id in shared:
    e_runs = run_scripts(ent[job_id] or {})
    c_runs = run_scripts(com[job_id] or {})
    if not e_runs and not c_runs:
        ok("%s: no run: steps on either side (nothing to compare)" % job_id)
        continue
    compared += 1
    e_shape = step_shape(ent[job_id] or {})
    c_shape = step_shape(com[job_id] or {})
    same = e_shape == c_shape
    if job_id in parity_exempt:
        if same:
            bad("%s is exempted from parity but its run steps are IDENTICAL; the exemption is dead weight - remove it (reason given: %s)"
                % (job_id, parity_exempt[job_id]))
        else:
            ok("%s: differs, exempted with a reason: %s" % (job_id, parity_exempt[job_id][:80]))
        continue
    if same:
        ok("%s: %d step(s) identical in both workflows (names, env, uses/with, working-directory, shell, scripts)" % (job_id, len(e_shape) - 1))
    else:
        bad("%s: steps DIFFER between test.yml and test-community.yml (%d vs %d step(s))" % (job_id, len(e_shape) - 1, len(c_shape) - 1))
        i, a, b = first_divergence(e_shape, c_shape)
        if a is None:
            print("        one side has extra steps beyond the common prefix (position %d)" % i)
        else:
            print("        first divergence at position %d:" % i)
            print("          test.yml:           " + repr(a)[:160])
            print("          test-community.yml: " + repr(b)[:160])
        print("        The mirror is the lane nobody watches. Make them identical, or exempt the job with a reason.")

for job_id in parity_exempt:
    if job_id not in shared:
        bad("parity exemption names %r, which is not declared in both workflows; the entry is dead" % job_id)

if compared < 1:
    print("  FAIL: no shared job has run: steps; the parity rule compared nothing")
    sys.exit(1)
ok("compared %d shared job(s) with run steps (anti-vacuity)" % compared)

# ---------------------------------------------------------------------------
# Rule 2: the simulation replays every replayable community job.
# ---------------------------------------------------------------------------
print("=== rule 2: the mirror simulation replays every service-less community job ===")

def replayable(job_id, job):
    if job_id in ("detect-changes", "test-summary"):
        # No run steps / expression-conditional steps by construction; both are
        # still subject to the derivation below, this just names why.
        pass
    if job.get("services"):
        return False
    steps = job.get("steps") or []
    runs = [s for s in steps if isinstance(s, dict) and "run" in s]
    if not runs:
        return False
    if any("if" in s for s in runs):
        return False
    return True

expected = sorted(j for j, job in com.items() if replayable(j, job or {}))
if not expected:
    print("  FAIL: no community job is replayable; the derivation has stopped working")
    sys.exit(1)

for job_id, reason in replay_exempt.items():
    if job_id not in com:
        bad("replay exemption names %r, which test-community.yml does not declare; the entry is dead" % job_id)
    elif job_id not in expected:
        bad("replay exemption names %r, which is not replayable anyway (services, no run steps, or conditional steps); the entry is dead" % job_id)
    else:
        ok("%s: replayable but exempted with a reason: %s" % (job_id, reason[:80]))
expected = [j for j in expected if j not in replay_exempt]
if not expected:
    print("  FAIL: every replayable community job is exempted; the simulation would replay nothing")
    sys.exit(1)

sim = ent.get("community-mirror-simulation")
if sim is None:
    print("  FAIL: test.yml declares no community-mirror-simulation job")
    sys.exit(1)

replayed = []
staged_args = []      # the directory the simulation script is told to stage into
replay_dirs = []      # the directory each replay is pointed at
for step in sim.get("steps") or []:
    script = str(step.get("run") or "")
    joined = re.sub(r"\\\n\s*", " ", script)
    for line in joined.splitlines():
        if "simulate-community-mirror.sh" in line:
            toks = line.split("simulate-community-mirror.sh", 1)[1].split()
            if toks:
                staged_args.append(toks[0])
        if "run-community-job-in-mirror.sh" in line:
            # `run-community-job-in-mirror.sh <staged-dir> <job>...`, possibly
            # backslash-continued (joined above).
            tokens = line.split("run-community-job-in-mirror.sh", 1)[1].split()
            if tokens:
                replay_dirs.append(tokens[0])
            replayed.extend(tokens[1:])
replayed = sorted(set(replayed))

# The replay must be pointed at the STAGED copy. Pointing it at the checkout
# replays the community jobs on the unstripped enterprise tree, which passes
# every "stripped symbol" case by construction.
if not staged_args:
    bad("community-mirror-simulation never invokes simulate-community-mirror.sh; there is no staged copy to replay against")
elif not replay_dirs:
    pass  # reported below as "never invokes run-community-job-in-mirror.sh"
else:
    wrong = [d for d in replay_dirs if d not in staged_args]
    if wrong:
        bad("community-mirror-simulation replays against %s, which is not the directory it staged (%s); the replay would run on the unstripped tree" % (wrong, staged_args))
    else:
        ok("every replay is pointed at the staged copy (%s)" % ", ".join(sorted(set(replay_dirs))))

if not replayed:
    bad("community-mirror-simulation never invokes run-community-job-in-mirror.sh with a job list")
else:
    missing = [j for j in expected if j not in replayed]
    unknown = [j for j in replayed if j not in com]
    for j in missing:
        bad("community job %r is replayable and is NOT replayed by community-mirror-simulation; it would land on the public mirror having never executed anywhere" % j)
    for j in unknown:
        bad("community-mirror-simulation replays %r, which test-community.yml does not declare" % j)
    for j in replayed:
        if j in replay_exempt:
            bad("community-mirror-simulation replays %r AND the job is exempted; one of the two is wrong" % j)
    if not missing and not unknown:
        ok("the simulation replays exactly the replayable set: %s" % ", ".join(replayed))

# The simulation must gate test.yml's own summary: needs AND the failure
# expression, because a job in `needs` that the expression ignores is a job
# whose red stops nothing.
summary = ent.get("test-summary") or {}
needs = summary.get("needs") or []
if isinstance(needs, str):
    needs = [needs]
fail_steps = [s for s in (summary.get("steps") or []) if "needs." in str(s.get("if") or "") and "!= 'success'" in str(s.get("if") or "")]
fail_expr = " ".join(str(s.get("if")) for s in fail_steps)
if "community-mirror-simulation" not in needs:
    bad("community-mirror-simulation is not in test.yml's test-summary needs")
elif "needs.community-mirror-simulation.result" not in fail_expr:
    bad("community-mirror-simulation is in test-summary needs but absent from its failure expression; its red would stop nothing")
else:
    ok("community-mirror-simulation gates test.yml's Test Summary (needs and failure expression)")

print("")
if failures:
    print("FAIL: %d violation(s)" % failures)
    sys.exit(1)
print("PASS: community twins are byte-identical and every replayable community job is replayed")
PY
