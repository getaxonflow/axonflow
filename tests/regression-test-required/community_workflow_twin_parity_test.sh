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
#   1b. Every PARITY exemption must rest on something STRUCTURAL, and the guard
#      resolves it rather than reading it. A parity exemption claims "the mirror
#      cannot run this step", which is a claim about what the mirror CONTAINS,
#      so the path the reason names must be one `sync-community-repo.yml`
#      actually strips AND one that exists - resolved against the sync's own
#      rule chain, in order, includes and excludes both, never against a list
#      re-typed here. Stated exactly, because the sentence above reads wider
#      than the code: this holds for exemptions that CITE a path. `test-summary`
#      rests on no path by design and is held to its own checked ground instead
#      (rule 3's hatch), so "every parity exemption rests on a stripped path" is
#      false as a description of the set - the accurate one is "on a checked
#      ground". `foo :: enterprise only` and
#      `foo :: we decided not to` used to pass; a reason naming `platform/`
#      fails, because a step reading `platform/` CAN run on the mirror and the
#      divergence needs a different justification. This also gives an exemption
#      a way to EXPIRE: stop stripping a path and every exemption resting on it
#      fails, which is the behaviour you want (#3863).
#
#      The escape hatch is one job wide and is itself checked, not asserted -
#      see rule 3. REPLAY exemptions are deliberately NOT held to this, and the
#      reason needs narrowing from the one first written here. `race-detector`
#      is a judgement about COST and has no structural form. `tests-executed-
#      census` is NOT - the job really does read `toJSON(needs)` and the mirror
#      runner rewrites every non-workspace expression to a literal, so its
#      ground IS checkable, and "replay grounds have no structural form" is
#      false for half the population. Excluding both from the PATH rule is still
#      right: a path test over either would only teach the next author to name a
#      path that happens to be stripped, which is worse than free text because
#      it would look checked. A structural check for the census one would be a
#      different rule, and is not this one.
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
test-summary :: the two summaries aggregate different job sets (test.yml has the enterprise, real-PG, audit and simulation jobs) and resolve different required-context names
unit-tests-decision :: test.yml carries one extra step, the enterprise-tagged corpus/template drift guard, which asserts that testdata/canary_payload_corpus.json still matches the plane map embedded in infrastructure/cloudformation/synthetic-monitoring-decision-shadow.yaml - the sync strips infrastructure/ from the mirror, so the file the step compares against does not exist there and the step cannot be replayed; the community tree is verified instead by the untagged corpus tests, which read the checked-in fixture and run in both lanes'

# Replay exemptions: community jobs that COULD be replayed on the staged copy
# and deliberately are not.
REPLAY_EXEMPT=$'race-detector :: runs `go test -race` over platform/orchestrator and the two decision-shadow packages - all three have untagged builds that test.yml\'s unit-test jobs execute on every pull request and whose community-build compile the simulation vets; replaying a multi-minute race run over already-proven packages is cost without evidence
tests-executed-census :: reads the `needs` context of the run it is in (#3649); a replay has no needs context to count, and the job is byte-identical to test.yml\'s census, which executes on every enterprise pull request - the twin parity rule above is what proves the mirror copy is the executed one'

SYNC_WORKFLOW="$REPO_ROOT/.github/workflows/sync-community-repo.yml"
# The sync workflow is EXCLUDED from the mirror, so on a mirror checkout it is
# absent. That branch is unreachable here - this script has already exited SKIP
# above when test.yml is missing, and test.yml is stripped by the same sync - so
# an absent sync file in a tree that HAS test.yml is an unrecognised tree and
# must fail rather than skip a rule.
[ -f "$SYNC_WORKFLOW" ] || { echo "FAIL: $SYNC_WORKFLOW not found in a tree that has test.yml; rule 3 cannot resolve an exemption's cited path against a list it cannot read"; exit 1; }

python3 - "$ENTERPRISE_WORKFLOW" "$COMMUNITY_WORKFLOW" "$PARITY_EXEMPT" "$REPLAY_EXEMPT" "$SYNC_WORKFLOW" <<'PY'
import fnmatch, os, re, subprocess, sys

try:
    import yaml
except ImportError:
    print("FAIL: PyYAML is unavailable; the parity assertions cannot run, and a guard that cannot run must not pass")
    sys.exit(1)

ent_path, com_path, parity_exempt_raw, replay_exempt_raw, sync_path = sys.argv[1:6]

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
other_workflows = []  # (workflow, jobs) replayed via COMMUNITY_WORKFLOW=... overrides
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
            # The simulation also replays OTHER mirrored workflows' jobs
            # (lint.yml's, via COMMUNITY_WORKFLOW=...). Those are held to the
            # staged-directory rule above like every replay, but they are not
            # test-community.yml jobs and rule 2 is about test-community.yml,
            # so they are not counted here. An override that names
            # test-community.yml itself still counts.
            m = re.search(r"COMMUNITY_WORKFLOW=(\S+)", line)
            if m and not m.group(1).endswith("test-community.yml"):
                other_workflows.append((m.group(1), tokens[1:]))
                continue
            replayed.extend(tokens[1:])
replayed = sorted(set(replayed))
for wf, jobs in other_workflows:
    ok("replays %s job(s) %s on the staged copy (not part of rule 2)" % (wf, ", ".join(jobs)))

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

# ---------------------------------------------------------------------------
# Rule 3: a parity exemption's REASON is resolved, not read (#3863).
#
# `parse_exempt` checks that a reason is non-empty and the rules above check
# that the exemption is load-bearing. Neither reads the WORDS, so `foo ::
# enterprise only` passed and so did `foo :: we decided not to`.
#
# The check that carries weight is not "the reason mentions a path" - any path
# satisfies that, including one the sync happily syncs, which is the
# presence-check-satisfied-by-your-own-comment failure this repository has hit
# before. It is: THE PATH THE REASON NAMES MUST BE ONE THE SYNC ACTUALLY
# STRIPS, resolved against sync-community-repo.yml's own declaration.
# ---------------------------------------------------------------------------
print("=== rule 3: every parity exemption cites a path the sync actually strips ===")

with open(sync_path) as fh:
    sync_src = fh.read()

# RULES IN ORDER, INCLUDES AND EXCLUDES BOTH - because rsync is FIRST MATCH
# WINS and the sync declares 31 `--include=` rules among its 146 `--exclude=`
# ones. An exclude-only reading is not a conservative approximation of that
# chain; it is a different chain. Measured against the live mirror's own file
# list: an exclude-only resolver calls 29 files "stripped" that are committed
# on the public mirror right now - `config/axonflow.yaml` (re-included at
# :677 before `/config/*` excludes it at :682), `build-community.yml`,
# `.gitignore` and the rest.
#
# The direction of that error is the dangerous one: it lets an exemption rest
# on a path the mirror HAS, which is precisely the free text this rule exists
# to replace. No current exemption was affected - it was a latent fail-open -
# and it passed a planted reason citing `config/axonflow.yaml`.
ALL_PATHS = subprocess.run(["git", "ls-files"], capture_output=True, text=True).stdout.split()

SYNC_RULES = [(kind, pat) for kind, pat
              in re.findall(r"--(exclude|include)='([^']*)'", sync_src)]
EXCLUDE_RULES = [pat for kind, pat in SYNC_RULES if kind == "exclude"]
if len(EXCLUDE_RULES) < 50:
    print("  FAIL: parsed only %d exclude rules from %s; the sync declares far more, so the "
          "extraction is broken and every resolution below would be meaningless"
          % (len(EXCLUDE_RULES), sync_path))
    sys.exit(1)
if len([1 for kind, _ in SYNC_RULES if kind == "include"]) < 10:
    print("  FAIL: parsed fewer than 10 include rules from %s; rsync is first-match-wins, so "
          "an include-blind reading resolves a DIFFERENT chain and would call mirrored files "
          "stripped" % sync_path)
    sys.exit(1)

# A path-shaped token: at least one '/', so a bare filename like `test.yml`
# (which the sync's rules never name on its own) is not mistaken for one.
PATH_TOKEN = re.compile(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.*-]+)+/?")

# WHAT THIS RULE DOES AND DOES NOT ESTABLISH, said here rather than left to be
# discovered. A reason usually names several paths - the enterprise one AND the
# community one it is being contrasted with - so the rule is that AT LEAST ONE
# cited path is stripped, not that all of them are. `migrations/core` and
# `testdata/canary_payload_corpus.json` are cited by real exemptions and both
# reach the mirror, correctly: they are the contrast, not the ground.
#
# So this establishes "the mirror is missing an input this step needs", which is
# what makes the divergence structural. It does NOT establish that the stripped
# path is the one the author had in mind. That would need the reason to say
# which of its paths is load-bearing, which is a heavier contract than the
# problem justifies - and the weaker claim is still the whole of what free text
# gave you before, which was nothing.


def _rule_matches(pattern, p):
    """Does one rsync rule match this repo-relative path?

    Only the three shapes the sync's list actually uses are modelled - a
    directory prefix, an exact path, and a glob - and anything unrecognised
    simply does not match, so it cannot bless anything.
    """
    r = pattern.lstrip("/").rstrip("/")
    if not r:
        return False
    if p == r or p.startswith(r + "/"):
        return True
    return fnmatch.fnmatch(p, r) or fnmatch.fnmatch(p, r + "/*")


def _exists(cited):
    """Is this cited path a real thing in the tree?

    Exact repo-relative first, then a UNIQUE suffix match - a reason may name a
    path relative to its own module (`testdata/canary_payload_corpus.json` lives
    at `platform/decision/legacycompile/testdata/...`) and that is a legitimate
    way to write it. A non-unique or absent suffix is not accepted, so a
    plausible string under a stripped prefix cannot pass.

    Tokens that are prose rather than paths (`corpus/template`, from "the
    corpus/template drift guard") simply fail this and are then ignored: only a
    path that is BOTH stripped and real is load-bearing, and the rest of a
    reason's tokens are context.
    """
    c = cited.rstrip("/")
    if os.path.exists(c):
        return True
    hits = [p for p in ALL_PATHS if p == c or p.endswith("/" + c)]
    return len(hits) == 1


def stripped_by(path):
    """The exclude rule that keeps `path` off the mirror, or None.

    FIRST MATCH WINS, over includes AND excludes in declaration order, because
    that is what rsync does. An INCLUDE that matches first means the file
    REACHES the mirror however many excludes follow it - `config/axonflow.yaml`
    is re-included at :677 and `/config/*` at :682 never sees it.

    Anything unmatched resolves to None, i.e. NOT stripped. That direction is
    deliberate: an unmodelled rule makes an exemption RED and sends a human to
    look, where the opposite would silently bless a reason resting on a path the
    mirror actually has.
    """
    p = path.strip("/")
    for kind, pattern in SYNC_RULES:
        if _rule_matches(pattern, p):
            return pattern if kind == "exclude" else None
    return None


# ANTI-VACUITY, and it is a control rather than a count: the resolver must say
# YES to a path the sync demonstrably strips and NO to one it demonstrably
# ships. A resolver that answered yes to everything would pass every exemption
# below, and a resolver that answered no to everything would fail them all -
# both are visible here and in neither case would the rule mean anything.
_probe_stripped = stripped_by("infrastructure/cloudformation/x.yaml")
_probe_synced = stripped_by("platform/agent/proxy.go")
# THE INCLUDE-RESCUE PROBE. `config/axonflow.yaml` is re-included by the sync
# BEFORE `/config/*` excludes it, and it is committed on the public mirror right
# now. An exclude-only resolver answers `/config/*` here, which is the
# fail-open this control exists to refuse.
_probe_rescued = stripped_by("config/axonflow.yaml")
if _probe_stripped is None:
    print("  FAIL: the resolver says infrastructure/ is NOT stripped, which the sync's own list "
          "contradicts; every exemption below would red for a reason that is not theirs")
    sys.exit(1)
if _probe_synced is not None:
    print("  FAIL: the resolver says platform/agent/proxy.go IS stripped (matched %r); it reaches "
          "the mirror, so the resolver would bless a reason resting on a path that syncs"
          % _probe_synced)
    sys.exit(1)
if _probe_rescued is not None:
    print("  FAIL: the resolver says config/axonflow.yaml is stripped (matched %r), but the sync "
          "RE-INCLUDES it before that rule and the file is committed on the public mirror. "
          "rsync is first-match-wins; an exclude-only reading resolves a different chain and "
          "would bless an exemption resting on a path the mirror has." % _probe_rescued)
    sys.exit(1)
ok("the resolver distinguishes stripped, synced, and INCLUDE-RESCUED paths (control, three ways)")

# THE ESCAPE HATCH, one job wide, and its ground is CHECKED rather than
# asserted. `test-summary` is the one parity exemption with no structural path:
# the two summaries aggregate different job sets, which is a fact about the
# workflows and not about the mirror. So it is held to that fact instead - if
# the two `needs` lists ever become equal, the exemption dies here rather than
# living on as a sentence nobody re-read.
def needs_of(job):
    n = (job or {}).get("needs") or []
    return {n} if isinstance(n, str) else set(n)


def _test_summary_ground(job_id):
    """`test-summary`'s ground, CHECKED: the two summaries aggregate different job sets."""
    e_needs, c_needs = needs_of(ent.get(job_id)), needs_of(com.get(job_id))
    if e_needs == c_needs:
        return False, ("the two workflows' `needs` are now IDENTICAL (%s). The ground is gone: "
                       "either the divergence has a different reason now, or the exemption "
                       "should go." % sorted(e_needs))
    return True, ("the two `needs` sets differ (%d vs %d jobs)" % (len(e_needs), len(c_needs)))


# EACH HATCH ENTRY MAPS TO ITS OWN CHECK, never to a sentence. The first version
# mapped job -> a ground STRING and had exactly one hard-coded branch beside it,
# so a second entry took the hatch and printed "on a ground that is checked"
# with nothing checking it - fail-open, in the escape hatch, which is exactly
# where a future author arrives. A callable cannot be added without supplying
# the check, because there is nothing else to add.
NO_PATH_GROUND = {"test-summary": _test_summary_ground}

for _job, _ground in NO_PATH_GROUND.items():
    if not callable(_ground):
        print("  FAIL: the no-path exemption %r maps to %r, not to a check. A hatch entry whose "
              "ground is a SENTENCE is unverified free text - the exact thing rule 3 exists to "
              "replace - sitting in the one place a future author is most likely to reach for."
              % (_job, _ground))
        sys.exit(1)


resolved_by_path = 0
for job_id, reason in sorted(parity_exempt.items()):
    if job_id in NO_PATH_GROUND:
        held, why = NO_PATH_GROUND[job_id](job_id)
        if held:
            ok("%s: exempted with no cited path, on a ground that is CHECKED - %s" % (job_id, why))
        else:
            bad("%s is exempted with no cited path and its ground no longer holds: %s"
                % (job_id, why))
        continue

    cited = [t for t in PATH_TOKEN.findall(reason)]
    if not cited:
        bad("%s: the exemption reason names no path, and %s is the only exemption allowed to have "
            "no structural path. A parity exemption claims the mirror CANNOT run the step; that "
            "claim has to rest on something the sync strips. Reason given: %r"
            % (job_id, sorted(NO_PATH_GROUND), reason))
        continue
    hits = [(c, stripped_by(c)) for c in cited]
    stripped = [(c, r) for c, r in hits if r and _exists(c)]
    unreal = [(c, r) for c, r in hits if r and not _exists(c)]
    if stripped:
        resolved_by_path += 1
        c, r = stripped[0]
        ok("%s: cites %s, which exists and which the sync strips (--exclude='%s')"
           % (job_id, c, r))
    elif unreal:
        bad("%s: the exemption's only stripped path(s) %s do not EXIST in this tree. A rule that "
            "resolves a path against the sync's list without checking the path is real is "
            "satisfied by any plausible-looking string under a stripped prefix - "
            "`infrastructure/there-is-no-such-file-anywhere.yaml` resolves perfectly. "
            "Reason given: %r" % (job_id, ", ".join(c for c, _ in unreal), reason))
    else:
        bad("%s: the exemption cites %s, and the sync strips NONE of them. A step that reads a "
            "path the mirror HAS can run there, so this divergence needs a different "
            "justification - or the sync needs to strip what the reason claims it does. "
            "Reason given: %r" % (job_id, ", ".join(c for c in cited), reason))

if resolved_by_path < 1:
    bad("no parity exemption was resolved through a stripped path; every one took the escape "
        "hatch, so rule 3 checked nothing about the sync's exclude list")
else:
    ok("%d parity exemption(s) resolved against the sync's own exclude list (anti-vacuity)"
       % resolved_by_path)

for job_id in NO_PATH_GROUND:
    if job_id not in parity_exempt:
        bad("%r is listed as having no structural path, but it is not a parity exemption at all; "
            "the entry is dead" % job_id)

print("")
if failures:
    print("FAIL: %d violation(s)" % failures)
    sys.exit(1)
print("PASS: community twins are byte-identical, every replayable community job is replayed, "
      "and every parity exemption rests on a checked ground - a real path the sync strips, "
      "or test-summary's diverging `needs`")
PY
