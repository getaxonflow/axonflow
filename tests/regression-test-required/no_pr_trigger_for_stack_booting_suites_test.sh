#!/usr/bin/env bash
# Regression guard: a stack-booting suite has NO pull_request trigger.
#
# THE BUG CLASS, AND THE TWO FAILED FIXES BEFORE THIS ONE.
# On 2026-09-01 this repository billed ~17,800 Actions minutes in one day; 56%
# of it was 56 suites that each boot a compose stack (~10 billable minutes)
# running on every push of every PR whose diff touched their `paths:`.
#
#   Attempt 1 (2026-09-03, #3679): gate them behind a `ci:e2e` PR label.
#   Attempt 2 (2026-09-03, #3683): plus skip while the PR is a draft.
#   Measured result of both: 129 billable minutes per push before, 133 after.
#   ZERO. Eleven of thirteen PRs applied the label within seconds of opening,
#   and drafts were flipped to ready in about two minutes (#3692 18:22->18:24,
#   #3734 opened and ready in the same minute).
#
# OPT-IN CANNOT RESTRAIN SPEND WHEN THE PERSON CHOOSING DOES NOT PAY FOR IT.
# A worker wants their change verified; the label costs them nothing and buys
# confidence; applying it is always rational. Both gates were decoration, and
# the process documents updated alongside them (BRIEF_TEMPLATE.md,
# MASTER_TRACKER_PLAYBOOK.md, internal-docs#118) changed nothing either,
# because a document is advice.
#
# So the choice is gone: these suites have no `pull_request` trigger at all.
# They run post-merge - nightly-e2e.yml against main by what changed, release
# tags, manual dispatch, and the merge queue where declared. This test refuses
# to let a PR path come back, by label, by draft clause, or by a fresh copy of
# an old template.
#
# WHAT THIS PINS:
#   1. No workflow that boots a stack in a `run:` step declares
#      `pull_request` (or `pull_request_target`), unless it is on the ALLOW
#      list below with a measured reason.
#   2. Every such workflow keeps a way to be run: `workflow_dispatch` (so the
#      nightly can reach it) and at least one automatic trigger.
#   3. No workflow anywhere gates a job on `ci:e2e` / `ci:full`. Those labels
#      are retired; a gate referencing them would be a silent no-op that reads
#      like a control.
#   4. In test.yml, the four heavy lanes carry `github.event_name !=
#      'pull_request'` as a top-level conjunct, and the ordinary unit lanes do
#      NOT (the PR tier must keep running unit tests).
#   5. Floors: >= 60 stack-booting workflows censused, >= 60 booting jobs
#      recognised; below either, the selector stopped seeing the tree.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

# Workflows that invoke compose or a runtime-e2e script but are not the
# expensive stack-booting tier, with the measured per-run cost that says so:
#   build-community.yml        image build feeding the gha layer cache, ~1 min
#   validate-version-alignment greps compose files, seconds
#   infra-validation.yml       CFN/pytest lanes on infra paths; its one
#                              image-building job is separately post-merge
#   definition-of-done.yml     lints the runtime-e2e tree, boots nothing, ~1 min
#   partner-name-denylist.yml  grep over the tree incl. compose, ~1 min
#   sdk-smoke-tests.yml        on: [merge_group, workflow_dispatch] - it has NO
#                              pull_request trigger, so it is not on the PR tier
#                              at all and `Smoke Test Summary` is not a required
#                              context. Exempt from the scoping rule only
#                              because its detect-changes job already scopes the
#                              smoke job; the ~12 min posture job runs unscoped
#                              on every entry, which is a known fixed cost
#   wait-for-stack-gate-e2e.yml tests the readiness script itself, ~3 min
#   nightly-e2e.yml            the dispatcher
#   self-hosted-canary.yml     proves the AWS runner host; dispatch/branch only
#   sync-community-repo.yml    operator-run mirror sync, workflow_dispatch only
ALLOW="self-hosted-canary.yml sync-community-repo.yml build-community.yml validate-version-alignment.yml infra-validation.yml definition-of-done.yml partner-name-denylist.yml sdk-smoke-tests.yml wait-for-stack-gate-e2e.yml nightly-e2e.yml"

out=$(python3 - "$ALLOW" <<'PY'
import glob, io, re, sys, yaml
allow = set(sys.argv[1].split())
BOOTS = re.compile(r"docker[ -]compose|runtime-e2e/\S+\.(sh|py)")
problems, censused, boot_jobs = [], 0, 0
label_refs = []
for f in sorted(glob.glob('.github/workflows/*.yml')):
    base = f.split('/')[-1]
    text = io.open(f, encoding='utf-8').read()
    d = yaml.safe_load(text)
    if not isinstance(d, dict):
        continue
    jobs = d.get('jobs') or {}
    # rule 3, every workflow: no live gate on the retired labels
    for jn, j in jobs.items():
        cond = str((j or {}).get('if', ''))
        if "'ci:e2e'" in cond or "'ci:full'" in cond:
            label_refs.append(f"{base}: job '{jn}' still gates on a retired label")
    booting = [jn for jn, j in jobs.items()
               if any(BOOTS.search(str((s or {}).get('run', '')))
                      for s in ((j or {}).get('steps') or []))]
    if not booting or base in allow:
        continue
    censused += 1
    boot_jobs += len(booting)
    on = d.get('on') or d.get(True) or {}
    if not isinstance(on, dict):
        problems.append(f"{base}: unparseable on: block")
        continue
    for ev in ('pull_request', 'pull_request_target'):
        if ev in on:
            problems.append(f"{base}: declares `{ev}` and boots a stack in job(s) {', '.join(booting)}")
    if 'workflow_dispatch' not in on:
        problems.append(f"{base}: needs workflow_dispatch: so nightly-e2e.yml can reach it")
    if not ({'push', 'merge_group', 'schedule'} & set(on)):
        problems.append(f"{base}: has no automatic trigger left - it would never run")
print(censused); print(boot_jobs); print('\n'.join(problems + label_refs))
PY
)
censused=$(printf '%s\n' "$out" | sed -n 1p)
boot_jobs=$(printf '%s\n' "$out" | sed -n 2p)
problems=$(printf '%s\n' "$out" | tail -n +3 | sed '/^$/d')

if [ "${censused:-0}" -lt 60 ] || [ "${boot_jobs:-0}" -lt 60 ]; then
  echo "FAIL: censused ${censused:-0} stack-booting workflows / ${boot_jobs:-0} booting jobs (floors 60 / 60)"
  exit 1
fi
echo "ok: censused ${censused} stack-booting workflows (${boot_jobs} booting jobs)"

if [ -n "$problems" ]; then
  echo "FAIL: the post-merge suite tier drifted back toward pull_request:"
  printf '%s\n' "$problems" | sed 's/^/  /'
  echo ""
  echo "A compose stack is ~10 billable minutes per run and 63 of these ran on"
  echo "every push. Two opt-in gates (a PR label, a draft clause) cut exactly"
  echo "zero, because everyone opted in. These suites run post-merge:"
  echo "  on: { push: {tags: [v*]}, workflow_dispatch: }"
  echo "and nightly-e2e.yml dispatches them against main when their paths"
  echo "change. If a suite is genuinely cheap, put it on ALLOW in this test"
  echo "with its measured per-run minutes."
  exit 1
fi
echo "ok: no stack-booting workflow declares pull_request; every one is dispatchable and reachable"

# --- rule 4: test.yml's heavy lanes are post-merge, the unit lanes are not ---
tsout=$(python3 - <<'PY'
import io, re, yaml
d = yaml.safe_load(io.open('.github/workflows/test.yml', encoding='utf-8'))
heavy = {'unit-tests-enterprise-realpg', 'community-mirror-simulation', 'race-detector', 'integration-tests'}
CONJ = "github.event_name != 'pull_request'"
def conjuncts(expr):
    expr = re.sub(r'\s+', ' ', str(expr).replace('\n', ' ')).strip()
    depth, cur, parts, q = 0, [], [], None
    i = 0
    while i < len(expr):
        c = expr[i]
        if q:
            cur.append(c)
            if c == q: q = None
        elif c in ("'", '"'): q = c; cur.append(c)
        elif c == '(': depth += 1; cur.append(c)
        elif c == ')': depth -= 1; cur.append(c)
        elif depth == 0 and expr.startswith('||', i):
            return []          # a top-level OR guarantees nothing
        elif depth == 0 and expr.startswith('&&', i):
            parts.append(''.join(cur).strip()); cur = []; i += 2; continue
        else: cur.append(c)
        i += 1
    parts.append(''.join(cur).strip())
    return parts
bad = []
for jn, j in d['jobs'].items():
    has = CONJ in conjuncts((j or {}).get('if', ''))
    if jn in heavy and not has:
        bad.append(f"heavy lane '{jn}' must carry `{CONJ}` as a top-level && conjunct")
    if jn not in heavy and jn != 'detect-changes' and has:
        bad.append(f"lane '{jn}' must NOT be post-merge-only - the PR tier keeps running it")
print('\n'.join(bad))
PY
)
if [ -n "$tsout" ]; then
  echo "FAIL: test.yml tiering drifted:"
  printf '%s\n' "$tsout" | sed 's/^/  /'
  exit 1
fi
echo "ok: test.yml runs exactly the four heavy lanes post-merge only"

# --- the nightly half exists and selects by a PROPERTY, not a marker --------
if [ ! -f .github/workflows/nightly-e2e.yml ] || [ ! -f .github/scripts/nightly-e2e-dispatch.py ]; then
  echo "FAIL: nightly-e2e.yml / nightly-e2e-dispatch.py missing - the suites would have NO coverage"
  exit 1
fi
# Marker-based selection is refused in CODE (the docstring may narrate the
# history). A grep over the whole file would match that prose, so this looks
# at non-comment lines only.
if python3 - <<'PY'
import io, sys
code = [l for l in io.open('.github/scripts/nightly-e2e-dispatch.py')
        if not l.lstrip().startswith('#')]
src = ''.join(code)
head = src.split('"""')
body = head[0] + ''.join(head[2:]) if len(head) > 2 else src
sys.exit(0 if ("GATE_MARKERS" in body or "'ci:e2e'" in body) else 1)
PY
then
  echo "FAIL: the dispatcher selects by a retired label marker in code - deleting the gates would empty the nightly set"
  exit 1
fi
if ! grep -q 'def in_nightly_set' .github/scripts/nightly-e2e-dispatch.py; then
  echo "FAIL: the dispatcher has no property-based selector"
  exit 1
fi
# POSITIVE CONTROL, the half a structural check cannot give: actually run the
# selector and require it to find the fleet. A selector that silently matches
# nothing is the failure this whole test exists to prevent.
selected=$(python3 .github/scripts/nightly-e2e-dispatch.py --dry-run --all 2>/dev/null \
           | sed -n 's/.*stack-booting workflows: \*\*\([0-9]*\)\*\*.*/\1/p')
if [ "${selected:-0}" -lt 60 ]; then
  echo "FAIL: the nightly dispatcher selects only ${selected:-0} workflows (expected >= 60) - the suites would have no coverage"
  exit 1
fi
echo "ok: nightly dispatcher selects ${selected} workflows by property, no marker in code"

# Every suite in the nightly set must appear in the path manifest, under
# `suites:` (its recovered `paths:` filter) or `unconditional:` (with a
# reason). Removing the PR trigger deleted those filters from the workflows;
# a suite missing from both lists fires every night unnoticed.
manifest=$(python3 - <<'PY'
import glob, io, re, yaml
man = yaml.safe_load(io.open('.github/nightly-suite-paths.yml', encoding='utf-8')) or {}
known = set(man.get('suites') or {}) | set(man.get('unconditional') or {})
BOOTS = re.compile(r"docker[ -]compose|runtime-e2e/\S+\.(sh|py)")
missing = []
for f in sorted(glob.glob('.github/workflows/*.yml')):
    d = yaml.safe_load(io.open(f, encoding='utf-8'))
    if not isinstance(d, dict):
        continue
    on = d.get('on') or d.get(True) or {}
    if not isinstance(on, dict) or 'pull_request' in on or 'workflow_dispatch' not in on:
        continue
    jobs = d.get('jobs') or {}
    if not any(BOOTS.search(str((s or {}).get('run', '')))
               for j in jobs.values() for s in ((j or {}).get('steps') or [])):
        continue
    b = f.split('/')[-1]
    if b not in known:
        missing.append(b)
# anti-vacuity: the manifest must actually describe the fleet
if len(man.get('suites') or {}) < 50:
    missing.append(f"MANIFEST TOO SMALL: {len(man.get('suites') or {})} suites with paths (expected >= 50)")

# ...AND EVERY VALUE MUST BE USABLE, not merely present. Membership alone was
# checked until 2026-09-04, when the same manifest started scoping the MERGE
# QUEUE as well as the nightly: an empty list, a list of only negations, or a
# non-list would then make a suite dark in BOTH, silently. `suite-relevant.py`
# treats a falsy list as "no entry" and fails open, but an all-negated or
# malformed list reaches the matcher and matches nothing, which is a silent
# skip in the queue - the one direction that merges untested code.
for name, paths in (man.get('suites') or {}).items():
    if not isinstance(paths, list) or not paths:
        missing.append(f"{name}: manifest value is empty or not a list ({paths!r}) - "
                       f"the suite would be dark in the queue AND the nightly")
        continue
    positive = [p for p in paths if not str(p).startswith('!')]
    if not positive:
        missing.append(f"{name}: manifest lists only negations, so it matches nothing - "
                       f"a silent skip in the merge queue")
    for p in paths:
        if not isinstance(p, str) or not p.strip():
            missing.append(f"{name}: manifest contains a blank or non-string path ({p!r})")
for name, reason in (man.get('unconditional') or {}).items():
    if not isinstance(reason, str) or len(reason.strip()) < 12:
        missing.append(f"{name}: unconditional entry needs a reason, not {reason!r} - "
                       f"'unconditional' costs job-minutes on every entry forever")
print('\n'.join(missing))
PY
)
if [ -n "$manifest" ]; then
  echo "FAIL: nightly path manifest is out of sync:"
  printf '%s\n' "$manifest" | sed 's/^/  /'
  echo ""
  echo "Add the suite to .github/nightly-suite-paths.yml under suites: with the"
  echo "files its correctness depends on, or under unconditional: with a reason."
  exit 1
fi
echo "ok: every nightly-set suite is described in the path manifest"

# --- the merge queue must be SCOPED, or it cannot finish an entry ----------
# A queue build with every suite unscoped is 742 job-minutes, ~93 wall-minutes
# on 8 runner slots, past suite-gate's deadline AND the ruleset's 60-minute
# check_response_timeout. That left no working configuration: advisory meant a
# red suite merged, required meant every entry timed out. `merge_group` takes
# no `paths:` filter, so each suite carries a `relevant` job (the reusable
# .github/workflows/suite-relevant.yml) and its booting jobs gate on that
# job's output. Without this rule the scoping silently regresses one copied
# template at a time and the queue goes back to being unfinishable.
#
# ALLOW, with the reason each is exempt:
#   build-community.yml   its own detect-changes already scopes it, ~1 min
#   definition-of-done.yml  lints the runtime-e2e tree; the compose match is a
#                         grep pattern, it boots nothing
#   sdk-smoke-tests.yml   detect-changes scopes the smoke job; the posture job
#                         is one suite at ~12 min, accepted unscoped. It has no
#                         pull_request trigger, so nothing here runs per-push
SCOPE_ALLOW="build-community.yml definition-of-done.yml sdk-smoke-tests.yml"
scope_out=$(python3 - "$SCOPE_ALLOW" <<'PY'
import glob, io, re, sys, yaml
allow = set(sys.argv[1].split())
BOOTS = re.compile(r"docker[ -]compose|runtime-e2e/\S+\.(sh|py)")
problems, censused, gated = [], 0, 0
for f in sorted(glob.glob('.github/workflows/*.yml')):
    base = f.split('/')[-1]
    d = yaml.safe_load(io.open(f, encoding='utf-8'))
    if not isinstance(d, dict):
        continue
    on = d.get('on') or d.get(True) or {}
    if not isinstance(on, dict) or 'merge_group' not in on:
        continue
    jobs = d.get('jobs') or {}
    booting = [jn for jn, j in jobs.items()
               if any(BOOTS.search(str((s or {}).get('run', '')))
                      for s in ((j or {}).get('steps') or []))]
    if not booting or base in allow:
        continue
    censused += 1
    if 'relevant' not in jobs:
        problems.append(f"{base}: no `relevant` job - the queue would run it on every entry")
        continue                      # NOTE: skips the `gated += 1` below
    rel = jobs['relevant'] or {}
    if 'suite-relevant.yml' not in str(rel.get('uses', '')):
        problems.append(f"{base}: `relevant` does not call the shared suite-relevant.yml")
    if str(rel.get('with', {}).get('suite')) != base:
        problems.append(f"{base}: `relevant` passes suite={rel.get('with', {}).get('suite')!r}, "
                        f"so it would apply another suite's paths")
    ungated = [b for b in booting
               if "needs.relevant.outputs.relevant == 'true'" not in str(jobs[b].get('if', ''))]
    if ungated:
        problems.append(f"{base}: booting job(s) {ungated} do not gate on the relevance output")
    for b in booting:
        needs = jobs[b].get('needs') or []
        needs = [needs] if isinstance(needs, str) else list(needs)
        if 'relevant' not in needs:
            problems.append(f"{base}: job '{b}' gates on needs.relevant but does not `needs: [relevant]`")
        if 'cancelled()' not in str(jobs[b].get('if', '')):
            problems.append(f"{base}: job '{b}' needs a skipped job without `!cancelled()`, so it "
                            f"would skip on every non-merge_group event too")
    # REACHED ONLY IF EVERY CHECK ABOVE RAN. `censused` counts workflows
    # ENTERED, `gated` counts workflows that reached the end of the body, so
    # any `continue` - including one added later that forgets to report a
    # problem - makes the two diverge. Deriving `gated` from the problem list
    # instead was a TAUTOLOGY: a silent `continue` appends no problem, so the
    # counts agreed and the mutant survived. Measured, not assumed.
    gated += 1
print(censused); print(gated); print('\n'.join(problems))
PY
)
scope_censused=$(printf '%s\n' "$scope_out" | sed -n 1p)
scope_gated=$(printf '%s\n' "$scope_out" | sed -n 2p)
scope_problems=$(printf '%s\n' "$scope_out" | tail -n +3 | sed '/^$/d')
if [ "${scope_censused:-0}" -lt 60 ]; then
  echo "FAIL: censused only ${scope_censused:-0} stack-booting merge_group workflows (floor 60)"
  exit 1
fi
# WIRE THE COUNT, or do not compute it. `scope_gated` was assigned here and
# never read - a check whose result nothing consumes, which is the class that
# let a shared cache be deleted under a live `tar` on 2026-09-04 (the handle
# check ran; the `rm` was not conditional on it). Asserting gated == censused
# is an INDEPENDENT cross-check on the problem collector itself: if it ever
# silently skipped a workflow, the counts diverge even though the problem list
# is empty.
if [ "${scope_gated:-0}" -ne "${scope_censused:-0}" ] && [ -z "$scope_problems" ]; then
  echo "FAIL: ${scope_gated} of ${scope_censused} stack-booting merge_group workflows"
  echo "      counted as scoped, yet no problem was reported - the problem"
  echo "      collector skipped one, so this guard is not seeing the fleet."
  exit 1
fi
if [ -n "$scope_problems" ]; then
  echo "FAIL: the merge queue is not scoped, so an entry cannot finish:"
  printf '%s\n' "$scope_problems" | sed 's/^/  /'
  echo ""
  echo "Every stack-booting merge_group workflow needs a \`relevant\` job calling"
  echo "./.github/workflows/suite-relevant.yml with its OWN filename, and its"
  echo "booting jobs must \`needs: [relevant]\` and carry"
  echo "  if: \"!cancelled() && (github.event_name != 'merge_group' || needs.relevant.outputs.relevant == 'true')\""
  exit 1
fi
echo "ok: all ${scope_censused} stack-booting merge_group workflows are relevance-scoped"

# --- a job with a PINNED host port cannot run on the shared fleet ----------
# MEASURED, not theorised: the self-hosted fleet is 8 runners sharing ONE
# Docker daemon and one host network. A job declaring `services:` with a
# pinned host port (`5432:5432`) works on GitHub-hosted runners, where every
# job gets its own machine, and FAILS on the fleet the moment two such jobs
# overlap - "Bind for 0.0.0.0:5432 failed: port is already allocated", which
# reds the required Test Summary. Nine jobs hit this on the first real run.
#
# Recovering them onto the fleet needs per-runner network isolation (a
# Docker-in-Docker runner per slot). Until that exists, this rule keeps the
# combination out of the tree, because the failure is intermittent - it needs
# two jobs to overlap - so it will not reliably show up on the PR that
# introduces it.
port_out=$(python3 - <<'PY'
import glob, io, yaml
problems, censused = [], 0
for f in sorted(glob.glob('.github/workflows/*.yml')):
    d = yaml.safe_load(io.open(f, encoding='utf-8'))
    if not isinstance(d, dict):
        continue
    for jn, j in (d.get('jobs') or {}).items():
        j = j or {}
        pinned = [p for sv in (j.get('services') or {}).values()
                  for p in ((sv or {}).get('ports') or [])
                  if isinstance(p, str) and ':' in p]
        if not pinned:
            continue
        censused += 1
        if 'self-hosted' in str(j.get('runs-on', '')):
            problems.append(f"{f.split('/')[-1]}: job '{jn}' pins host port(s) {pinned} "
                            f"AND runs on the shared self-hosted fleet - concurrent jobs "
                            f"will collide on those ports")
print(censused)
print('\n'.join(problems))
PY
)
port_censused=$(printf '%s\n' "$port_out" | sed -n 1p)
port_problems=$(printf '%s\n' "$port_out" | tail -n +2 | sed '/^$/d')
# Anti-vacuity: 9 such jobs exist today. A census of 0 means the selector
# stopped seeing `services:` blocks, not that the tree became clean.
if [ "${port_censused:-0}" -lt 5 ]; then
  echo "FAIL: censused only ${port_censused:-0} jobs pinning a host port (expected >= 5)"
  exit 1
fi
if [ -n "$port_problems" ]; then
  echo "FAIL: a pinned host port cannot share the self-hosted fleet:"
  printf '%s\n' "$port_problems" | sed 's/^/  /'
  echo ""
  echo "Either keep the job on ubuntu-latest, or stop pinning the host port and"
  echo "read the mapped one from \`job.services.<id>.ports['5432']\`."
  exit 1
fi
echo "ok: all ${port_censused} pinned-host-port jobs are on GitHub-hosted runners"

# --- jobs that must stay GitHub-hosted for a measured reason ---------------
# The pinned-port rule above is DERIVED - a `services:` port is a property of
# the job. This one cannot be: "this job measures wall-clock time" has no
# structural signature, so it is a NAMED list with a measured reason each.
# That is weaker than a derived rule and is used only where nothing can be
# derived; the cost of getting it wrong is a red lane, not a bad merge.
#
#   risk-scorer-tests.yml :: tests
#     asserts CI_REGRESSION_BOUND_MS = 250 (test_latency.py), whose own
#     docstring calibrates that to a GitHub-hosted runner. The fleet gives
#     ~2 vCPU per slot under contention and measured p99 269.8ms.
#   risk-scorer-tests.yml :: container-smoke
#     boots a container ("Refuse to start without a secret") on a Docker
#     daemon shared by 8 runners; boot timing and port availability are both
#     perturbed.
# The five Trivy jobs joined this list on 2026-09-05 after drain 10 ejected on
# one of them. The aquasecurity/trivy-action installs ONE binary at a shared
# path - measured on the host, exactly one at
# /home/runner/.local/bin/trivy-bin/trivy, with all eight slots sharing
# /home/runner - so two slots installing at once leaves one exec'ing a
# partially written file: exit 126, "cannot execute", on -29-7 while the same
# scan passed on -29-3 in the same minute with the same action pin. The action
# exposes `cache-dir` but no input for the binary path, so the thing that
# actually raced cannot be isolated per slot from the workflow. And
# `Security Scan Summary` is REQUIRED, so the race blocks every merge.
# DRAIN 12, 2026-09-06: the Real-PG lane joins them, and it is the THIRD
# required context lost to fleet contention after `Migrations apply cleanly`
# (drain 4) and these Trivy scans (drain 10). `test.yml`'s
# unit-tests-enterprise-realpg feeds `Test Summary`, which is REQUIRED, and on
# the fleet two packages hit go's own `-timeout 20m` - platform/agent
# 1200.158s and platform/orchestrator 1200.344s (job 101415833014,
# aws-ip-10-1-2-29-2) - against 899.7s and 515.7s for the same packages on a
# hosted entry the same night. General slowness with eight slots busy, not a
# hang; the job's 75-minute cap was never the binding one.
#
# Raising `-timeout` was the alternative and is worse: the multiplier is a
# function of how many siblings share the host, so it grows with every suite
# added and buys a slower failure rather than a fix.
# #3791 STAGE ONE, 2026-09-06: 28 rollups and trivial feeders join them. None
# of these does real work - they read other jobs' results, or grep the tree -
# but each feeds a REQUIRED context, so while one waits for a fleet slot behind
# the suites it blocks a merge having tested nothing. Measured: #3795's
# `Test Summary` sat QUEUED from 07:07Z behind 57 queued fleet runs with every
# unit job already green. A few seconds of hosted time is the correct price for
# a gate; slot-time is what the suites need.
#
# DELIBERATELY NOT MOVED, so the split is legible: the heavy lanes (Real-PG is
# already hosted for its own reason, race-detector, the mirror simulation,
# golangci-lint, CodeQL) and every stack-booting suite stay on the fleet. That
# is the spend the fleet was bought for. compile-java-examples also stays - it
# looks trivial by step count but it runs setup-java and compiles.
FLEET_FORBIDDEN="risk-scorer-tests.yml:tests risk-scorer-tests.yml:container-smoke \
security.yml:trivy-filesystem-scan security.yml:trivy-config-scan \
security.yml:trivy-secret-scan security.yml:trivy-docker-agent \
security.yml:trivy-docker-orchestrator \
test.yml:unit-tests-enterprise-realpg \
build.yml:merge \
build.yml:build-summary \
build.yml:detect-changes \
build.yml:plan \
test.yml:test-summary \
test.yml:detect-changes \
test-community.yml:test-summary \
test-community.yml:detect-changes \
lint.yml:lint-summary \
lint.yml:detect-changes \
lint.yml:org-column-guard \
lint.yml:hitl-queue-choke-point \
lint.yml:docker-rm-volumes \
lint.yml:trap-handlers-exit \
security.yml:security-summary \
security.yml:detect-changes \
security.yml:dependency-review \
definition-of-done.yml:lint-no-mocks-in-runtime-e2e \
definition-of-done.yml:lint-readiness-gate-shape \
definition-of-done.yml:lint-runtime-e2e-executors \
definition-of-done.yml:runtime-e2e-required \
migrations-gate.yml:detect-changes \
tier-gate-contract.yml:summary \
sdk-smoke-tests.yml:smoke-test-summary \
sdk-smoke-tests.yml:detect-changes \
java-examples-compile.yml:java-examples-summary \
java-examples-compile.yml:detect-changes \
e2e-tests.yml:portal-golden-flows-summary \
regression-test-required.yml:check-regression-test"
ff_out=$(python3 - "$FLEET_FORBIDDEN" <<'PY'
import io, sys, yaml
problems, checked = [], 0
for spec in sys.argv[1].split():
    base, jid = spec.split(':', 1)
    path = '.github/workflows/' + base
    try:
        d = yaml.safe_load(io.open(path, encoding='utf-8'))
    except OSError:
        problems.append(f"{spec}: {path} does not exist - the entry is dead and hides nothing")
        continue
    job = ((d or {}).get('jobs') or {}).get(jid)
    if not isinstance(job, dict):
        problems.append(f"{spec}: job '{jid}' not found - the entry is dead and hides nothing")
        continue
    checked += 1
    if 'self-hosted' in str(job.get('runs-on', '')):
        problems.append(f"{spec}: is on the self-hosted fleet, which perturbs what it measures")
print(checked)
print('\n'.join(problems))
PY
)
ff_checked=$(printf '%s\n' "$ff_out" | sed -n 1p)
ff_problems=$(printf '%s\n' "$ff_out" | tail -n +2 | sed '/^$/d')
# Anti-vacuity BOTH ways: every entry must name a real job (a dead entry
# protects nothing and rots silently), and the list must not be empty.
if [ "${ff_checked:-0}" -lt 2 ]; then
  echo "FAIL: only ${ff_checked:-0} of the fleet-forbidden entries name a real job"
  printf '%s\n' "$ff_problems" | sed 's/^/  /'
  exit 1
fi
if [ -n "$ff_problems" ]; then
  echo "FAIL: a job that must stay GitHub-hosted is on the fleet:"
  printf '%s\n' "$ff_problems" | sed 's/^/  /'
  echo ""
  echo "The fleet shares 16 vCPU and one Docker daemon across 8 runners, so a"
  echo "wall-clock bound or a container boot measures the topology. Keep the"
  echo "job on ubuntu-latest, or remove it from FLEET_FORBIDDEN with evidence"
  echo "that what it measures is no longer perturbed."
  exit 1
fi
echo "ok: all ${ff_checked} fleet-forbidden jobs are on GitHub-hosted runners"

# --- no two FLEET jobs may share a fixed absolute temp path ----------------
# MEASURED, and it is the sixth instance of one class. `test.yml` and
# `test-community.yml` both have a `unit-tests-platform-packages` job, both on
# the fleet, and both did `go test ... | tee /tmp/platform-packages.log` then
# counted verdicts by grepping that file. Two concurrent writers on the same
# host interleave, so the count came back 87 against 84 packages selected and
# the census guard failed a run in which EVERY TEST PASSED. `/tmp/keygen` had
# the same shape across three suites, one of which was the Agentgateway
# failure on the same entry.
#
# GitHub-hosted runners give every job its own VM, so a fixed /tmp path is
# private there and this cannot happen. On this fleet, 8 slots share /tmp.
# `$RUNNER_TEMP` is per-job on both, which is why it is the fix rather than a
# per-slot prefix.
#
# Only SHARED paths fail: a fixed path used by exactly one fleet job has one
# writer and is safe, and there are 15 of those. Sharing is the defect, not
# the fixed path itself.
tmp_out=$(python3 - <<'PY'
import glob, io, re, collections, yaml
hits = collections.defaultdict(set)
fleet_jobs = 0
for f in sorted(glob.glob('.github/workflows/*.yml')):
    d = yaml.safe_load(io.open(f, encoding='utf-8'))
    if not isinstance(d, dict):
        continue
    for jn, j in (d.get('jobs') or {}).items():
        if 'self-hosted' not in str((j or {}).get('runs-on', '')):
            continue
        fleet_jobs += 1
        blob = '\n'.join(str((s or {}).get('run', '')) for s in ((j or {}).get('steps') or []))
        # (?<!RUNNER_TEMP) so the fix itself is not flagged
        for m in re.finditer(r'(?<!RUNNER_TEMP)/tmp/[a-zA-Z0-9._-]+', blob):
            hits[m.group(0)].add(f.split('/')[-1] + '::' + jn)
problems = [f"{p} is written by {len(v)} fleet jobs: {sorted(v)}"
            for p, v in sorted(hits.items()) if len(v) > 1]
print(fleet_jobs)
print('\n'.join(problems))
PY
)
tmp_fleet_jobs=$(printf '%s\n' "$tmp_out" | sed -n 1p)
tmp_problems=$(printf '%s\n' "$tmp_out" | tail -n +2 | sed '/^$/d')
# Anti-vacuity: 100+ jobs run on the fleet today. A census of 0 means the
# selector stopped recognising `runs-on`, not that the tree became clean.
# Was 50. The release-window pin (#3791) moved the 66 runtime-e2e suite jobs
# to ubuntu-latest, leaving 35 fleet jobs; 25 still catches a scan that has
# stopped seeing the fleet. THE REVERT RESTORES BOTH TOGETHER.
if [ "${tmp_fleet_jobs:-0}" -lt 25 ]; then
  echo "FAIL: censused only ${tmp_fleet_jobs:-0} fleet jobs (expected >= 25)"
  exit 1
fi
if [ -n "$tmp_problems" ]; then
  echo "FAIL: two or more fleet jobs share a fixed temp path:"
  printf '%s\n' "$tmp_problems" | sed 's/^/  /'
  echo ""
  echo "8 runner slots share /tmp on this host, so concurrent jobs interleave."
  echo "Use \"\$RUNNER_TEMP/<name>\", which is per-job on both hosted and"
  echo "self-hosted runners. A fixed path used by exactly ONE fleet job has a"
  echo "single writer and is fine."
  exit 1
fi
echo "ok: no fixed temp path is shared between fleet jobs (${tmp_fleet_jobs} fleet jobs censused)"
