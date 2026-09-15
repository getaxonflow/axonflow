#!/usr/bin/env bash
# pr_board_hosted_cost_test.sh - the pull-request board's hosted cost per push,
# computed from the workflow files, and a ceiling on how it can grow.
#
# THE BILL (W3-J, measured 2026-09-08..11 over the pull_request tier): 30,064
# hosted minutes in four days, ~$1,353 per 30 days at the billed $0.006/min. Most
# of it was NOT work. GitHub bills every hosted JOB rounded UP to a whole minute,
# so the one-minute gates, change detectors, censuses and summaries around the
# real lanes billed more than most of the lanes they surround. The fix was to
# fold, scope and move them; this test keeps them folded, scoped and moved.
#
# WHAT IT COUNTS. For every workflow that triggers on pull_request, the jobs that
# can run on a pull_request event (a job whose own `if:` excludes the event, or
# the repository, as a top-level conjunct is unreachable; so is one whose every
# `needs:` is unreachable and whose `if:` carries no always()/!cancelled()/
# failure()), and of those, the ones that resolve to a GitHub-HOSTED runner on
# this repository (through lib/runs_on_labels.py, the resolver every fleet
# census shares). A static count is an upper bound on how many hosted jobs run
# per push - a detector can still skip some at runtime - and each one that runs
# bills at least a minute. A matrix is counted from its lists, or from its
# `include:` entries when it has only those; a matrix given by an EXPRESSION
# counts as one, because its size is not in the file.
#
# WHAT IT PINS:
#   1. A pull_request workflow with NO `paths:` filter fires on every push, so it
#      may reach at most CAP hosted jobs - or be EXEMPT below with its count
#      PINNED EXACTLY and the reason stated. A pin that stops matching fails in
#      BOTH directions: growth is the regression this test exists for, and a
#      drop means the reason no longer describes the workflow.
#   2. A workflow MEASURED heavy on the pull_request tier (HEAVY below), and every
#      *-e2e.yml, declares no pull_request / pull_request_target trigger. This is
#      where $354 of September went: a trigger removed on main keeps firing from
#      every open branch that predates the removal, so a returning trigger is paid
#      for by every stale branch too. no_pr_trigger_for_stack_booting_suites_test.sh
#      pins the stack-booting class by what it BOOTS; its ALLOW list exempts
#      sdk-smoke-tests.yml by name, so the measured list here closes that gap.
#   3. java-examples-compile.yml's workflow-level pull_request `paths:` equals its
#      change detector's `java-examples` filter, entry for entry. The workflow
#      filter decides whether the gate runs on a PR; the detector decides it in
#      the merge queue, which accepts no paths filter. Two lists that drift
#      would give the two tiers different answers.
#   4. Floors, so a census that stopped seeing the tree cannot pass.
#
# It PRINTS the per-push number either way, which is the figure the brief asked
# for: hosted jobs reachable on every push, and hosted jobs reachable only when a
# path filter matches.
#
# Self-tested first, both directions, over planted workflow files.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.." || exit 1
export PYTHONDONTWRITEBYTECODE=1
export PYTHONPYCACHEPREFIX="$(mktemp -d)"

python3 - <<'PY'
import glob, os, re, sys, tempfile
try:
    import yaml
except ImportError:
    print("FAIL: PyYAML is unavailable; the census cannot run, and a guard that cannot run must not pass")
    sys.exit(1)
sys.path.insert(0, "tests/regression-test-required/lib")
from runs_on_labels import ENTERPRISE, labels_for

CAP = 3
# Each exemption: the hosted-job count reachable on a push, PINNED, and why.
EXEMPT = {
    "test.yml": (7, "the four unit lanes (Agent, Orchestrator, Connectors, Enterprise) declare `services:` on "
                    "pinned host ports that collide on the fleet's one Docker daemon (#3791), and moving them "
                    "needs ~1,550 fleet-min/day the fleet has not got (W3-J item 2, ledger row on #3746); "
                    "detect-changes, the census and the required Test Summary stay hosted because they sit on "
                    "the serial path (#3795)"),
    "security.yml": (6, "the three Trivy scans install one 160 MB binary to a fixed path the fleet's slots would "
                        "share (FLEET_FORBIDDEN) and run only when a manifest changed; Dependency Review runs only "
                        "when a dependency manifest changed; detect-changes and the required Security Scan "
                        "Summary are serial-path"),
    "lint.yml": (4, "detect-changes, the consolidated repository guards (the only thing Lint Summary waits on for "
                    "a PR without Go), the census and the required Lint Summary - all serial or required-path"),
}
HEAVY = {
    "e2e-tests.yml": "Portal E2E, 57 hosted min per run, 419 PR runs 2026-09-01..06",
    "sdk-smoke-tests.yml": "30 hosted min per run, 510 PR runs before 2026-09-07",
    "community-saas-reads-e2e.yml": "7.4 hosted min per run",
}
# *-e2e.yml workflows that legitimately keep a pull_request trigger, each with
# the reason; an entry that stops matching a PR-triggered file fails, so the
# list cannot rot into a blanket.
E2E_ALLOW = {
    "wait-for-stack-gate-e2e.yml": "the readiness gate's own test: on the fleet, path-filtered to the gate "
                                   "script, ~3 fleet minutes and no hosted cost; exempted by "
                                   "no_pr_trigger_for_stack_booting_suites_test.sh for the same reason",
}
OVERRIDE = re.compile(r"always\(\)|!\s*cancelled\(\)|failure\(\)")

def split_top(expr, op):
    parts, depth, cur, i, q = [], 0, [], 0, None
    while i < len(expr):
        c = expr[i]
        if q:
            cur.append(c)
            if c == q: q = None
        elif c in ("'", '"'): q = c; cur.append(c)
        elif c == "(": depth += 1; cur.append(c)
        elif c == ")": depth -= 1; cur.append(c)
        elif depth == 0 and expr.startswith(op, i):
            parts.append("".join(cur)); cur = []; i += len(op); continue
        else: cur.append(c)
        i += 1
    parts.append("".join(cur))
    return parts

def unwrap(e):
    e = e.strip()
    while e.startswith("(") and e.endswith(")"):
        depth = 0
        for k, c in enumerate(e):
            if c == "(": depth += 1
            elif c == ")":
                depth -= 1
                if depth == 0 and k != len(e) - 1:
                    return e
        e = e[1:-1].strip()
    return e

def conjuncts(expr):
    expr = unwrap(re.sub(r"\s+", " ", str(expr)).strip())
    if expr.startswith("${{") and expr.endswith("}}"):
        expr = unwrap(expr[3:-2])
    if not expr or len(split_top(expr, "||")) > 1:
        return []
    out = []
    for part in split_top(expr, "&&"):
        part = unwrap(part)
        out.extend(conjuncts(part) if len(split_top(part, "&&")) > 1 else [part])
    return out

def excluded_on_pr(cond):
    for c in conjuncts(cond):
        if c == "github.event_name != 'pull_request'":
            return True
        m = re.fullmatch(r"github\.event_name == '([a-z_]+)'", c)
        if m and m.group(1) != "pull_request":
            return True
        m = re.fullmatch(r"github\.repository == '([^']+)'", c)
        if m and m.group(1) != ENTERPRISE:
            return True
    return False

def matrix_size(job):
    matrix = ((job.get("strategy") or {}).get("matrix")) or {}
    if not isinstance(matrix, dict):
        return 1
    axes = [v for k, v in matrix.items() if k not in ("include", "exclude") and isinstance(v, list)]
    if not axes and isinstance(matrix.get("include"), list):
        return max(1, len(matrix["include"]))
    n = 1
    for v in axes:
        n *= max(1, len(v))
    return n

def census(root, exempt, heavy, e2e_allow=None):
    e2e_allow = e2e_allow or {}
    problems, rows, prs, allowed_seen = [], [], 0, set()
    for path in sorted(glob.glob(os.path.join(root, ".github/workflows/*.yml")) + glob.glob(os.path.join(root, ".github/workflows/*.yaml"))):
        base = os.path.basename(path)
        d = yaml.safe_load(open(path, encoding="utf-8"))
        if not isinstance(d, dict):
            continue
        on = d.get("on") or d.get(True) or {}
        if isinstance(on, str): on = {on: None}
        if isinstance(on, list): on = {k: None for k in on}
        pr_events = [e for e in ("pull_request", "pull_request_target") if e in on]
        if pr_events and base in e2e_allow:
            allowed_seen.add(base)
        elif (base in heavy or base.endswith(("-e2e.yml", "-e2e.yaml"))) and pr_events:
            problems.append(f"{base}: declares {pr_events[0]} - {heavy.get(base, 'a stack-booting suite')}; it runs post-merge")
        if "pull_request" not in on:
            continue
        prs += 1
        pr = on.get("pull_request") or {}
        filtered = isinstance(pr, dict) and ("paths" in pr or "paths-ignore" in pr)
        jobs = d.get("jobs") or {}
        reach = set()
        changed = True
        while changed:
            changed = False
            for jn, j in jobs.items():
                if jn in reach: continue
                j = j or {}
                cond = str(j.get("if", ""))
                if excluded_on_pr(cond): continue
                needs = j.get("needs") or []
                needs = [needs] if isinstance(needs, str) else list(needs)
                if needs and not OVERRIDE.search(cond) and not any(n in reach for n in needs): continue
                # always() keeps a job alive past a skipped need, but a conjunct
                # that asks for that need's SUCCESS, or compares one of its
                # outputs, still cannot hold when the need did not run - the
                # shape of build.yml's build and merge, which follow `plan`.
                if any(re.fullmatch(r"needs\.([\w-]+)\.(?:result == 'success'|outputs\.[\w-]+ == '[^']+')", c)
                       and re.fullmatch(r"needs\.([\w-]+)\..*", c).group(1) not in reach
                       for c in conjuncts(cond)):
                    continue
                reach.add(jn); changed = True
        hosted = sum(matrix_size(jobs[jn] or {}) for jn in reach
                     if "self-hosted" not in labels_for((jobs[jn] or {}).get("runs-on"), ENTERPRISE))
        rows.append((base, filtered, hosted, len(reach)))
        if not filtered:
            if base in exempt:
                pin, _ = exempt[base]
                if hosted != pin:
                    problems.append(f"{base}: {hosted} hosted jobs reachable per push, but its exemption pins {pin} - "
                                    "move the job, or update the pin and its reason in the same change")
            elif hosted > CAP:
                problems.append(f"{base}: {hosted} hosted jobs reachable on every push (cap {CAP}) and no paths filter - "
                                "fold them into one job, move the non-serial ones to the fleet, or scope the trigger")
    for base in exempt:
        if not any(r[0] == base and not r[1] for r in rows):
            problems.append(f"{base}: exempted but no longer an unfiltered pull_request workflow - remove the exemption")
    for base in sorted(set(e2e_allow) - allowed_seen):
        problems.append(f"{base}: on E2E_ALLOW but no longer declares a pull_request trigger - remove the entry")
    return problems, rows, prs

def filters_of(step):
    raw = (step.get("with") or {}).get("filters")
    return yaml.safe_load(raw) if isinstance(raw, str) else (raw or {})

def java_problem(root):
    p = os.path.join(root, ".github/workflows/java-examples-compile.yml")
    if not os.path.exists(p):
        return None
    d = yaml.safe_load(open(p, encoding="utf-8"))
    on = d.get("on") or d.get(True) or {}
    trig = ((on.get("pull_request") or {}).get("paths")) or []
    det = []
    for s in ((d.get("jobs") or {}).get("detect-changes") or {}).get("steps") or []:
        det = det or (filters_of(s or {}).get("java-examples") or [])
    if not trig or not det:
        return "java-examples-compile.yml: the workflow's pull_request paths or its detector's java-examples filter is missing"
    if sorted(trig) != sorted(det):
        return (f"java-examples-compile.yml: the pull_request paths {sorted(set(trig) ^ set(det))} differ from the "
                "detector's java-examples filter - the PR tier and the merge queue would disagree about when it runs")
    return None

# ---- self-test, both directions --------------------------------------------
fx = tempfile.mkdtemp(); os.makedirs(os.path.join(fx, ".github/workflows"))
def plant(name, text):
    open(os.path.join(fx, ".github/workflows", name), "w").write(text)
HOSTED4 = "jobs:\n" + "".join(f"  j{i}:\n    runs-on: ubuntu-latest\n    steps: [{{run: 'true'}}]\n" for i in range(4))
plant("unfiltered4.yml", "on: [pull_request]\n" + HOSTED4)
plant("filtered4.yml", "on:\n  pull_request:\n    paths: ['x/**']\n" + HOSTED4)
plant("mixed.yml", "on: [pull_request]\njobs:\n"
      "  a:\n    runs-on: ubuntu-latest\n    steps: [{run: 'true'}]\n"
      "  b:\n    runs-on: [self-hosted, linux, x64, axonflow]\n    steps: [{run: 'true'}]\n"
      "  c:\n    runs-on: ${{ github.repository == 'getaxonflow/axonflow-enterprise' && fromJSON('[\"self-hosted\",\"linux\",\"x64\",\"axonflow\"]') || 'ubuntu-latest' }}\n    steps: [{run: 'true'}]\n"
      "  d:\n    runs-on: ubuntu-latest\n    if: github.event_name != 'pull_request'\n    steps: [{run: 'true'}]\n"
      "  e:\n    runs-on: ubuntu-latest\n    needs: [d]\n    steps: [{run: 'true'}]\n"
      "  f:\n    runs-on: ubuntu-latest\n    needs: [d]\n    if: always()\n    steps: [{run: 'true'}]\n"
      "  g:\n    runs-on: ubuntu-latest\n    if: github.repository == 'getaxonflow/axonflow'\n    steps: [{run: 'true'}]\n"
      "  h:\n    runs-on: ubuntu-latest\n    needs: [d]\n    if: always() && needs.d.result == 'success'\n    steps: [{run: 'true'}]\n")
plant("include-only.yaml", "on: [pull_request]\njobs:\n  m:\n    runs-on: ubuntu-latest\n    strategy:\n      matrix:\n        include: [{a: 1}, {a: 2}, {a: 3}, {a: 4}]\n    steps: [{run: 'true'}]\n")
plant("readiness-e2e.yml", "on:\n  pull_request:\n    paths: ['lib/**']\njobs:\n  s:\n    runs-on: [self-hosted, linux, x64, axonflow]\n    steps: [{run: 'true'}]\n")
plant("sdk-smoke-tests.yml", "on: [pull_request, merge_group]\n" + HOSTED4)
plant("fixture-e2e.yml", "on:\n  pull_request_target:\n  workflow_dispatch:\n" + HOSTED4)
got, rows, _ = census(fx, {}, {"sdk-smoke-tests.yml": "planted heavy"}, {"readiness-e2e.yml": "fixture"})
counts = {r[0]: r[2] for r in rows}
selftest = []
if any(p.startswith("readiness-e2e.yml:") for p in got): selftest.append("an E2E_ALLOW entry was flagged")
dead, _, _ = census(fx, {}, {}, {"readiness-e2e.yml": "fixture", "gone-e2e.yml": "fixture"})
if not any(p.startswith("gone-e2e.yml:") for p in dead): selftest.append("a dead E2E_ALLOW entry was not flagged")
if not any(p.startswith("unfiltered4.yml:") for p in got): selftest.append("4 hosted jobs with no paths filter were not flagged")
if any(p.startswith("filtered4.yml:") for p in got): selftest.append("a paths-filtered workflow was flagged")
if not any(p.startswith("include-only.yaml:") for p in got): selftest.append("a .yaml workflow with an include-only matrix of 4 hosted jobs was not flagged")
if counts.get("mixed.yml") != 2: selftest.append(f"mixed.yml counted {counts.get('mixed.yml')} hosted, want 2 (a, f): fleet, expression, PR-excluded, needs-unreachable, needs-success-of-unreachable and mirror-only jobs must not count")
if not any(p.startswith("sdk-smoke-tests.yml:") for p in got): selftest.append("a heavy workflow with pull_request was not flagged")
if not any(p.startswith("fixture-e2e.yml:") for p in got): selftest.append("an *-e2e.yml with pull_request_target was not flagged")
pinned, _, _ = census(fx, {"unfiltered4.yml": (4, "fixture")}, {})
if any(p.startswith("unfiltered4.yml:") for p in pinned): selftest.append("an exemption pinned at its true count was flagged")
moved, _, _ = census(fx, {"unfiltered4.yml": (5, "fixture")}, {})
if not any("pins 5" in p for p in moved): selftest.append("an exemption whose pin no longer matches was not flagged")
if selftest:
    print("FAIL: the census is wrong before it reads the tree:")
    print("\n".join("  " + s for s in selftest)); sys.exit(1)
print("ok: self-test - unfiltered over the cap, heavy triggers, pin drift all caught; filters, fleet, PR-excluded and unreachable jobs not counted")

# ---- the tree ----------------------------------------------------------------
problems, rows, prs = census(".", EXEMPT, HEAVY, E2E_ALLOW)
jp = java_problem(".")
if jp: problems.append(jp)
always = [r for r in rows if not r[1]]
scoped = [r for r in rows if r[1]]
if prs < 15 or len(always) < 8:
    print(f"FAIL: censused {prs} pull_request workflows ({len(always)} unfiltered); floors 15 / 8 - the census stopped seeing the tree")
    sys.exit(1)
per_push = sum(r[2] for r in always)
print(f"PR board, per push: at most {per_push} GitHub-hosted jobs in {len(always)} unfiltered pull_request workflows, "
      f"each billing at least one minute when it runs; plus up to {sum(r[2] for r in scoped)} in "
      f"{len(scoped)} path-filtered workflows when their paths match.")
for base, _, hosted, reach in sorted(always, key=lambda r: -r[2]):
    if hosted:
        print(f"  {base:34} {hosted} hosted of {reach} reachable" + ("  [exempt, pinned]" if base in EXEMPT else ""))
if problems:
    print("FAIL: the pull-request board's hosted cost drifted:")
    print("\n".join("  " + p for p in problems))
    sys.exit(1)
print(f"ok: every unfiltered pull_request workflow is within {CAP} hosted jobs or pinned; no measured-heavy suite has a PR trigger; the Java filter matches its detector")
PY
