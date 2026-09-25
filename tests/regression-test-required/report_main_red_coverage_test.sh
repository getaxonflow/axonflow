#!/usr/bin/env bash
# report_main_red_coverage_test.sh - every job that runs after the merge ends
# with the main-red reporter (#4041).
#
# THE POPULATION IS DERIVED, NEVER LISTED. A workflow is in it when its runs
# speak for main or for a release - a push to main, a schedule, or a push of a
# tag (#4169) - the rule .github/actions/report-main-red applies at runtime. The
# rule itself lives ONCE, in .github/scripts/add-report-main-red-steps.py
# (`reports_on_the_tracker`, `EXEMPT`, `relevance_exemption`), which this census
# imports; that generator also WRITES the reporter step, and its `--check` runs
# here, so a new workflow without the reporter reds with the command that fixes
# it.
#
# THE COUNT IS ASSERTED EXACTLY, AND IT IS TWO COUNTS. This census syncs to the
# public mirror, where the sync strips every *-e2e.yml. On the enterprise tree
# the selected population must equal SELECTED_ENTERPRISE; on the mirror (no
# sync workflow: it excludes itself) SELECTED_MIRROR. The enterprise run PROVES
# the mirror's number too, by replaying the sync's own rule chain
# (scripts/ci/simulate-community-mirror.sh) over the workflows alone, with a
# planted sync change as its control. Any PR that adds, removes or re-triggers
# a reporting workflow, or changes what the sync carries, moves these numbers in
# the same diff. Before this, the mirror's copy asserted a floor of 15 over the
# 4 workflows it can see, and was red there.
#
# Every job of every such workflow must:
#   - end with `uses: ./.github/actions/report-main-red` under `if: always()`,
#     passing `status: ${{ job.status }}` and `token: ${{ github.token }}`,
#     plus `matrix: ${{ toJSON(matrix) }}` when it has a matrix, so each leg
#     has an issue of its own;
#   - check the repository out before that step, so the local action
#     resolves: with no `path:` for `uses: ./.github/actions/report-main-red`,
#     or with `path: <p>` for `uses: ./<p>/.github/actions/report-main-red`
#     (a fleet job must use its own path, #4182);
#   - hold `issues: write` on its token, from its own permissions or the
#     workflow's. The repository default is read, so a job with neither
#     cannot file anything.
#
# A job-level `uses:` is refused, except a call of suite-relevant.yml whose
# every dependent job runs whatever it answers outside the merge queue
# (`!cancelled()` and `github.event_name != 'merge_group' ||`): then a red
# relevance job cannot hide a suite on main or on a tag (#4169).
#
# EXEMPT, by name and with a reason, and a stale exemption fails: see EXEMPT.
#
# The checker runs against planted workflows first, so each rule is known to
# fail when broken, and against the tree second.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

python3 - "$REPO_ROOT" <<'PY'
import fnmatch
import glob
import os
import re
import sys
import tempfile

import importlib.util
import shutil
import subprocess

import yaml

ROOT = sys.argv[1]
ACTION = "./.github/actions/report-main-red"
GENERATOR = os.path.join(ROOT, ".github/scripts/add-report-main-red-steps.py")
_spec = importlib.util.spec_from_file_location("report_main_red_generator", GENERATOR)
_gen = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_gen)
EXEMPT = _gen.EXEMPT
reports_on_the_tracker = _gen.reports_on_the_tracker
relevance_exemption = _gen.relevance_exemption

# The measured counts, asserted exactly and moved in the same PR as any change
# to the population (2026-09-23, #4169): 20 workflows on main or a schedule plus
# 76 that run on a release tag; the mirror carries 5 of them, build-community.yml
# (exempt) among them.
SELECTED_ENTERPRISE = 97
SELECTED_MIRROR = 5
SYNC_WORKFLOW = os.path.join(ROOT, ".github/workflows/sync-community-repo.yml")
ON_ENTERPRISE = os.path.isfile(SYNC_WORKFLOW)


def action_root(uses):
    """The checkout path a reporter step's `uses` resolves under: "" for
    ./.github/actions/report-main-red, "p" for ./p/.github/actions/report-main-red
    (a fleet job checks the action out under its own path, #4182), None for
    anything else."""
    u = str(uses or "")
    if u == ACTION:
        return ""
    m = re.fullmatch(r"\./([A-Za-z0-9._-]+)/\.github/actions/report-main-red", u)
    return m.group(1) if m else None


resolves_the_action = _gen.resolves_the_action


def problems(path):
    doc = yaml.safe_load(open(path)) or {}
    top = doc.get("permissions")
    out = []
    for name, job in (doc.get("jobs") or {}).items():
        where = f"{os.path.basename(path)}:{name}"
        if "uses" in job:
            out.extend(f"{where}: {p}" for p in relevance_exemption(doc, name))
            continue
        steps = job.get("steps") or []
        if not steps:
            out.append(f"{where} has no steps")
            continue
        last, w = steps[-1], (steps[-1].get("with") or {})
        has_matrix = "matrix" in (job.get("strategy") or {})
        root = action_root(last.get("uses"))
        if root is None:
            out.append(f"{where}: the last step is not the main-red reporter")
        else:
            if str(last.get("if")) != "always()":
                out.append(f"{where}: the reporter does not run under if: always()")
            if w.get("status") != "${{ job.status }}":
                out.append(f"{where}: the reporter is not given status: ${{{{ job.status }}}}")
            if w.get("token") != "${{ github.token }}":
                out.append(f"{where}: the reporter is not given token: ${{{{ github.token }}}}")
            if has_matrix and w.get("matrix") != "${{ toJSON(matrix) }}":
                out.append(f"{where}: a matrix job's reporter is not given matrix: ${{{{ toJSON(matrix) }}}}")
            if not has_matrix and "matrix" in w:
                out.append(f"{where}: a job with no matrix passes one")
        if not any(resolves_the_action(s, root if root is not None else "") for s in steps[:-1]):
            out.append(f"{where}: nothing checks the repository out before the reporter, so the local action cannot resolve")
        perms = job.get("permissions", top)
        if not isinstance(perms, dict) or perms.get("issues") != "write":
            out.append(f"{where}: its token has no issues: write (the repository default is read)")
    return out


# ---- the checker against planted workflows ---------------------------------
GOOD_STEPS = """    steps:
      - uses: actions/checkout@v6
      - run: echo work
      - name: Report
        if: always()
        uses: ./.github/actions/report-main-red
        with:
          status: ${{ job.status }}
          token: ${{ github.token }}
"""
GOOD = "on:\n  schedule:\n    - cron: '0 0 * * 0'\npermissions:\n  contents: read\n  issues: write\njobs:\n  j:\n    runs-on: ubuntu-latest\n" + GOOD_STEPS
RELEVANCE_SUITE = ("on:\n  push:\n    tags: ['v*']\npermissions:\n  contents: read\n  issues: write\njobs:\n"
                   "  relevant:\n    uses: ./.github/workflows/suite-relevant.yml\n    with:\n      suite: s.yml\n"
                   "  s:\n    needs: [relevant]\n"
                   "    if: ${{ !cancelled() && (github.event_name != 'merge_group' || needs.relevant.outputs.relevant == 'true') }}\n"
                   "    runs-on: ubuntu-latest\n" + GOOD_STEPS)
PLANTS = {
    "good": (GOOD, None),
    "not_last": (GOOD + "      - run: echo after\n", "the last step is not the main-red reporter"),
    "no_always": (GOOD.replace("        if: always()\n", ""), "does not run under if: always()"),
    "no_status": (GOOD.replace("          status: ${{ job.status }}\n", ""), "not given status"),
    "no_checkout": (GOOD.replace("      - uses: actions/checkout@v6\n", ""), "nothing checks the repository out"),
    "checkout_elsewhere": (GOOD.replace("      - uses: actions/checkout@v6\n",
                                        "      - uses: actions/checkout@v6\n        with:\n          path: sub\n"),
                           "nothing checks the repository out"),
    "path_scoped": (GOOD.replace("      - uses: actions/checkout@v6\n",
                                 "      - uses: actions/checkout@v6\n        with:\n          path: probe\n")
                    .replace("        uses: ./.github/actions/report-main-red\n",
                             "        uses: ./probe/.github/actions/report-main-red\n"), None),
    "path_scoped_wrong_root": (GOOD.replace("      - uses: actions/checkout@v6\n",
                                            "      - uses: actions/checkout@v6\n        with:\n          path: probe\n")
                               .replace("        uses: ./.github/actions/report-main-red\n",
                                        "        uses: ./other/.github/actions/report-main-red\n"),
                               "nothing checks the repository out"),
    "no_issues_write": (GOOD.replace("  issues: write\n", ""), "has no issues: write"),
    "matrix_without_key": (GOOD.replace("    runs-on: ubuntu-latest\n",
                                        "    runs-on: ubuntu-latest\n    strategy:\n      matrix:\n        a: [x, y]\n"),
                           "a matrix job's reporter is not given matrix"),
    "push_main_selected": (GOOD.replace("on:\n  schedule:\n    - cron: '0 0 * * 0'\n",
                                        "on:\n  push:\n    branches: [main]\n").replace("      - run: echo work\n", "")
                           .replace("        uses: ./.github/actions/report-main-red\n", "        uses: ./somewhere-else\n"),
                           "the last step is not the main-red reporter"),
    "checkout_always": (GOOD.replace("      - uses: actions/checkout@v6\n",
                                     "      - uses: actions/checkout@v6\n        if: always()\n"), None),
    "checkout_conditional": (GOOD.replace("      - uses: actions/checkout@v6\n",
                                          "      - uses: actions/checkout@v6\n        if: env.SKIP_RUN != 'true'\n"),
                             "nothing checks the repository out"),
    "checkout_other_repo": (GOOD.replace("      - uses: actions/checkout@v6\n",
                                         "      - uses: actions/checkout@v6\n        with:\n          repository: o/other\n"),
                            "nothing checks the repository out"),
    "checkout_other_ref": (GOOD.replace("      - uses: actions/checkout@v6\n",
                                        "      - uses: actions/checkout@v6\n        with:\n          ref: v10.0.0\n"),
                           "nothing checks the repository out"),
    "relevance_ok": (RELEVANCE_SUITE, None),
    "other_reusable": (RELEVANCE_SUITE.replace("./.github/workflows/suite-relevant.yml",
                                               "./.github/workflows/other.yml"),
                       "only ./.github/workflows/suite-relevant.yml is exempt"),
    "suite_not_cancelled_proof": (RELEVANCE_SUITE.replace("!cancelled() && ", ""),
                                  "without `!cancelled()`"),
    "suite_reads_relevance": (RELEVANCE_SUITE.replace("(github.event_name != 'merge_group' || needs.relevant.outputs.relevant == 'true')",
                                                      "needs.relevant.outputs.relevant == 'true'"),
                              "does not run whatever it answers outside the merge queue"),
}
failed = []
with tempfile.TemporaryDirectory() as tmp:
    for name, (src, want) in PLANTS.items():
        p = os.path.join(tmp, f"{name}.yml")
        open(p, "w").write(src)
        got = problems(p)
        if want is None and got:
            failed.append(f"planted '{name}' is correct but was flagged: {got}")
        elif want is not None and not any(want in g for g in got):
            failed.append(f"planted '{name}' should be flagged '{want}', got {got}")
    for name, src, want in (
        ("tags_only", "on:\n  push:\n    tags: ['v*']\njobs: {}\n", True),
        ("pr_only", "on:\n  pull_request: {}\njobs: {}\n", False),
        ("push_main", "on:\n  push:\n    branches: [main]\njobs: {}\n", True),
        ("push_unfiltered", "on: push\njobs: {}\n", True),
        ("push_other_branch", "on:\n  push:\n    branches: [develop]\njobs: {}\n", False),
        ("schedule", "on:\n  schedule:\n    - cron: '0 0 * * 0'\njobs: {}\n", True),
    ):
        if reports_on_the_tracker(yaml.safe_load(src)) != want:
            failed.append(f"the rule selects '{name}' as {not want}, want {want}")
# The generator refuses by name what it cannot copy, and treats `jobs: {}` as
# nothing to edit.
with tempfile.TemporaryDirectory() as tmp:
    for name, src, want in (
        ("string_permissions", GOOD.replace("permissions:\n  contents: read\n  issues: write\n", "permissions: read-all\n")
         .replace("        if: always()\n        uses: ./.github/actions/report-main-red\n        with:\n          status: ${{ job.status }}\n          token: ${{ github.token }}\n", ""),
         "string_permissions.yml:j: top-level `permissions: read-all` is a string"),
        ("reporter_not_last", GOOD + "      - run: echo after\n", "not once as the last step"),
        ("reporting_conditional_checkout", GOOD.replace("      - uses: actions/checkout@v6\n",
                                                        "      - uses: actions/checkout@v6\n        if: env.SKIP_RUN != 'true'\n"),
         "no earlier checkout always loads the action"),
        ("empty_jobs", "on:\n  schedule:\n    - cron: '0 0 * * 0'\njobs: {}\n", None),
    ):
        q = os.path.join(tmp, name + ".yml")
        open(q, "w").write(src)
        try:
            _gen.plan(q)
            got = None
        except _gen.Refused as e:
            got = str(e)
        if (want is None) != (got is None) or (want and want not in got):
            failed.append(f"generator on '{name}': want refusal {want!r}, got {got!r}")
    r = subprocess.run([sys.executable, GENERATOR, "--check", os.path.join(tmp, "no-such-root")],
                       capture_output=True, text=True)
    if r.returncode != 2:
        failed.append(f"generator --check on a root with no workflows exited {r.returncode}, want 2")

if failed:
    print("FAIL: the checker does not flag what it claims:\n  " + "\n  ".join(failed))
    sys.exit(1)

# ---- the checker against the tree -------------------------------------------
paths = sorted(glob.glob(os.path.join(ROOT, ".github/workflows/*.yml")) + glob.glob(os.path.join(ROOT, ".github/workflows/*.yaml")))
selected = [p for p in paths if reports_on_the_tracker(yaml.safe_load(open(p)) or {})]
names = {os.path.basename(p) for p in selected}
bad = [f"stale exemption {ex}: it is not a workflow that reports on the tracker (gone, or its triggers changed)"
       for ex in EXEMPT if ex not in names]
checked = [p for p in selected if os.path.basename(p) not in EXEMPT]
want = SELECTED_ENTERPRISE if ON_ENTERPRISE else SELECTED_MIRROR
tree = "enterprise" if ON_ENTERPRISE else "mirror"
if len(selected) != want:
    bad.append(f"{len(selected)} workflow(s) report on the tracker on this {tree} tree, the census asserts {want}: "
               "a change to the population moves the number in the same PR (or the rule stopped reading the tree)")


def mirror_selected(sync_workflow):
    """How many workflows the MIRROR would select: the sync's own rule chain,
    replayed over the workflows alone, then the same selector."""
    with tempfile.TemporaryDirectory() as tmp:
        probe = os.path.join(tmp, "probe")
        os.makedirs(os.path.join(probe, ".github/workflows"))
        os.makedirs(os.path.join(probe, "ee"))
        for q in paths:
            shutil.copy(q, os.path.join(probe, ".github/workflows", os.path.basename(q)))
        open(os.path.join(probe, "ee/.witness"), "w").write("witness\n")
        env = dict(os.environ, SYNC_SOURCE_ROOT=probe, SYNC_WORKFLOW=sync_workflow)
        r = subprocess.run(["bash", os.path.join(ROOT, "scripts/ci/simulate-community-mirror.sh"),
                            os.path.join(tmp, "staged")], env=env, capture_output=True, text=True)
        if r.returncode != 0:
            raise RuntimeError("the mirror replay failed: " + (r.stdout + r.stderr)[-600:])
        staged = glob.glob(os.path.join(tmp, "staged/.github/workflows/*.yml"))
        return sum(1 for q in staged if reports_on_the_tracker(yaml.safe_load(open(q)) or {}))


if ON_ENTERPRISE:
    got = mirror_selected(SYNC_WORKFLOW)
    if got != SELECTED_MIRROR:
        bad.append(f"the sync would carry {got} reporting workflow(s) to the mirror, where this census asserts "
                   f"{SELECTED_MIRROR}: move SELECTED_MIRROR in the same PR")
    # CONTROL: the replay must see a change to the sync. One more exclude, and
    # one restored *-e2e.yml, must each move the number.
    src = open(SYNC_WORKFLOW).read()
    anchor = "            --exclude='.claude/' \\\n"
    if src.count(anchor) != 1:
        bad.append("the mirror control's anchor is not in the sync workflow exactly once")
    else:
        with tempfile.TemporaryDirectory() as tmp:
            for name, extra, moved in (
                ("one more exclude", "            --exclude='.github/workflows/gitleaks.yml' \\\n", SELECTED_MIRROR - 1),
                ("one restored e2e", "            --include='.github/workflows/audit-date-range-e2e.yml' \\\n", SELECTED_MIRROR + 1),
            ):
                planted = os.path.join(tmp, name.replace(" ", "-") + ".yml")
                open(planted, "w").write(src.replace(anchor, anchor + extra))
                seen = mirror_selected(planted)
                if seen != moved:
                    bad.append(f"mirror control '{name}': the replay counted {seen}, want {moved}; the mirror "
                               "assertion is not reading the sync")
                else:
                    print(f"control: a sync with {name} moves the mirror count to {seen}, and "
                          f"{'passes' if seen == SELECTED_MIRROR else 'reds'} the assertion of {SELECTED_MIRROR}")

gen = subprocess.run([sys.executable, GENERATOR, "--check", ROOT], capture_output=True, text=True)
if gen.returncode != 0:
    bad.append("the generator's --check is not clean:\n    " + (gen.stdout + gen.stderr).strip().replace("\n", "\n    "))

# CONTROL: --check must see a job that lost its reporter. A copy of one checked
# workflow, with its first reporter step cut out, must red naming that
# workflow and the fixing command. (Any checked workflow: the mirror has no
# *-e2e.yml.)


def cut_first_reporter(text):
    lines = text.split("\n")
    at = next((i for i, l in enumerate(lines) if re.match(r"^\s+uses: \./\.github/actions/report-main-red\s*$", l)), None)
    if at is None:
        return text
    start = at
    while start > 0 and not re.match(r"^\s*- ", lines[start]):
        start -= 1
    ind = len(lines[start]) - len(lines[start].lstrip(" "))
    end = start + 1
    while end < len(lines) and (not lines[end].strip() or len(lines[end]) - len(lines[end].lstrip(" ")) > ind):
        end += 1
    while end > start + 1 and not lines[end - 1].strip():
        end -= 1  # keep the blank lines after the step, and the file's final newline
    return "\n".join(lines[:start] + lines[end:])


victim = checked[0] if checked else None
if victim is None:
    bad.append("no checked workflow to plant the --check control on")
else:
    with tempfile.TemporaryDirectory() as tmp:
        os.makedirs(os.path.join(tmp, ".github/workflows"))
        text = open(victim).read()
        cut = cut_first_reporter(text)
        open(os.path.join(tmp, ".github/workflows", os.path.basename(victim)), "w").write(cut)
        r = subprocess.run([sys.executable, GENERATOR, "--check", tmp], capture_output=True, text=True)
        if cut == text or r.returncode != 1 or os.path.basename(victim) + ":" not in r.stdout \
                or "--write" not in r.stdout:
            bad.append(f"--check control: a {os.path.basename(victim)} without its reporter did not red naming "
                       f"the job and the fixing command (rc {r.returncode}): {r.stdout.strip()[:300]}")
        else:
            print(f"control: --check reds a {os.path.basename(victim)} whose reporter was cut, naming the fix")
jobs = 0
for p in checked:
    bad += problems(p)
    jobs += len((yaml.safe_load(open(p)) or {}).get("jobs") or {})
if bad:
    print("FAIL: jobs that run after the merge and would go red unreported:\n  " + "\n  ".join(bad))
    sys.exit(1)
print(f"PASS: {len(selected)} workflow(s) report on the tracker on this {tree} tree (asserted {want}), and all {jobs} "
      f"jobs of the {len(checked)} checked end with the main-red reporter ({len(EXEMPT)} exempt by name)"
      + (f"; the mirror would carry {SELECTED_MIRROR}, proven by replaying the sync" if ON_ENTERPRISE else ""))
PY
