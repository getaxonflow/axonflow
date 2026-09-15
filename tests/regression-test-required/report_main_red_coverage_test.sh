#!/usr/bin/env bash
# report_main_red_coverage_test.sh - every job that runs after the merge ends
# with the main-red reporter (#4041).
#
# THE POPULATION IS DERIVED, NEVER LISTED. A workflow is in it when it runs on a
# push to main or on a schedule: the rule .github/actions/report-main-red
# applies at runtime. A new post-merge workflow joins the population the
# moment it is written, so it cannot ship without the reporter.
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

import yaml

ROOT = sys.argv[1]
ACTION = "./.github/actions/report-main-red"
EXEMPT = {
    "build-community.yml": "its jobs run only in the public mirror (github.repository == "
                           "'getaxonflow/axonflow'), where the reporter is a no-op by design",
}
FLOOR = 15  # 18 workflows met the rule when it was written, one of them exempt


def triggers(doc):
    on = doc.get(True, doc.get("on")) or {}
    if isinstance(on, str):
        return {on: None}
    if isinstance(on, list):
        return {k: None for k in on}
    return on


def runs_after_the_merge(doc):
    on = triggers(doc)
    if "schedule" in on:
        return True
    if "push" not in on:
        return False
    push = on.get("push")
    if not isinstance(push, dict):
        return True  # a bare `push`: every branch, main among them
    if "branches" in push:
        return any(fnmatch.fnmatchcase("main", b) for b in push["branches"] or [])
    if "branches-ignore" in push:
        return not any(fnmatch.fnmatchcase("main", b) for b in push["branches-ignore"] or [])
    return not push.get("tags")  # no branch filter: every branch, unless tags-only


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


def resolves_the_action(step, root):
    if not str(step.get("uses", "")).startswith("actions/checkout"):
        return False
    w = step.get("with") or {}
    if str(w.get("path") or "") != root:
        return False
    sparse = w.get("sparse-checkout")
    return sparse is None or ".github/actions/report-main-red" in str(sparse)


def problems(path):
    doc = yaml.safe_load(open(path)) or {}
    top = doc.get("permissions")
    out = []
    for name, job in (doc.get("jobs") or {}).items():
        where = f"{os.path.basename(path)}:{name}"
        if "uses" in job:
            out.append(f"{where} calls a reusable workflow; the reporter must end each job of the workflow it calls")
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
        ("tags_only", "on:\n  push:\n    tags: ['v*']\njobs: {}\n", False),
        ("pr_only", "on:\n  pull_request: {}\njobs: {}\n", False),
        ("push_main", "on:\n  push:\n    branches: [main]\njobs: {}\n", True),
        ("push_unfiltered", "on: push\njobs: {}\n", True),
        ("push_other_branch", "on:\n  push:\n    branches: [develop]\njobs: {}\n", False),
        ("schedule", "on:\n  schedule:\n    - cron: '0 0 * * 0'\njobs: {}\n", True),
    ):
        if runs_after_the_merge(yaml.safe_load(src)) != want:
            failed.append(f"the rule selects '{name}' as {not want}, want {want}")
if failed:
    print("FAIL: the checker does not flag what it claims:\n  " + "\n  ".join(failed))
    sys.exit(1)

# ---- the checker against the tree -------------------------------------------
paths = sorted(glob.glob(os.path.join(ROOT, ".github/workflows/*.yml")) + glob.glob(os.path.join(ROOT, ".github/workflows/*.yaml")))
selected = [p for p in paths if runs_after_the_merge(yaml.safe_load(open(p)) or {})]
names = {os.path.basename(p) for p in selected}
bad = [f"stale exemption {ex}: it is not a workflow that runs after the merge (gone, or its triggers changed)"
       for ex in EXEMPT if ex not in names]
checked = [p for p in selected if os.path.basename(p) not in EXEMPT]
if len(checked) < FLOOR:
    bad.append(f"only {len(checked)} workflow(s) run after the merge, want at least {FLOOR}: the rule is not reading this tree")
jobs = 0
for p in checked:
    bad += problems(p)
    jobs += len((yaml.safe_load(open(p)) or {}).get("jobs") or {})
if bad:
    print("FAIL: jobs that run after the merge and would go red unreported:\n  " + "\n  ".join(bad))
    sys.exit(1)
print(f"PASS: {len(checked)} workflow(s) run after the merge, and all {jobs} of their jobs end with the main-red reporter "
      f"({len(EXEMPT)} exempt by name)")
PY
