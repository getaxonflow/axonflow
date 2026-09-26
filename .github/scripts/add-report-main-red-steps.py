#!/usr/bin/env python3
"""End every reporting job with the main-red reporter (#4041, #4169).

WHICH WORKFLOWS REPORT. A workflow whose run speaks for main or for a release -
it runs on a push to main, on a schedule, or on a push of a tag - has no pull
request to go red on, so each of its jobs ends with
`.github/actions/report-main-red`, which files the red on the tracker (a
`main-red` issue for main, a `release-red` issue for a tag). This file holds
that rule ONCE: `reports_on_the_tracker`, `EXEMPT` and `relevance_exemption`
are imported by tests/regression-test-required/report_main_red_coverage_test.sh,
so the census and this generator cannot disagree about the population.

WHAT IT WRITES, per job that does not already end with the reporter:
  - the reporter as the job's LAST step, `if: always()`, with `status` and
    `token` (and `matrix` for a matrix job) - the exact text the census asks;
  - a job-level `permissions:` block equal to the workflow's top-level block
    plus `issues: write` (a job-level block REPLACES the workflow's, so the
    other scopes are carried over; a workflow with no top-level block gets
    `contents: read` plus `issues: write`), unless the token already holds
    `issues: write`.

It edits TEXT, never dumps YAML: a dump would drop every comment. So it refuses,
by name, what it cannot edit safely - a job whose last key is not `steps`, a job
with no checkout before its last step, a job-level `permissions:` block without
`issues: write` - and every edit is re-parsed and checked: the job's steps equal
the old steps plus the reporter, its permissions equal the expected block, and
every other part of the document is unchanged. A second `--write` is a no-op.

A job that only CALLS `./.github/workflows/suite-relevant.yml` is not given the
reporter: see `relevance_exemption`.

Usage:  add-report-main-red-steps.py --check [ROOT]   exit 1 listing what --write would change
        add-report-main-red-steps.py --write [ROOT]   make the change
"""
from __future__ import annotations

import argparse
import copy
import fnmatch
import glob
import io
import os
import re
import sys

import yaml

ACTION = "./.github/actions/report-main-red"
RELEVANCE = "./.github/workflows/suite-relevant.yml"
EXEMPT = {
    "build-community.yml": "its jobs run only in the public mirror (github.repository == "
                           "'getaxonflow/axonflow'), where the reporter is a no-op by design",
}


class Refused(Exception):
    pass


def triggers(doc: dict) -> dict:
    on = doc.get(True, doc.get("on")) or {}
    if isinstance(on, str):
        return {on: None}
    if isinstance(on, list):
        return {k: None for k in on}
    return on


def reports_on_the_tracker(doc: dict) -> bool:
    """A run of this workflow speaks for main or for a release: a schedule, a
    push that can reach main, or a push of a tag."""
    on = triggers(doc)
    if "schedule" in on:
        return True
    if "push" not in on:
        return False
    push = on.get("push")
    if not isinstance(push, dict):
        return True  # a bare `push`: every branch, main among them
    if push.get("tags"):
        return True  # a release tag (#4169)
    if "branches" in push:
        return any(fnmatch.fnmatchcase("main", b) for b in push["branches"] or [])
    if "branches-ignore" in push:
        return not any(fnmatch.fnmatchcase("main", b) for b in push["branches-ignore"] or [])
    return True  # no filter: every branch


def relevance_exemption(doc: dict, name: str) -> list[str]:
    """Problems with the exemption of job `name`, a job-level `uses:`. Only a
    call of suite-relevant.yml is exempt, and only when every job that needs it
    runs whatever it answers outside the merge queue: `!cancelled()` (so a red
    relevance job does not skip it) AND `github.event_name != 'merge_group' ||`
    (so it does not read the answer on a push or a tag). Then a red relevance
    job cannot hide a suite on main or on a tag, and it reports nothing a
    reader needs."""
    job = (doc.get("jobs") or {}).get(name) or {}
    if str(job.get("uses", "")) != RELEVANCE:
        return [f"calls the reusable workflow {job.get('uses')!r}; only {RELEVANCE} is exempt, and the "
                "reporter must end each job of any other workflow it calls"]
    out = []
    for other, j in (doc.get("jobs") or {}).items():
        needs = j.get("needs")
        needs = [needs] if isinstance(needs, str) else list(needs or [])
        if name not in needs:
            continue
        cond = str(j.get("if", ""))
        if "!cancelled()" not in cond:
            out.append(f"{other} needs {name} without `!cancelled()`, so a red {name} would skip it unreported")
        if "github.event_name != 'merge_group' ||" not in cond:
            out.append(f"{other} needs {name} but does not run whatever it answers outside the merge queue "
                       "(`github.event_name != 'merge_group' ||`), so a red on a push or a tag could hide it")
    return out


def reporter_root(uses) -> str | None:
    u = str(uses or "")
    if u == ACTION:
        return ""
    m = re.fullmatch(r"\./([A-Za-z0-9._-]+)/\.github/actions/report-main-red", u)
    return m.group(1) if m else None


def resolves_the_action(step: dict, root: str) -> bool:
    """Whether a step is a checkout that always makes the reporter action (a
    LOCAL action) loadable at `root`: `actions/checkout`, with `path` equal to
    root; no `if:` other than an always-true one (a skipped checkout leaves
    nothing to load, and the reporter step itself then turns the job red);
    this repository (`repository:` absent or `${{ github.repository }}`); a
    `ref:` that is absent, `main` or an expression (a LITERAL ref to another
    tree, `v10.0.0`, may not carry the action); and a sparse checkout, if any,
    that includes the action. One definition, used by this generator and by
    the census."""
    if not str(step.get("uses", "")).startswith("actions/checkout"):
        return False
    cond = step.get("if")
    if cond is not None and not re.fullmatch(r"\s*(\$\{\{\s*)?always\(\)(\s*\}\})?\s*", str(cond)):
        return False
    w = step.get("with") or {}
    repo = w.get("repository")
    if repo and not re.fullmatch(r"\$\{\{\s*github\.repository\s*\}\}", str(repo)):
        return False
    ref = w.get("ref")
    if ref and str(ref) != "main" and "${{" not in str(ref):
        return False
    if str(w.get("path") or "") != root:
        return False
    sparse = w.get("sparse-checkout")
    return sparse is None or ".github/actions/report-main-red" in str(sparse)


def ends_with_reporter(job: dict) -> bool:
    steps = job.get("steps") or []
    return bool(steps) and reporter_root(steps[-1].get("uses")) is not None


def expected_step(job: dict) -> dict:
    w = {"status": "${{ job.status }}", "token": "${{ github.token }}"}
    if "matrix" in (job.get("strategy") or {}):
        w["matrix"] = "${{ toJSON(matrix) }}"
    return {"name": "Report a red run to the tracker (#4169)", "if": "always()", "uses": ACTION, "with": w}


def expected_permissions(doc: dict, where: str = "") -> dict:
    top = doc.get("permissions")
    if isinstance(top, str):
        raise Refused(f"{where + ': ' if where else ''}top-level `permissions: {top}` is a string; a job-level "
                      "block cannot copy it, so add `issues: write` by hand")
    perms = dict(top) if isinstance(top, dict) else {"contents": "read"}
    perms["issues"] = "write"
    return perms


def _job_blocks(lines: list[str]) -> dict[str, tuple[int, int]]:
    """Job name -> (index of its `  name:` line, index one past its last line)."""
    try:
        start = next(i for i, l in enumerate(lines) if re.match(r"^jobs:\s*(#.*)?$", l))
    except StopIteration:
        if any(re.match(r"^jobs:\s*\{\s*\}\s*(#.*)?$", l) for l in lines):
            return {}  # `jobs: {}`: nothing to edit
        raise Refused("no top-level `jobs:` line")
    keys = []
    end_of_jobs = len(lines)
    for i in range(start + 1, len(lines)):
        l = lines[i]
        if re.match(r"^\S", l) and not l.startswith("#"):
            end_of_jobs = i
            break
        m = re.match(r"^  ([A-Za-z0-9_-]+):\s*(#.*)?$", l)
        if m:
            keys.append((m.group(1), i))
    blocks = {}
    for k, (name, i) in enumerate(keys):
        j = keys[k + 1][1] if k + 1 < len(keys) else end_of_jobs
        # The block's own lines end at its last line indented deeper than a job key.
        last = i
        for t in range(i + 1, j):
            if lines[t].strip() and (len(lines[t]) - len(lines[t].lstrip(" "))) >= 4:
                last = t
        blocks[name] = (i, last + 1)
    return blocks


def plan(path: str) -> tuple[str, list[str]]:
    """(new text, [job names edited]) for one workflow; raises Refused."""
    text = io.open(path, encoding="utf-8").read()
    doc = yaml.safe_load(text) or {}
    base = os.path.basename(path)
    if base in EXEMPT or not reports_on_the_tracker(doc):
        return text, []
    lines = text.split("\n")
    blocks = _job_blocks(lines)
    top = doc.get("permissions")
    top_writes = isinstance(top, dict) and top.get("issues") == "write"
    edits = []  # (insert-after index, lines) applied bottom-up
    edited = []
    for name, job in (doc.get("jobs") or {}).items():
        if "uses" in job:
            continue  # the census judges the exemption; nothing to write
        where = f"{base}:{name}"
        steps = job.get("steps") or []
        roots = [reporter_root(s.get("uses")) for s in steps]
        at = [i for i, r in enumerate(roots) if r is not None]
        if at and at != [len(steps) - 1]:
            raise Refused(f"{where}: carries the reporter at step(s) {[i + 1 for i in at]} of {len(steps)}, not "
                          "once as the last step; --write would add a second one, so fix it by hand")
        if ends_with_reporter(job):
            # Already reporting: it must still load the action, whatever wrote it.
            if not any(resolves_the_action(s, roots[-1]) for s in steps[:-1]):
                raise Refused(f"{where}: ends with the reporter, but no earlier checkout always loads the "
                              "action (an `if:` other than always(), another repository, or a literal ref)")
            continue
        if list(job.keys())[-1] != "steps":
            raise Refused(f"{where}: its last key is not `steps`, so the reporter cannot be appended as text")
        if not any(resolves_the_action(s, "") for s in steps):
            raise Refused(f"{where}: no unconditional checkout of this repository (no `if:`, `path:`, "
                          "`repository:` or `ref:`), so the local action may not resolve")
        if name not in blocks:
            raise Refused(f"{where}: its `  {name}:` line was not found in the text")
        head, end = blocks[name]
        step_lines = [l for l in lines[head:end] if re.match(r"^\s*- ", l)]
        step_indent = None
        for i in range(head, end):
            if re.match(r"^    steps:\s*(#.*)?$", lines[i]):
                for t in range(i + 1, end):
                    m = re.match(r"^(\s*)- ", lines[t])
                    if m:
                        step_indent = m.group(1)
                        break
                break
        if step_indent is None or not step_lines:
            raise Refused(f"{where}: no `    steps:` list found in the text")
        ind = step_indent
        body = [f"{ind}- name: Report a red run to the tracker (#4169)",
                f"{ind}  if: always()",
                f"{ind}  uses: {ACTION}",
                f"{ind}  with:",
                f"{ind}    status: ${{{{ job.status }}}}",
                f"{ind}    token: ${{{{ github.token }}}}"]
        if "matrix" in (job.get("strategy") or {}):
            body.append(f"{ind}    matrix: ${{{{ toJSON(matrix) }}}}")
        edits.append((end, body))
        jp = job.get("permissions")
        if jp is not None:
            if not (isinstance(jp, dict) and jp.get("issues") == "write"):
                raise Refused(f"{where}: has a job-level `permissions:` without `issues: write`; add it by hand")
        elif not top_writes:
            perm = ["    permissions:"] + [f"      {k}: {v}" for k, v in expected_permissions(doc, where).items()]
            edits.append((head + 1, perm))
        edited.append(name)
    for at, add in sorted(edits, key=lambda e: e[0], reverse=True):
        lines[at:at] = add
    new = "\n".join(lines)
    verify(doc, yaml.safe_load(new) or {}, edited, top_writes, path)
    return new, edited


def verify(old: dict, new: dict, edited: list[str], top_writes: bool, path: str) -> None:
    """The edit changed exactly what it meant to and nothing else."""
    want = copy.deepcopy(old)
    for name in edited:
        job = want["jobs"][name]
        job["steps"] = list(job.get("steps") or []) + [expected_step(job)]
        if job.get("permissions") is None and not top_writes:
            job["permissions"] = expected_permissions(old)
    if new != want:
        raise Refused(f"{os.path.basename(path)}: the edited text does not parse to the intended document; "
                      "nothing was written")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--write", action="store_true")
    ap.add_argument("root", nargs="?", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
    a = ap.parse_args()
    if not os.path.isdir(os.path.join(a.root, ".github/workflows")):
        print(f"REFUSED: {a.root} has no .github/workflows; a check of nothing is not clean")
        return 2
    paths = sorted(glob.glob(os.path.join(a.root, ".github/workflows/*.yml"))
                   + glob.glob(os.path.join(a.root, ".github/workflows/*.yaml")))
    todo, refused = [], []
    for p in paths:
        try:
            new, edited = plan(p)
        except Refused as e:
            refused.append(str(e))
            continue
        if edited:
            todo.append((p, new, edited))
    for msg in refused:
        print(f"REFUSED: {msg}")
    for p, new, edited in todo:
        for name in edited:
            print(f"{'would add' if a.check else 'added'} the reporter: {os.path.basename(p)}:{name}")
        if a.write:
            io.open(p, "w", encoding="utf-8").write(new)
    if refused:
        return 1
    if a.check and todo:
        print(f"{sum(len(e) for _, _, e in todo)} job(s) in {len(todo)} workflow(s) would go red unreported; "
              "run: python3 .github/scripts/add-report-main-red-steps.py --write")
        return 1
    print(f"{'checked' if a.check else 'wrote'}: {len(todo)} workflow(s) changed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
