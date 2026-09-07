#!/usr/bin/env python3
"""Fail a merge-queue build if any stack-booting suite failed at this SHA.

WHY. The 62 suites run in the merge queue but none of them is a required
status check, and a queue entry is gated only by required checks - so without
this job a red suite would merge. A merge_group-only context cannot itself be
required (proven on this repository 2026-08-28: adding one put a PR at
mergeState=BLOCKED with every PR check green), so `Suite Gate` runs on both
events and does its real work only in the queue.

WHAT COUNTS AS A SUITE, and why it is not a list. The same property the
nightly dispatcher uses: a workflow whose job runs `docker compose` or a
`runtime-e2e/` script in a `run:` step. Keying on names or a hand-kept list is
the class this repository spent the week finding - a guard that recognises
members by spelling goes quiet the moment the spelling changes.

OUTCOMES, all three of them stated so none is a fallthrough:
  * a suite concluded failure / cancelled / timed_out  -> FAIL, named
  * any expected suite produced no run at all          -> FAIL, named
    (the expected set is DERIVED: every stack-booting workflow declaring
    merge_group. A run whose every job skips still reports completed, so this
    is a set comparison, not a picked floor.)
  * every observed suite succeeded or skipped          -> pass
A `skipped` suite is a pass: a queue build legitimately skips a suite whose
own job-level conditions exclude it.

THE SANITY FLOOR IS A PROPERTY OF THE TREE, NOT A CONSTANT THAT FITS ONE OF
THEM. This file SYNCS to the community mirror, and the mirror's tree is not
this one: the sync strips runtime-e2e/ and every enterprise-only workflow, so
the mirror carries 2 stack-booting merge_group workflows against this tree's
76. The enterprise floor of 20 is therefore unreachable on the mirror BY
CONSTRUCTION, and it failed there exactly that way - "only 2 stack-booting
workflows declare merge_group (sanity floor 20)" on the v10.4.0 sync PR's
queue build (getaxonflow/axonflow run 34066582583).

So the floor is chosen from what the CHECKED-OUT TREE CONTAINS, the same
marker scripts/lint-trap-handlers-exit.sh and
scripts/lint-hitl-queue-choke-point.sh use, and never from "the count looks
small" - a gate that decides it must be on the mirror because it found few
suites is a gate that excuses a broken selector on the tree that has many.
  * enterprise tree -> MIN_SUITE_RUNS, unchanged at 20.
  * community tree  -> the count of stack-booting workflows the mirror's own
    tree carries, and never below 1. That is STRICTER than a constant: every
    stack-booting workflow that reached the mirror must also declare
    merge_group, so a selector that matches nothing fails on the floor of 1,
    a broken `on:` parse fails at 0 < 2, and a mirrored suite that boots a
    stack outside the queue is named rather than tolerated.

`--check-floor [ROOT]` runs that decision alone, with no API call, and is what
tests/regression-test-required/suite_gate_floor_is_edition_aware_test.sh
drives over fixture trees in both directions.
"""
import glob
import json
import os
import re
import subprocess
import sys
import time

import yaml

BOOTS = re.compile(r"docker[ -]compose|runtime-e2e/\S+\.(sh|py)")
REPO = os.environ.get("GITHUB_REPOSITORY", "getaxonflow/axonflow-enterprise")
SHA = os.environ.get("GITHUB_SHA", "")
DEADLINE = float(os.environ.get("DEADLINE_MINUTES", "35")) * 60
MIN_RUNS = int(os.environ.get("MIN_SUITE_RUNS", "20"))
POLL = 30
BAD = {"failure", "cancelled", "timed_out", "startup_failure", "action_required"}
OK = {"success", "skipped", "neutral"}


def gh(path):
    out = subprocess.run(["gh", "api", path], capture_output=True, text=True)
    if out.returncode != 0:
        raise RuntimeError(f"gh api {path} failed: {out.stderr.strip()[:300]}")
    return json.loads(out.stdout)


def suite_workflow_names(workflows_dir=".github/workflows", require_merge_group=False):
    """Display names of workflows that boot a stack, by property not by list.

    With `require_merge_group`, only those that actually trigger on
    merge_group - which is the EXACT set a queue build must produce, because
    even a run whose every job skips still reports `status=completed`. That
    makes the sufficiency check a set comparison rather than a picked floor.
    """
    names = {}
    for f in sorted(glob.glob(os.path.join(workflows_dir, "*.yml"))):
        with open(f, encoding="utf-8") as fh:
            doc = yaml.safe_load(fh)
        if not isinstance(doc, dict):
            continue
        jobs = doc.get("jobs") or {}
        if not any(BOOTS.search(str((s or {}).get("run", "")))
                   for j in jobs.values() for s in ((j or {}).get("steps") or [])):
            continue
        base = os.path.basename(f)
        # This gate is not a suite; neither is the dispatcher.
        if base in ("suite-gate.yml", "nightly-e2e.yml", "self-hosted-canary.yml"):
            continue
        on = doc.get("on") or doc.get(True) or {}
        if require_merge_group and not (isinstance(on, dict) and "merge_group" in on):
            continue
        names[doc.get("name") or base] = base
    return names


def is_community_tree(root="."):
    """True for the tree the community sync produces.

    The SAME marker scripts/lint-hitl-queue-choke-point.sh and
    scripts/lint-trap-handlers-exit.sh use, so the three guards agree on what
    edition they are standing in: the mirror carries the mirrored lint.yml and
    NOT sync-community-repo.yml, because the sync excludes its own workflow.
    Read from what the tree CONTAINS. Never inferred from how many suites were
    found - that inference is the one a broken selector satisfies.
    """
    wf = os.path.join(root, ".github", "workflows")
    return (os.path.isfile(os.path.join(wf, "lint.yml"))
            and not os.path.isfile(os.path.join(wf, "sync-community-repo.yml")))


def sanity_floor(root="."):
    """(floor, reason, booting) for this tree. `booting` is None off the mirror.

    See the module header. On the enterprise tree this returns MIN_SUITE_RUNS
    unchanged, so nothing about the enterprise gate moves.
    """
    wf = os.path.join(root, ".github", "workflows")
    if not is_community_tree(root):
        return MIN_RUNS, f"the enterprise calibration MIN_SUITE_RUNS={MIN_RUNS}", None
    booting = suite_workflow_names(wf, require_merge_group=False)
    return (max(1, len(booting)),
            f"derived from this community tree, which carries {len(booting)} "
            f"stack-booting workflow(s) - every one of them must declare merge_group",
            booting)


def floor_holds(root="."):
    """Apply the sanity floor to ROOT. Prints its own verdict; returns a bool.

    main() calls exactly this, so the regression suite drives the production
    decision rather than a second copy of it.
    """
    wf = os.path.join(root, ".github", "workflows")
    suites = suite_workflow_names(wf, require_merge_group=True)
    floor, reason, booting = sanity_floor(root)
    if len(suites) < floor:
        print(f"::error::only {len(suites)} stack-booting workflows declare merge_group "
              f"(sanity floor {floor}, {reason}). "
              "The selector is broken, not the day quiet.")
        for n in sorted(set(booting or {}) - set(suites)):
            print(f"::error::  boots a stack but declares no merge_group: {n}")
        return False
    print(f"sanity floor {floor} met by {len(suites)} merge_group suite(s) "
          f"({reason})")
    return True


def runs_at_sha():
    """EVERY run at this SHA, paginated.

    `per_page=100` against 88 workflows carrying merge_group is 12 of
    headroom, and a truncated page was reproduced PASSING with a red suite
    off the end of it. `total_count` is authoritative, so the loop reads
    until it has that many or a page comes back short.
    """
    runs, page = [], 1
    while True:
        data = gh(f"/repos/{REPO}/actions/runs?head_sha={SHA}&per_page=100&page={page}")
        batch = data.get("workflow_runs", [])
        runs.extend(batch)
        total = data.get("total_count")
        if not batch or (total is not None and len(runs) >= total) or page >= 20:
            if total is not None and len(runs) < total:
                raise RuntimeError(
                    f"paged {len(runs)} of {total} runs at {SHA[:9]} and stopped; "
                    "refusing to judge on a truncated list")
            return runs
        page += 1


def main():
    if not SHA:
        print("::error::GITHUB_SHA is empty; refusing to report success.")
        return 1
    # EXPECTED is derived, not guessed: every stack-booting workflow that
    # declares merge_group must produce a completed run for this queue build.
    suites = suite_workflow_names(require_merge_group=True)
    if not floor_holds("."):
        return 1
    print(f"expecting a completed run from each of {len(suites)} merge_group suites "
          f"at {SHA[:9]}")

    started = time.time()
    while True:
        runs = [r for r in runs_at_sha() if r.get("name") in suites]
        done = {r["name"]: r for r in runs if r.get("status") == "completed"}
        pending = [r["name"] for r in runs if r.get("status") != "completed"]
        failed = {n: r for n, r in done.items() if (r.get("conclusion") or "") in BAD}

        # Fail fast: a red suite will not become green by waiting.
        if failed:
            print(f"::error::{len(failed)} suite(s) failed in this merge-queue build:")
            for n, r in sorted(failed.items()):
                print(f"::error::  {n} -> {r.get('conclusion')}  {r.get('html_url')}")
            return 1

        if not pending and runs:
            unknown = {n: (r.get("conclusion") or "?") for n, r in done.items()
                       if (r.get("conclusion") or "") not in OK}
            if unknown:
                print(f"::error::unmodelled conclusion(s), refusing to pass: {unknown}")
                return 1
            missing = sorted(set(suites) - set(done))
            if missing:
                print(f"::error::{len(missing)} of {len(suites)} expected suites produced "
                      f"NO run at this SHA. Passing here would verify nothing:")
                for n in missing:
                    print(f"::error::  never ran: {n}")
                return 1
            print(f"all {len(suites)} expected suites accounted for, green or skipped:")
            for n, r in sorted(done.items()):
                print(f"  {r.get('conclusion'):9} {n}")
            return 0

        waited = time.time() - started
        if waited > DEADLINE:
            print(f"::error::deadline after {waited/60:.0f} min with "
                  f"{len(pending)} suite(s) still running: {sorted(pending)[:8]}")
            print("::error::refusing to report success on suites that have not finished.")
            return 1
        print(f"  {len(done)} complete, {len(pending)} running "
              f"({waited/60:.0f}/{DEADLINE/60:.0f} min) ...")
        time.sleep(POLL)


if __name__ == "__main__":
    # `--check-floor [ROOT]`: the sanity-floor decision alone, no API call, so
    # it can be driven over a fixture tree. Anything else is the real gate.
    if len(sys.argv) > 1 and sys.argv[1] == "--check-floor":
        sys.exit(0 if floor_holds(sys.argv[2] if len(sys.argv) > 2 else ".") else 1)
    sys.exit(main())
